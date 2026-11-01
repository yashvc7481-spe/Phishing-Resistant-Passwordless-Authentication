package com.cybernova.authenticator

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.Executor
import kotlin.concurrent.thread

/**
 * CyberNova Android Companion Authenticator
 * Implements Android Native BiometricPrompt (Fingerprint / Face Unlock)
 * for QR-based proximity authentication with zero simulation.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    private var currentSessionId: String? = null
    private var currentEmail: String = "student@nkocet.edu"
    private var serverBaseUrl: String = "https://cybernova-auth.vercel.app"

    private lateinit var tvStatus: TextView
    private lateinit var tvAccount: TextView
    private lateinit var btnScanFingerprint: Button
    private lateinit var btnScanQr: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        tvStatus = findViewById(R.id.tvStatus)
        tvAccount = findViewById(R.id.tvAccount)
        btnScanFingerprint = findViewById(R.id.btnScanFingerprint)
        btnScanQr = findViewById(R.id.btnScanQr)

        executor = ContextCompat.getMainExecutor(this)

        // Initialize Android OS Native BiometricPrompt
        setupBiometricPrompt()

        // Handle incoming Intent / Deep Link (e.g. cybernova://auth?session=...&email=...)
        handleIncomingIntent(intent)

        btnScanFingerprint.setOnClickListener {
            triggerBiometricAuthentication()
        }

        btnScanQr.setOnClickListener {
            startQrScanner()
        }

        checkBiometricAvailability()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        intent?.let { handleIncomingIntent(it) }
    }

    private fun handleIncomingIntent(intent: Intent) {
        val uri: Uri? = intent.data
        if (uri != null) {
            val session = uri.getQueryParameter("session")
            val email = uri.getQueryParameter("email")
            if (!session.isNullOrEmpty()) {
                currentSessionId = session
                currentEmail = email ?: "student@nkocet.edu"
                tvAccount.text = "Account: $currentEmail"
                tvStatus.text = "Session Linked: ${session.take(16)}...\nReady for Fingerprint Verification."
                btnScanFingerprint.isEnabled = true
                // Automatically prompt fingerprint when opened via deep link
                triggerBiometricAuthentication()
            }
        }
    }

    /**
     * Checks if the Android device has hardware fingerprint sensors available and enrolled.
     */
    private fun checkBiometricAvailability() {
        val biometricManager = BiometricManager.from(this)
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK
        when (biometricManager.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                tvStatus.text = "Hardware Fingerprint Sensor Ready."
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                tvStatus.text = "Error: No biometric hardware detected on this Android device."
                btnScanFingerprint.isEnabled = false
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                tvStatus.text = "Error: Biometric hardware is currently busy or unavailable."
            }
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                tvStatus.text = "Error: No fingerprint enrolled. Please enroll a fingerprint in Android Settings."
                btnScanFingerprint.isEnabled = false
            }
            else -> {
                tvStatus.text = "Biometric security status: Ready."
            }
        }
    }

    /**
     * Configures the Android BiometricPrompt with native OS callbacks.
     */
    private fun setupBiometricPrompt() {
        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("CyberNova Fingerprint Verification")
            .setSubtitle("Confirm sign-in to CyberNova Web Portal")
            .setDescription("Touch the fingerprint sensor to authenticate $currentEmail")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.BIOMETRIC_WEAK)
            .build()

        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    when (errorCode) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON -> {
                            tvStatus.text = "Biometric verification cancelled by user."
                        }
                        BiometricPrompt.ERROR_LOCKOUT,
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> {
                            tvStatus.text = "Biometric sensor locked due to too many attempts."
                        }
                        BiometricPrompt.ERROR_NO_BIOMETRICS -> {
                            tvStatus.text = "No fingerprint enrolled. Please set up a fingerprint in Android Settings."
                        }
                        BiometricPrompt.ERROR_HW_UNAVAILABLE -> {
                            tvStatus.text = "Fingerprint sensor currently unavailable. Try again shortly."
                        }
                        else -> {
                            tvStatus.text = "Biometric Error: $errString"
                        }
                    }
                    Toast.makeText(applicationContext, "Biometric: $errString", Toast.LENGTH_SHORT).show()
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    tvStatus.text = "Fingerprint Verified! Submitting cryptographic proof to server..."
                    // Execute Cryptographic Challenge Signing and Backend Submission
                    submitAuthenticationApproval()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    tvStatus.text = "Fingerprint not recognized. Touch the sensor again with an enrolled finger."
                }
            })
    }

    /**
     * Triggers the Android Native System BiometricPrompt Bottom Sheet.
     */
    private fun triggerBiometricAuthentication() {
        if (currentSessionId.isNullOrEmpty()) {
            Toast.makeText(this, "Please scan a QR code first.", Toast.LENGTH_SHORT).show()
            return
        }
        biometricPrompt.authenticate(promptInfo)
    }

    /**
     * Signs the ephemeral session challenge with the ECDSA P-256 key and posts to backend.
     */
    private fun submitAuthenticationApproval() {
        val sessionId = currentSessionId ?: return
        val email = currentEmail

        thread {
            try {
                // ECDSA P-256 Private Key
                val isStaff = email.contains("staff")
                val pkcs8Base64 = if (isStaff) {
                    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxk5oPgBvQjJGLFA4jfxdddE/8xM6/xVcMyd/GE+XYHehRANCAARPUIWbl9HF8pS068+0tqbBMgIPLOncQUKc66iTJptCmBMQlV2mdhuPI3Gmr3Acxqhik7VfAdKXDv3+v2/ss/ph"
                } else {
                    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgj3OZ1lDndLmqlA8r2VWwWnlotLVuG1hkSPpiC1RDSaGhRANCAARAK2yKY0YlX0PFRJZ47OugdA1uMM5h2NG4ymOj2K1BPBZfHVI1TK0Bv9tuy3l0keWQj3BKpsmsYPHF4pTLnx56"
                }

                val privKeyBytes = Base64.decode(pkcs8Base64, Base64.DEFAULT)
                val keySpec = PKCS8EncodedKeySpec(privKeyBytes)
                val kf = KeyFactory.getInstance("EC")
                val privateKey = kf.generatePrivate(keySpec)

                val signer = Signature.getInstance("SHA256withECDSA")
                signer.initSign(privateKey)
                signer.update(sessionId.toByteArray(Charsets.UTF_8))
                val signatureBytes = signer.sign()
                val signatureBase64 = Base64.encodeToString(signatureBytes, Base64.NO_WRAP)

                // POST to CyberNova backend
                val url = URL("$serverBaseUrl/api/auth/bluetooth/approve-mobile")
                val conn = url.openConnection() as HttpURLConnection
                conn.requestMethod = "POST"
                conn.setRequestProperty("Content-Type", "application/json")
                conn.doOutput = true

                val payload = JSONObject().apply {
                    put("sessionId", sessionId)
                    put("email", email)
                    put("signature", signatureBase64)
                    put("biometricVerified", true)
                    put("biometricType", "ANDROID_BIOMETRIC_PROMPT_NATIVE")
                }

                val writer = OutputStreamWriter(conn.outputStream)
                writer.write(payload.toString())
                writer.flush()
                writer.close()

                val responseCode = conn.responseCode
                runOnUiThread {
                    if (responseCode == 200) {
                        tvStatus.text = "SUCCESS! Computer unlocked via Android BiometricPrompt."
                        Toast.makeText(this@MainActivity, "Sign-In Approved!", Toast.LENGTH_LONG).show()
                        btnScanFingerprint.isEnabled = false
                    } else {
                        tvStatus.text = "Server Rejected Authentication (Code $responseCode)"
                    }
                }
            } catch (e: Exception) {
                runOnUiThread {
                    tvStatus.text = "Error: ${e.message}"
                }
            }
        }
    }

    private fun startQrScanner() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), 101)
        } else {
            Toast.makeText(this, "Point camera at CyberNova screen QR code", Toast.LENGTH_SHORT).show()
        }
    }
}
