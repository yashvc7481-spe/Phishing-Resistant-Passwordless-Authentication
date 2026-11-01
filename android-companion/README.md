# CyberNova Android Companion Authenticator

Native Android Companion Application providing hardware-backed **Android `BiometricPrompt`** (Fingerprint / Face Unlock) for QR-based proximity authentication on the CyberNova Cybersecurity Portal.

---

## Architecture & Workflow

```
[ Desktop: CyberNova Portal ]
          │
          │ 1. Generates Ephemeral Challenge & Dynamic QR Code
          ▼
    [ Screen QR ]
          │
          │ 2. Scanned with Android Phone Camera / App
          ▼
[ Android Companion App / WebAuthn ]
          │
          │ 3. Invokes Android OS Native BiometricPrompt Bottom Sheet
          │    ("Touch the fingerprint sensor to verify identity")
          ▼
   [ Android TEE / Secure Enclave ]
          │
          │ 4. Hardware Fingerprint Sensor confirms match
          │ 5. ECDSA P-256 signs ephemeral challenge nonce
          ▼
   [ CyberNova Backend (Render) ]
          │
          │ 6. Cryptographic signature verified against registered public key
          │ 7. Single-use session approved (replay-blocked)
          ▼
[ Desktop Auto-Unlock & Dashboard Redirect ]
```

---

## Two Ways to Authenticate on Android

### Method 1: Instant Browser Fingerprint (No Installation Required)
1. Point your Android phone camera or Google Lens at the QR code on the CyberNova screen.
2. Tap the link to open `/mobile-auth.html`.
3. Tap **"Verify Fingerprint"**.
4. Android's native system **`BiometricPrompt`** bottom sheet appears from the bottom.
5. Touch your phone's fingerprint sensor.
6. The desktop immediately unlocks and redirects to your dashboard.

### Method 2: Native Android Companion App (`android-companion/`)
1. Open this `android-companion/` folder in **Android Studio**.
2. Connect your Android phone via USB (or wireless debugging).
3. Click **Run** (`Shift + F10`) or run:
   ```bash
   ./gradlew assembleDebug
   adb install app/build/outputs/apk/debug/app-debug.apk
   ```
4. The app opens `BiometricPrompt` directly on scanning or clicking deep-link `cybernova://auth`.

---

## Security Guarantees
* **Zero Fingerprint Storage:** Biometric images or templates are NEVER transmitted or stored on the server. All biometric matching occurs inside Android's local Secure Enclave / Titan M2 chip.
* **Single-Use Ephemeral Nonce:** Every QR code contains a unique 160-bit challenge nonce that expires in 90 seconds.
* **Cryptographic Verification:** Signed using ECDSA P-256 and verified using Node.js `crypto.verify` on the backend.
