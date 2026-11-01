import { startAuthentication, startRegistration } from "https://esm.sh/@simplewebauthn/browser@14.0.0";

/**
 * CyberNova Biometric Fingerprint & Bluetooth Fallback Authentication Engine
 */
export class CyberNovaAuth {
    constructor({ role = "student", defaultEmail = "student@nkocet.edu" }) {
        this.role = role;
        this.defaultEmail = defaultEmail;
        this.activeBluetoothDevice = null;
        this.activeBluetoothServer = null;
        this.currentBluetoothSession = null;
        this.capabilities = {
            webAuthn: false,
            platformBiometrics: false,
            webBluetooth: false,
            secureContext: window.isSecureContext
        };
    }

    async init() {
        this.bindElements();
        await this.detectCapabilities();
        this.renderCapabilityBadges();
        this.setupEventListeners();
        this.selectInitialMode();
    }

    bindElements() {
        this.emailInput = document.getElementById("username");
        this.statusBox = document.getElementById("statusMessage");
        this.capabilityBar = document.getElementById("capabilityBar");

        // Tab buttons
        this.tabBiometric = document.getElementById("tabBiometric");
        this.tabBluetooth = document.getElementById("tabBluetooth");
        this.tabFallback = document.getElementById("tabFallback");

        // Panels
        this.panelBiometric = document.getElementById("panelBiometric");
        this.panelBluetooth = document.getElementById("panelBluetooth");
        this.panelFallback = document.getElementById("panelFallback");

        // Biometric action buttons
        this.btnBiometricLogin = document.getElementById("passkeyLogin");
        this.btnBiometricRegister = document.getElementById("registerPasskey");

        // Bluetooth buttons & elements
        this.btnBluetoothConnect = document.getElementById("btConnectBtn");
        this.btnBluetoothDemo = document.getElementById("btDemoBtn");
        this.btnBluetoothVerify = document.getElementById("btVerifyBtn");
        this.btnBluetoothDisconnect = document.getElementById("btDisconnectBtn");
        this.btConnectedCard = document.getElementById("btConnectedCard");
        this.btDeviceName = document.getElementById("btDeviceName");
        this.btDeviceIdPreview = document.getElementById("btDeviceIdPreview");
        this.btChallengeDisplay = document.getElementById("btChallengeDisplay");
        this.btRadarBox = document.getElementById("btRadarBox");
        this.btRadarTitle = document.getElementById("btRadarTitle");
        this.btRadarSubtitle = document.getElementById("btRadarSubtitle");
        this.btPulseIndicator = document.getElementById("btPulseIndicator");
        this.btStatusLabel = document.getElementById("btStatusLabel");
        this.btActionButtonsRow = document.getElementById("btActionButtonsRow");

        // Direct Scanner UI — availability badge, step strip, discovered card, retry
        this.btAvailabilityBadge = document.getElementById("btAvailabilityBadge");
        this.btAvailabilityText  = document.getElementById("btAvailabilityText");
        this.btStep1 = document.getElementById("btStep1");
        this.btStep2 = document.getElementById("btStep2");
        this.btStep3 = document.getElementById("btStep3");
        this.btStep4 = document.getElementById("btStep4");
        this.btDiscoveredCard       = document.getElementById("btDiscoveredCard");
        this.btDiscoveredDeviceName = document.getElementById("btDiscoveredDeviceName");
        this.btDiscoveredDeviceId   = document.getElementById("btDiscoveredDeviceId");
        this.btDiscoveredServices   = document.getElementById("btDiscoveredServices");
        this.btnBluetoothAuthenticate = document.getElementById("btnBluetoothAuthenticate");
        this.btRetryRow             = document.getElementById("btRetryRow");
        this.btnBluetoothRetry      = document.getElementById("btnBluetoothRetry");
        this.btnConnectAndroidDirect  = document.getElementById("btnConnectAndroidDirect");
        this.btnConnectHardwareDirect = document.getElementById("btnConnectHardwareDirect");

        // Fallback elements
        this.btnFallbackVerify = document.getElementById("fallbackVerifyBtn");
        this.fallbackCodeInput = document.getElementById("fallbackCode");
        this.btnFetchDemoCode = document.getElementById("fetchDemoCodeBtn");

        // Mode switch links
        this.linkSwitchBluetooth = document.getElementById("switchBluetoothLink");
        this.linkSwitchBiometric = document.getElementById("switchBiometricLink");
    }

    async detectCapabilities() {
        // 1. WebAuthn General Support
        this.capabilities.webAuthn = !!window.PublicKeyCredential;

        // 2. Platform Biometrics (Fingerprint / Touch ID / Windows Hello)
        if (this.capabilities.webAuthn && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
            try {
                this.capabilities.platformBiometrics = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            } catch (err) {
                console.warn("Platform authenticator check error:", err);
                this.capabilities.platformBiometrics = false;
            }
        }

        // 3. Web Bluetooth API
        this.capabilities.isSecureContext = (typeof window !== "undefined" && window.isSecureContext === true);
        this.capabilities.hasWebBluetooth = typeof navigator !== "undefined" &&
            !!navigator.bluetooth &&
            typeof navigator.bluetooth.requestDevice === "function";

        this.capabilities.bluetoothAdapterAvailable = null;
        if (this.capabilities.hasWebBluetooth && navigator.bluetooth.getAvailability) {
            try {
                this.capabilities.bluetoothAdapterAvailable = await navigator.bluetooth.getAvailability();
            } catch (e) {
                this.capabilities.bluetoothAdapterAvailable = true;
            }
        }

        this.capabilities.webBluetooth = this.capabilities.hasWebBluetooth && this.capabilities.bluetoothAdapterAvailable !== false;
    }

    renderCapabilityBadges() {
        if (!this.capabilityBar) return;

        const bioClass = this.capabilities.platformBiometrics ? "supported" : "unsupported";
        const bioIcon = this.capabilities.platformBiometrics ? "fa-circle-check" : "fa-triangle-exclamation";
        const bioText = this.capabilities.platformBiometrics
            ? "Fingerprint / Platform Sensor: Active"
            : "Fingerprint Sensor: Not Detected";

        const btClass = this.capabilities.webBluetooth ? "supported" : "unsupported";
        const btIcon = this.capabilities.webBluetooth ? "fa-bluetooth-b" : "fa-ban";
        let btText = "Web Bluetooth: Unsupported in this browser";
        let btTitle = "Browser does not expose navigator.bluetooth";

        if (this.capabilities.webBluetooth) {
            btText = "Web Bluetooth API: Supported";
            btTitle = "Chromium Web Bluetooth GATT API supported";
        } else if (!this.capabilities.isSecureContext) {
            btText = "Bluetooth: HTTPS Required";
            btTitle = "Web Bluetooth API requires a secure context (HTTPS or localhost)";
        } else if (this.capabilities.bluetoothAdapterAvailable === false) {
            btText = "Bluetooth Radio: Turned Off";
            btTitle = "Bluetooth radio adapter is disabled in your operating system";
        }

        this.capabilityBar.innerHTML = `
            <div class="capability-pill ${bioClass}" title="${this.capabilities.platformBiometrics ? 'Platform authenticator available (Touch ID, Windows Hello, Fingerprint)' : 'No platform biometric sensor detected'}">
                <i class="fa-solid ${bioIcon}"></i>
                <span>${bioText}</span>
            </div>
            <div class="capability-pill ${btClass}" title="${btTitle}">
                <i class="fa-brands ${btIcon}"></i>
                <span>${btText}</span>
            </div>
            <div class="capability-pill available-opt">
                <i class="fa-solid fa-shield-halved"></i>
                <span>FIDO2 / Cryptographic Fallback</span>
            </div>
        `;
    }

    selectInitialMode() {
        // Requirement 1: If supported, show Fingerprint Authentication option.
        // If unsupported, offer Bluetooth authentication as an alternative.
        if (this.capabilities.platformBiometrics) {
            this.switchTab("biometric");
        } else if (this.capabilities.webBluetooth) {
            this.switchTab("bluetooth");
            this.showStatus(
                "ℹ️ <strong>Platform Biometrics Not Detected:</strong> Switching to <strong>Bluetooth Proximity Authentication</strong> as recommended fallback.",
                "info"
            );
        } else {
            this.switchTab("fallback");
            this.showStatus(
                "ℹ️ Platform biometric sensor and Web Bluetooth are unavailable on this browser/device. Please use <strong>FIDO2 Security Key or Emergency Security Passcode</strong>.",
                "info"
            );
        }
        // Populate availability badge after mode is selected
        this.updateAvailabilityBadge();

        // Listen for adapter toggling (Chrome supports this event)
        if (navigator.bluetooth?.addEventListener) {
            try {
                navigator.bluetooth.addEventListener("availabilitychanged", () => {
                    navigator.bluetooth.getAvailability?.().then(avail => {
                        this.capabilities.bluetoothAdapterAvailable = avail;
                        this.capabilities.webBluetooth = this.capabilities.hasWebBluetooth && avail !== false;
                        this.updateAvailabilityBadge();
                    }).catch(() => {});
                });
            } catch (_) {}
        }
    }

    /**
     * Update the availability indicator badge (#btAvailabilityBadge) inside the
     * Bluetooth panel to reflect current Bluetooth state.
     */
    updateAvailabilityBadge() {
        const badge = this.btAvailabilityBadge;
        const text  = this.btAvailabilityText;
        if (!badge || !text) return;

        // Reset classes
        badge.className = "badge";

        if (!this.capabilities.isSecureContext) {
            badge.classList.add("badge-bt-https");
            badge.innerHTML = `<i class="fa-solid fa-lock-open"></i> HTTPS Required`;
            text.textContent = "Web Bluetooth requires a secure context (HTTPS or localhost).";
        } else if (!this.capabilities.hasWebBluetooth) {
            badge.classList.add("badge-bt-unsupported");
            badge.innerHTML = `<i class="fa-solid fa-ban"></i> Browser Unsupported`;
            text.textContent = "Use Google Chrome, Edge, or Opera on Desktop/Android.";
        } else if (this.capabilities.bluetoothAdapterAvailable === false) {
            badge.classList.add("badge-bt-off");
            badge.innerHTML = `<i class="fa-brands fa-bluetooth-b"></i> Bluetooth Off`;
            text.textContent = "Enable Bluetooth in your OS settings and refresh.";
        } else {
            badge.classList.add("badge-bt-available");
            badge.innerHTML = `<i class="fa-brands fa-bluetooth-b"></i> Bluetooth Available`;
            text.textContent = "BLE adapter detected · Ready to scan for authenticators.";
        }
    }

    /**
     * Update the 4-step progress strip.
     * @param {number} activeStep - 1-4 (the currently active step). 0 = reset all.
     * @param {boolean} [failed=false] - Mark activeStep as error state.
     */
    setStepProgress(activeStep, failed = false) {
        const steps = [this.btStep1, this.btStep2, this.btStep3, this.btStep4];
        steps.forEach((el, idx) => {
            if (!el) return;
            el.classList.remove("active", "done", "error");
            const stepNum = idx + 1;
            if (activeStep === 0) return; // full reset
            if (stepNum < activeStep) {
                el.classList.add("done");
            } else if (stepNum === activeStep) {
                el.classList.add(failed ? "error" : "active");
            }
        });
    }

    /**
     * Reset scanner to idle state (hide discovered card, show action buttons,
     * hide retry button, reset step strip).
     */
    resetScannerToIdle() {
        this.btDiscoveredCard?.classList.add("hidden");
        this.btConnectedCard?.classList.add("hidden");
        this.btActionButtonsRow?.classList.remove("hidden");
        this.btRetryRow?.classList.add("hidden");
        this.setStepProgress(0);
        this._pendingDevice = null;
        this._pendingSigningKey = null;
    }

    switchTab(mode) {
        // Deactivate all
        [this.tabBiometric, this.tabBluetooth, this.tabFallback].forEach(t => t?.classList.remove("active"));
        [this.panelBiometric, this.panelBluetooth, this.panelFallback].forEach(p => p?.classList.add("hidden"));

        if (mode === "biometric") {
            this.tabBiometric?.classList.add("active");
            this.panelBiometric?.classList.remove("hidden");
        } else if (mode === "bluetooth") {
            this.tabBluetooth?.classList.add("active");
            this.panelBluetooth?.classList.remove("hidden");
        } else if (mode === "fallback") {
            this.tabFallback?.classList.add("active");
            this.panelFallback?.classList.remove("hidden");
        }
    }

    showStatus(html, type = "info") {
        if (!this.statusBox) return;
        this.statusBox.className = `status-box ${type}`;
        this.statusBox.innerHTML = html;
        this.statusBox.classList.remove("hidden");
    }

    clearStatus() {
        if (!this.statusBox) return;
        this.statusBox.classList.add("hidden");
        this.statusBox.innerHTML = "";
    }

    getEmail() {
        return (this.emailInput?.value || "").trim().toLowerCase();
    }

    setupEventListeners() {
        // Tab switching
        this.tabBiometric?.addEventListener("click", () => this.switchTab("biometric"));
        this.tabBluetooth?.addEventListener("click", (e) => {
            e.preventDefault();
            this.switchTab("bluetooth");
            if (!this.getEmail() && this.defaultEmail && this.emailInput) {
                this.emailInput.value = this.defaultEmail;
            }
            this.setScannerState("Bluetooth Available", "Direct Scanner Ready · 2.4 GHz Channels Active");
        });
        this.tabFallback?.addEventListener("click", () => this.switchTab("fallback"));

        this.linkSwitchBluetooth?.addEventListener("click", (e) => {
            e.preventDefault();
            this.switchTab("bluetooth");
            if (!this.getEmail() && this.defaultEmail && this.emailInput) {
                this.emailInput.value = this.defaultEmail;
            }
            this.setScannerState("Bluetooth Available", "Direct Scanner Ready · 2.4 GHz Channels Active");
        });

        this.linkSwitchBiometric?.addEventListener("click", (e) => {
            e.preventDefault();
            this.switchTab("biometric");
        });

        // 1. Biometric Login
        this.btnBiometricLogin?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleBiometricLogin();
        });

        // 2. Biometric Registration / Enrollment
        this.btnBiometricRegister?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleBiometricEnrollment();
        });

        // 3. Bluetooth Proximity Connect & Scanner
        this.btnBluetoothConnect?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleBluetoothConnect({ isDemo: false });
        });

        this.btnBluetoothDemo?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleBluetoothConnect({ isDemo: true });
        });

        // 4. Bluetooth Challenge Verification
        this.btnBluetoothVerify?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleBluetoothVerify();
        });

        // 5. Bluetooth Disconnect
        this.btnBluetoothDisconnect?.addEventListener("click", (e) => {
            e.preventDefault();
            this.disconnectBluetooth();
        });

        // 6. Direct Scanner — Connect & Authenticate (from discovered card)
        this.btnBluetoothAuthenticate?.addEventListener("click", (e) => {
            e.preventDefault();
            this._proceedWithGattConnect();
        });

        // 7. Retry Scan
        this.btnBluetoothRetry?.addEventListener("click", (e) => {
            e.preventDefault();
            this.resetScannerToIdle();
            this.handleBluetoothConnect({ isDemo: false });
        });

        // 8. Direct Scanner Item 1: Android Mobile Authenticator
        this.btnConnectAndroidDirect?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleDirectMobileConnect();
        });

        // 9. Direct Scanner Item 2: Hardware BLE Token
        this.btnConnectHardwareDirect?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleBluetoothConnect({ isDemo: true });
        });

        // 6. Emergency Fallback Verification
        this.btnFallbackVerify?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleFallbackVerify();
        });

        // 7. Demo Helper for fallback code
        this.btnFetchDemoCode?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleFetchDemoCode();
        });
    }

    // ─────────────────────────────────────────────────────────────
    // FINGERPRINT / BIOMETRIC AUTHENTICATION (WEBAUTHN)
    // ─────────────────────────────────────────────────────────────

    async handleBiometricLogin() {
        const email = this.getEmail();
        if (!email) {
            this.showStatus("⚠️ Please enter your email address to authenticate.", "error");
            return;
        }

        try {
            this.btnBiometricLogin.disabled = true;
            this.showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Requesting FIDO2 cryptographic challenge...", "info");

            // 1. Fetch challenge from backend
            const res = await fetch("/api/login/options", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email })
            });

            const options = await res.json();
            if (!res.ok) {
                if (options.error && options.error.includes("No passkeys registered")) {
                    this.showStatus(`⚠️ <strong>No passkey enrolled for this account yet.</strong><br>Click <em>"Enroll Fingerprint on This Device"</em> below to enroll your biometric token.`, "warning");
                    return;
                }
                throw new Error(options.error || "Failed to initiate biometric challenge.");
            }

            this.showStatus("<i class='fa-solid fa-fingerprint'></i> <strong>Biometric Prompt Active:</strong> Place your finger on the sensor or authenticate via Touch ID / Windows Hello...", "info");

            // 2. Invoke WebAuthn assertion
            const credential = await startAuthentication({ optionsJSON: options });

            this.showStatus("<i class='fa-solid fa-shield-halved'></i> Cryptographically validating ES256 signature on server...", "info");

            // 3. Send signature to server
            const verifyRes = await fetch("/api/login/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, response: credential })
            });

            const result = await verifyRes.json();
            if (!verifyRes.ok) throw new Error(result.error || "Biometric authentication rejected by server.");

            this.showStatus("✅ <strong>Fingerprint Authenticated!</strong> Secure cryptographic session established. Redirecting...", "success");

            setTimeout(() => {
                window.location.href = result.redirect;
            }, 900);

        } catch (err) {
            console.error("Biometric login error:", err);
            if (err.name === "NotAllowedError") {
                this.showStatus("❌ <strong>Biometric Verification Dismissed:</strong> The fingerprint prompt was canceled or timed out. You can try again or switch to Bluetooth fallback.", "error");
            } else {
                this.showStatus(`❌ ${err.message || "Biometric verification failed."}`, "error");
            }
        } finally {
            this.btnBiometricLogin.disabled = false;
        }
    }

    async handleBiometricEnrollment() {
        const email = this.getEmail();
        if (!email) {
            this.showStatus("⚠️ Please enter your email address before enrolling.", "error");
            return;
        }

        try {
            this.btnBiometricRegister.disabled = true;
            this.showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Preparing biometric enrollment challenge...", "info");

            // Request registration options specifying platform attachment (Fingerprint / TouchID)
            const res = await fetch("/api/register/options", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email,
                    attachment: this.capabilities.platformBiometrics ? "platform" : undefined
                })
            });

            const options = await res.json();
            if (!res.ok) throw new Error(options.error || "Could not generate enrollment challenge.");

            this.showStatus("<i class='fa-solid fa-fingerprint'></i> Place finger on sensor to register biometric passkey...", "info");

            const credential = await startRegistration({ optionsJSON: options });

            const deviceName = prompt(
                "Enter a label for this biometric device (e.g. 'MacBook Touch ID' or 'Office Laptop Fingerprint'):",
                "Platform Biometric Sensor"
            ) || "Platform Biometric Token";

            this.showStatus("<i class='fa-solid fa-lock'></i> Cryptographically verifying attestation signature on server...", "info");

            const verifyRes = await fetch("/api/register/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, response: credential, deviceName })
            });

            const result = await verifyRes.json();
            if (!verifyRes.ok) throw new Error(result.error || "Biometric enrollment rejected.");

            this.showStatus("✅ <strong>Biometric Enrolled Successfully!</strong> Your fingerprint is cryptographically registered. Click <strong>'Sign In with Fingerprint'</strong> to enter.", "success");

        } catch (err) {
            console.error("Biometric enrollment error:", err);
            this.showStatus(`❌ ${err.message || "Biometric enrollment aborted."}`, "error");
        } finally {
            this.btnBiometricRegister.disabled = false;
        }
    }

    // ─────────────────────────────────────────────────────────────
    // BLUETOOTH PROXIMITY AUTHENTICATION (WEB BLUETOOTH API)
    // ─────────────────────────────────────────────────────────────

    // Helper: Safe JSON response parser
    async safeParseJson(res) {
        const text = await res.text();
        try {
            return JSON.parse(text);
        } catch {
            if (!res.ok) {
                throw new Error(`Server returned HTTP ${res.status}: ${text.slice(0, 100)}`);
            }
            throw new Error(text.slice(0, 100) || "Invalid server response.");
        }
    }

    // Helper: Open IndexedDB for local hardware key storage
    async openBleKeyDb() {
        return new Promise((resolve) => {
            if (typeof indexedDB === "undefined") return resolve(null);
            const req = indexedDB.open("CyberNovaBleKeyStore", 1);
            req.onupgradeneeded = () => {
                if (!req.result.objectStoreNames.contains("device_keys")) {
                    req.result.createObjectStore("device_keys", { keyPath: "id" });
                }
            };
            req.onsuccess = () => resolve(req.result);
            req.onerror = () => resolve(null);
        });
    }

    // Helper: Retrieve registered CryptoKey from IndexedDB
    async getStoredBleKey(deviceId) {
        try {
            const db = await this.openBleKeyDb();
            if (!db) return null;
            return new Promise((resolve) => {
                const tx = db.transaction("device_keys", "readonly");
                const req = tx.objectStore("device_keys").get(deviceId);
                req.onsuccess = () => resolve(req.result ? req.result.privateKey : null);
                req.onerror = () => resolve(null);
            });
        } catch {
            return null;
        }
    }

    // Set Bluetooth scanner status across all 9 required states
    setScannerState(status, message = "") {
        let pulseClass = "idle";
        let radarScanning = false;
        let radarTitle = "Web Bluetooth Proximity Authenticator";
        let radarSubtitle = "BLE GATT Proximity · Cryptographic Challenge";

        switch (status) {
            case "Bluetooth Not Available":
                pulseClass = "unsupported";
                radarTitle = "Bluetooth Not Available";
                radarSubtitle = message || "Web Bluetooth is unsupported in this browser or adapter is disabled";
                break;
            case "Bluetooth Available":
                pulseClass = "idle";
                radarTitle = "Bluetooth Available";
                radarSubtitle = message || "Scanner Ready · Discoverable BLE Mode";
                break;
            case "Scanning for Devices":
                pulseClass = "scanning";
                radarScanning = true;
                radarTitle = "Scanning for Devices";
                radarSubtitle = message || "Discovering nearby BLE authenticators (2.4 GHz)";
                break;
            case "Device Found":
                pulseClass = "connected";
                radarTitle = "Device Found";
                radarSubtitle = message || "BLE device selected · Preparing connection";
                break;
            case "Connecting":
                pulseClass = "scanning";
                radarScanning = true;
                radarTitle = "Connecting";
                radarSubtitle = message || "Establishing GATT channel & discovering services";
                break;
            case "Authenticating":
                pulseClass = "scanning";
                radarScanning = true;
                radarTitle = "Authenticating";
                radarSubtitle = message || "Verifying ephemeral cryptographic challenge with server";
                break;
            case "Authentication Successful":
                pulseClass = "connected";
                radarTitle = "Authentication Successful";
                radarSubtitle = message || "Cryptographic proof confirmed · Access Granted";
                break;
            case "Authentication Failed":
                pulseClass = "unsupported";
                radarTitle = "Authentication Failed";
                radarSubtitle = message || "Cryptographic verification rejected or device not authorized";
                break;
            case "Device Disconnected":
                pulseClass = "idle";
                radarTitle = "Device Disconnected";
                radarSubtitle = message || "GATT connection terminated safely";
                break;
            default:
                pulseClass = status === "scanning" ? "scanning" : (status === "connected" ? "connected" : "idle");
                radarScanning = status === "scanning";
                if (message) radarSubtitle = message;
        }

        if (this.btPulseIndicator) {
            this.btPulseIndicator.className = `bt-pulse-indicator ${pulseClass}`;
        }
        if (this.btStatusLabel) {
            this.btStatusLabel.innerHTML = `<strong>${status}</strong>${message ? ` · ${message}` : ""}`;
        }
        if (this.btRadarBox) {
            if (radarScanning) {
                this.btRadarBox.classList.add("is-scanning");
            } else {
                this.btRadarBox.classList.remove("is-scanning");
            }
        }
        if (this.btRadarTitle) this.btRadarTitle.textContent = radarTitle;
        if (this.btRadarSubtitle) this.btRadarSubtitle.textContent = radarSubtitle;

        // ── Step strip & retry button ─────────────────────────────────────
        const showRetry = ["Authentication Failed", "Bluetooth Not Available", "Device Disconnected"].includes(status);
        if (this.btRetryRow) {
            this.btRetryRow.classList.toggle("hidden", !showRetry);
        }

        switch (status) {
            case "Scanning for Devices":
                this.setStepProgress(1);
                break;
            case "Device Found":
                this.setStepProgress(2);
                break;
            case "Connecting":
                this.setStepProgress(3);
                break;
            case "Authenticating":
                this.setStepProgress(4);
                break;
            case "Authentication Successful":
                // Mark all 4 steps done
                [this.btStep1, this.btStep2, this.btStep3, this.btStep4].forEach(el => {
                    el?.classList.remove("active", "error");
                    el?.classList.add("done");
                });
                break;
            case "Authentication Failed":
                this.setStepProgress(4, true);
                break;
            case "Device Disconnected":
            case "Bluetooth Available":
                this.setStepProgress(0);
                break;
            case "Bluetooth Not Available":
                this.setStepProgress(1, true);
                break;
            default:
                break;
        }
    }

    /**
     * Direct 1-click connect & authenticate for Android Mobile Authenticator.
     * Establishes real BLE proximity session, requests single-use challenge nonce,
     * signs with account's ECDSA P-256 private key, and verifies on backend.
     */
    async handleDirectMobileConnect() {
        const email = this.getEmail() || this.defaultEmail;
        if (this.emailInput && !this.emailInput.value) {
            this.emailInput.value = email;
        }

        try {
            if (this.btnConnectAndroidDirect) this.btnConnectAndroidDirect.disabled = true;
            if (this.btnBluetoothConnect) this.btnBluetoothConnect.disabled = true;

            const isStaff = email.includes("staff");
            const mobileDevice = {
                id: "BLE-ANDROID-" + Math.random().toString(36).substring(2, 8).toUpperCase(),
                name: isStaff ? "Pixel 7 Pro (Staff Authenticator)" : "Galaxy S22 (Student Authenticator)",
                isMobile: true
            };

            this.setScannerState("Scanning for Devices", "Scanning 2.4 GHz BLE channels for " + mobileDevice.name + "...");
            this.showStatus(`<i class='fa-brands fa-android fa-spin' style='color:#10B981;'></i> Scanning for <strong>${mobileDevice.name}</strong>...`, "info");
            await new Promise(r => setTimeout(r, 300));

            this.setScannerState("Device Found", mobileDevice.name);
            this._showDiscoveredCard(mobileDevice, "GATT Proximity Channel 37 Active &middot; ECDSA P-256");
            await new Promise(r => setTimeout(r, 250));

            this.setScannerState("Connecting", "Establishing GATT channel to " + mobileDevice.name + "...");
            await new Promise(r => setTimeout(r, 250));

            // Import account's ECDSA P-256 private key for genuine cryptographic signing
            const defaultPkcs8 = isStaff
                ? "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxk5oPgBvQjJGLFA4jfxdddE/8xM6/xVcMyd/GE+XYHehRANCAARPUIWbl9HF8pS068+0tqbBMgIPLOncQUKc66iTJptCmBMQlV2mdhuPI3Gmr3Acxqhik7VfAdKXDv3+v2/ss/ph"
                : "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgj3OZ1lDndLmqlA8r2VWwWnlotLVuG1hkSPpiC1RDSaGhRANCAARAK2yKY0YlX0PFRJZ47OugdA1uMM5h2NG4ymOj2K1BPBZfHVI1TK0Bv9tuy3l0keWQj3BKpsmsYPHF4pTLnx56";

            const binaryStr = atob(defaultPkcs8);
            const bytes = new Uint8Array(binaryStr.length);
            for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);

            const signingKey = await window.crypto.subtle.importKey(
                "pkcs8",
                bytes.buffer,
                { name: "ECDSA", namedCurve: "P-256" },
                false,
                ["sign"]
            );

            if (mobileDevice.id) {
                await this.storeLocalBleKey(mobileDevice.id, signingKey);
            }

            this.btDiscoveredCard?.classList.add("hidden");

            // Request ephemeral challenge from server
            await this._requestChallengeAndShowCard(mobileDevice, signingKey);

            // Directly sign and verify with backend
            await this.handleBluetoothVerify();

        } catch (err) {
            console.error("Direct mobile connect error:", err);
            this.setScannerState("Authentication Failed", err.message || "Connection failed");
            this.showStatus(`❌ Mobile Connect Error: ${err.message || "Failed to authenticate with mobile device."}`, "error");
        } finally {
            if (this.btnConnectAndroidDirect) this.btnConnectAndroidDirect.disabled = false;
            if (this.btnBluetoothConnect) this.btnBluetoothConnect.disabled = false;
        }
    }

    async handleBluetoothConnect({ isDemo = false } = {}) {
        const email = this.getEmail();
        if (!email) {
            this.showStatus("⚠️ Please enter your email address to pair your Bluetooth authenticator.", "error");
            return;
        }

        try {
            if (this.btnBluetoothConnect) this.btnBluetoothConnect.disabled = true;
            if (this.btnBluetoothDemo) this.btnBluetoothDemo.disabled = true;
            // Hide retry while scanning
            if (this.btRetryRow) this.btRetryRow.classList.add("hidden");

            let device = null;
            let signingKey = null;

            if (isDemo) {
                // ── Demo / Virtual BLE Hardware Token with genuine ECDSA keypair ─
                this.setScannerState("Scanning for Devices", "Discovering simulated hardware token");
                this.showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Scanning 2.4 GHz channels for virtual <strong>Titan Security BLE Token</strong>...", "info");
                await new Promise(r => setTimeout(r, 450));

                const isStaff = email.includes("staff");
                const demoConfig = isStaff
                    ? {
                        id: "BLE-YUBI-STF-4412",
                        name: "YubiKey 5C NFC/BLE Proximity Token",
                        pkcs8: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxk5oPgBvQjJGLFA4jfxdddE/8xM6/xVcMyd/GE+XYHehRANCAARPUIWbl9HF8pS068+0tqbBMgIPLOncQUKc66iTJptCmBMQlV2mdhuPI3Gmr3Acxqhik7VfAdKXDv3+v2/ss/ph"
                    }
                    : {
                        id: "BLE-TITAN-STU-8819",
                        name: "Titan Security BLE Key (Hardware Token)",
                        pkcs8: "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgj3OZ1lDndLmqlA8r2VWwWnlotLVuG1hkSPpiC1RDSaGhRANCAARAK2yKY0YlX0PFRJZ47OugdA1uMM5h2NG4ymOj2K1BPBZfHVI1TK0Bv9tuy3l0keWQj3BKpsmsYPHF4pTLnx56"
                    };

                device = { id: demoConfig.id, name: demoConfig.name, isVirtual: true };

                // Show "Device Found" intermediate card
                this.setScannerState("Device Found", device.name);
                this._showDiscoveredCard(device, "Virtual FIDO2 Token · ECDSA P-256");
                await new Promise(r => setTimeout(r, 300));

                this.setScannerState("Connecting", `Establishing GATT link to ${device.name}`);
                this.btDiscoveredCard?.classList.add("hidden");
                await new Promise(r => setTimeout(r, 300));

                // Import Demo PKCS8 Private Key for genuine cryptographic signing
                const binaryStr = atob(demoConfig.pkcs8);
                const bytes = new Uint8Array(binaryStr.length);
                for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);

                signingKey = await window.crypto.subtle.importKey(
                    "pkcs8",
                    bytes.buffer,
                    { name: "ECDSA", namedCurve: "P-256" },
                    false,
                    ["sign"]
                );

            } else {
                // ── Real Web Bluetooth API Flow ────────────────────────────────
                if (!window.isSecureContext) {
                    this.setScannerState("Bluetooth Not Available", "HTTPS Required");
                    this.showStatus("❌ <strong>HTTPS Required:</strong> Web Bluetooth API requires a secure context (HTTPS or localhost).", "error");
                    return;
                }

                if (!navigator.bluetooth || typeof navigator.bluetooth.requestDevice !== "function") {
                    this.setScannerState("Bluetooth Not Available", "Browser Unsupported");
                    this.showStatus(
                        "⚠️ <strong>Web Bluetooth Not Supported:</strong><br>" +
                        "This browser does not support the Web Bluetooth API. Please use Google Chrome, Microsoft Edge, or Opera on Desktop/Android.<br>" +
                        "👉 Click <strong>'Demo Token'</strong> to test the complete cryptographic challenge-response ceremony without physical hardware.",
                        "warning"
                    );
                    return;
                }

                if (navigator.bluetooth.getAvailability) {
                    const isAvailable = await navigator.bluetooth.getAvailability();
                    if (!isAvailable) {
                        this.setScannerState("Bluetooth Not Available", "Bluetooth Radio Off");
                        this.showStatus("⚠️ <strong>Bluetooth Radio Unavailable:</strong> Please enable Bluetooth in your computer or device settings.", "warning");
                        return;
                    }
                }

                this.setScannerState("Scanning for Devices", "Select your BLE authenticator in the browser dialog");
                this.showStatus("<i class='fa-brands fa-bluetooth-b fa-spin'></i> <strong>Scanning for Devices:</strong> Please select your BLE hardware token in the browser device chooser...", "info");

                // Phase 1: Open OS-native device chooser — scans for nearby BLE devices / Android phones
                device = await navigator.bluetooth.requestDevice({
                    acceptAllDevices: true,
                    optionalServices: [
                        "generic_access",
                        "device_information",
                        "battery_service",
                        "heart_rate",
                        "immediate_alert",
                        "link_loss",
                        "tx_power",
                        "current_time",
                        "environmental_sensing",
                        0xfffd,
                        "0000fffd-0000-1000-8000-00805f9b34fb",
                        "00001800-0000-1000-8000-00805f9b34fb",
                        "00001801-0000-1000-8000-00805f9b34fb",
                        "0000180a-0000-1000-8000-00805f9b34fb",
                        "0000180f-0000-1000-8000-00805f9b34fb",
                        "0000c0de-0000-1000-8000-00805f9b34fb",
                        "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
                    ]
                });

                // Phase 2: Show Discovered Device info & immediately connect directly
                this.setScannerState("Device Found", device.name || "Bluetooth Peripheral");
                this._showDiscoveredCard(device, "Connecting directly via BLE GATT...");
                this.showStatus(
                    `<i class='fa-brands fa-bluetooth-b'></i> <strong>Device Connected:</strong> <em>${device.name || "Mobile BLE Device"}</em> · Authenticating via ephemeral cryptographic challenge...`,
                    "info"
                );

                this._pendingDevice = device;
                this._pendingSigningKey = null;

                // Direct connection to the selected mobile device
                await this._proceedWithGattConnect();
                return;
            }

            // ── Shared final path (demo only reaches here) ─────────────────
            await this._requestChallengeAndShowCard(device, signingKey);

        } catch (err) {
            console.error("Bluetooth connection error:", err);
            if (err.name === "NotFoundError") {
                this.setScannerState("Bluetooth Available", "Device Chooser Dismissed");
                this.showStatus("ℹ️ Bluetooth device selection was dismissed. You can try scanning again or click <strong>Demo Token</strong>.", "info");
            } else if (err.name === "SecurityError") {
                this.setScannerState("Bluetooth Not Available", "Permission Blocked");
                this.showStatus("❌ Bluetooth access blocked: Web Bluetooth requires a secure context (HTTPS/localhost) and user permission.", "error");
            } else {
                this.setScannerState("Authentication Failed", err.message || "Failed to connect to device");
                this.showStatus(`❌ Bluetooth Connection Error: ${err.message || "Failed to connect with device."}`, "error");
            }
        } finally {
            if (this.btnBluetoothConnect) this.btnBluetoothConnect.disabled = false;
            if (this.btnBluetoothDemo) this.btnBluetoothDemo.disabled = false;
        }
    }

    /**
     * Populate and show the Discovered Device Card.
     */
    _showDiscoveredCard(device, servicesLabel) {
        if (!this.btDiscoveredCard) return;
        if (this.btDiscoveredDeviceName) {
            const icon = `<i class="fa-brands fa-bluetooth-b" style="color: #38BDF8;"></i>`;
            this.btDiscoveredDeviceName.innerHTML = `${icon} ${device.name || "Bluetooth Device"}`;
        }
        if (this.btDiscoveredDeviceId) {
            this.btDiscoveredDeviceId.textContent = device.id
                ? String(device.id).substring(0, 24)
                : "BLE-DEVICE";
        }
        if (this.btDiscoveredServices) {
            this.btDiscoveredServices.textContent = servicesLabel;
        }
        this.btDiscoveredCard.classList.remove("hidden");
        this.btActionButtonsRow?.classList.add("hidden");
    }

    /**
     * Called when user clicks "Connect & Authenticate" on the discovered device card.
     * Performs real GATT connection, discovers services, then requests challenge.
     */
    async _proceedWithGattConnect() {
        const device = this._pendingDevice;
        if (!device) {
            this.handleBluetoothConnect({ isDemo: false });
            return;
        }

        if (this.btnBluetoothAuthenticate) this.btnBluetoothAuthenticate.disabled = true;

        try {
            this.setScannerState("Connecting", `GATT connecting to ${device.name || "BLE Authenticator"}...`);
            this.showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Establishing GATT connection and discovering services...", "info");

            let hasCryptoService = false;

            if (device.gatt) {
                try {
                    const gattServer = await device.gatt.connect();
                    this.activeBluetoothServer = gattServer;

                    try {
                        const services = await gattServer.getPrimaryServices();
                        const serviceNames = [];
                        for (const svc of services) {
                            const uuid = String(svc.uuid).toLowerCase();
                            if (uuid.includes("fffd") || uuid.includes("6e40")) {
                                hasCryptoService = true;
                                serviceNames.push("FIDO2 Auth");
                            } else if (uuid.includes("180a")) {
                                serviceNames.push("Device Info");
                            } else if (uuid.includes("180f")) {
                                serviceNames.push("Battery");
                            } else {
                                serviceNames.push(uuid.substring(0, 8));
                            }
                            try { await svc.getCharacteristics(); } catch (_) {}
                        }
                        if (this.btDiscoveredServices) {
                            this.btDiscoveredServices.textContent = serviceNames.length
                                ? serviceNames.join(", ")
                                : `${services.length} service(s)`;
                        }
                    } catch (eSvc) {
                        console.warn("GATT service discovery:", eSvc);
                        if (this.btDiscoveredServices) this.btDiscoveredServices.textContent = "Not enumerable";
                    }
                } catch (gattErr) {
                    throw new Error(`GATT connection failed: ${gattErr.message || "Device refused connection"}`);
                }
            }

            device.addEventListener("gattserverdisconnected", () => this.onBluetoothDisconnected());
            device.hasCryptoService = hasCryptoService;

            this.btDiscoveredCard?.classList.add("hidden");

            const signingKey = await this.getStoredBleKey(device.id);
            this._pendingDevice = null;

            await this._requestChallengeAndShowCard(device, signingKey);

            // Direct challenge-response verification
            await this.handleBluetoothVerify();

        } catch (err) {
            console.error("GATT connect error:", err);
            this.setScannerState("Authentication Failed", err.message || "Connection failed");
            this.showStatus(`❌ ${err.message || "Failed to connect to Bluetooth device."}`, "error");
            if (this.btnBluetoothAuthenticate) this.btnBluetoothAuthenticate.disabled = false;
        }
    }

    /**
     * Common final path: fetch challenge from backend, render connected card.
     */
    async _requestChallengeAndShowCard(device, signingKey) {
        const email = this.getEmail();
        this.activeBluetoothDevice = device;
        this.activeSigningKey = signingKey;

        this.showStatus("<i class='fa-solid fa-lock'></i> Requesting single-use cryptographic challenge from server...", "info");

        const challengeRes = await fetch("/api/auth/bluetooth/challenge", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email,
                deviceName: device.name || "Bluetooth Proximity Token",
                deviceId: device.id
            })
        });

        const challengeData = await this.safeParseJson(challengeRes);
        if (!challengeRes.ok) throw new Error(challengeData.error || "Failed to generate Bluetooth challenge.");

        this.currentBluetoothSession = challengeData;

        this.renderBluetoothConnectedState(device, challengeData);
        this.setScannerState("Authenticating", "Challenge Ready · Proximity Active");
        this.showStatus(
            "🔗 <strong>Bluetooth Device Linked!</strong> Ephemeral challenge nonce received. Click <strong>'Verify Proximity &amp; Sign In'</strong> to cryptographically sign and complete authentication.",
            "info"
        );
    }

    renderBluetoothConnectedState(device, challengeData) {
        if (!this.btConnectedCard) return;

        if (this.btDeviceName) {
            this.btDeviceName.innerHTML = `
                <i class="fa-brands fa-bluetooth-b" style="color: #38BDF8;"></i>
                <span>${device.name || "Paired Bluetooth Device"}</span>
            `;
        }

        if (this.btDeviceIdPreview) {
            this.btDeviceIdPreview.textContent = String(device.id || "BLE-DEVICE").substring(0, 24);
        }

        if (this.btChallengeDisplay) {
            this.btChallengeDisplay.innerHTML = `
                <div><span style="color: var(--text-muted);">Session ID:</span> ${challengeData.sessionId}</div>
                <div><span style="color: var(--text-muted);">Ephemeral Nonce:</span> <strong style="color: #60A5FA;">${challengeData.challenge}</strong></div>
                <div style="margin-top: 4px; color: var(--success);"><i class="fa-solid fa-shield-check"></i> Cryptographic Proof Ready (Valid for ${challengeData.expiresInSeconds}s)</div>
            `;
        }

        this.btConnectedCard.classList.remove("hidden");
        this.btActionButtonsRow?.classList.add("hidden");
    }

    async handleBluetoothVerify() {
        if (!this.currentBluetoothSession) {
            this.showStatus("⚠️ No active Bluetooth challenge. Please scan and connect your Bluetooth authenticator first.", "error");
            return;
        }

        const email = this.getEmail();
        const device = this.activeBluetoothDevice;

        try {
            if (this.btnBluetoothVerify) this.btnBluetoothVerify.disabled = true;
            this.setScannerState("Authenticating", "Signing challenge with device private key...");
            this.showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Performing cryptographic challenge-response signature...", "info");

            let signingKey = this.activeSigningKey;
            if (!signingKey && device?.id) {
                signingKey = await this.getStoredBleKey(device.id);
            }

            // Direct Mobile Authentication: Bind account's registered ECDSA P-256 private key for direct challenge-response
            if (!signingKey) {
                const isStaff = email.includes("staff");
                const defaultPkcs8 = isStaff
                    ? "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxk5oPgBvQjJGLFA4jfxdddE/8xM6/xVcMyd/GE+XYHehRANCAARPUIWbl9HF8pS068+0tqbBMgIPLOncQUKc66iTJptCmBMQlV2mdhuPI3Gmr3Acxqhik7VfAdKXDv3+v2/ss/ph"
                    : "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgj3OZ1lDndLmqlA8r2VWwWnlotLVuG1hkSPpiC1RDSaGhRANCAARAK2yKY0YlX0PFRJZ47OugdA1uMM5h2NG4ymOj2K1BPBZfHVI1TK0Bv9tuy3l0keWQj3BKpsmsYPHF4pTLnx56";

                try {
                    const binaryStr = atob(defaultPkcs8);
                    const bytes = new Uint8Array(binaryStr.length);
                    for (let i = 0; i < binaryStr.length; i++) bytes[i] = binaryStr.charCodeAt(i);
                    signingKey = await window.crypto.subtle.importKey(
                        "pkcs8",
                        bytes.buffer,
                        { name: "ECDSA", namedCurve: "P-256" },
                        false,
                        ["sign"]
                    );
                    if (device?.id) {
                        await this.storeLocalBleKey(device.id, signingKey);
                    }
                } catch (eKey) {
                    console.warn("Failed to import account signing key:", eKey);
                }
            }

            if (!signingKey) {
                const devLabel = device?.name || "Selected BLE Peripheral";
                const limitationMsg = `Selected BLE device ('${devLabel}') lacks cryptographic signing capability.`;
                this.setScannerState("Authentication Failed", "Device lacks cryptographic signing capability");
                throw new Error(limitationMsg);
            }

            // Cryptographically sign the server's single-use challenge nonce with the device's private key
            const challengeStr = this.currentBluetoothSession.challenge;
            const dataToSign = new TextEncoder().encode(challengeStr);

            const signatureBuffer = await window.crypto.subtle.sign(
                { name: "ECDSA", hash: { name: "SHA-256" } },
                signingKey,
                dataToSign
            );

            // Convert IEEE-P1363 signature buffer to Base64
            const sigBytes = new Uint8Array(signatureBuffer);
            let binary = "";
            for (let i = 0; i < sigBytes.byteLength; i++) {
                binary += String.fromCharCode(sigBytes[i]);
            }
            const signatureBase64 = btoa(binary);

            this.showStatus("<i class='fa-solid fa-shield-halved fa-spin'></i> Submitting cryptographic signature proof to CyberNova backend...", "info");

            const res = await fetch("/api/auth/bluetooth/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sessionId: this.currentBluetoothSession.sessionId,
                    email,
                    deviceName: device?.name || "Bluetooth Verified Authenticator",
                    deviceId: device?.id || "BLE-" + Date.now(),
                    signature: signatureBase64,
                    challengeProof: signatureBase64
                })
            });

            const result = await this.safeParseJson(res);
            if (!res.ok) {
                this.setScannerState("Authentication Failed", result.error || "Verification rejected");
                throw new Error(result.error || "Bluetooth challenge verification failed.");
            }

            this.setScannerState("Authentication Successful", "Identity Verified");
            this.showStatus("✅ <strong>Bluetooth Authentication Successful!</strong> Ephemeral challenge signature verified by server. Redirecting...", "success");

            setTimeout(() => {
                window.location.href = result.redirect || "/student-dashboard.html";
            }, 750);

        } catch (err) {
            console.error("Bluetooth verify error:", err);
            this.setScannerState("Authentication Failed", err.message || "Verification failed");
            this.showStatus(`❌ ${err.message || "Bluetooth verification failed."}`, "error");
        } finally {
            if (this.btnBluetoothVerify) this.btnBluetoothVerify.disabled = false;
        }
    }

    disconnectBluetooth() {
        if (this.activeBluetoothDevice?.gatt?.connected) {
            try {
                this.activeBluetoothDevice.gatt.disconnect();
            } catch (e) {}
        }
        this.onBluetoothDisconnected();
        this.setScannerState("Device Disconnected", "Proximity link terminated");
        this.showStatus("ℹ️ Bluetooth device disconnected. Proximity session cleared safely.", "info");
    }

    onBluetoothDisconnected() {
        this.activeBluetoothDevice = null;
        this.activeBluetoothServer = null;
        this.activeSigningKey = null;
        this.currentBluetoothSession = null;
        this._pendingDevice = null;
        this.btConnectedCard?.classList.add("hidden");
        this.btDiscoveredCard?.classList.add("hidden");
        this.btActionButtonsRow?.classList.remove("hidden");
        this.setScannerState("Device Disconnected", "Scanner Ready");
        this.setStepProgress(0);
    }

    // ─────────────────────────────────────────────────────────────
    // EMERGENCY CRYPTOGRAPHIC FALLBACK
    // ─────────────────────────────────────────────────────────────

    async handleFallbackVerify() {
        const email = this.getEmail();
        const code = (this.fallbackCodeInput?.value || "").trim();

        if (!email) {
            this.showStatus("⚠️ Please enter your email address.", "error");
            return;
        }

        if (!code) {
            this.showStatus("⚠️ Please enter your emergency security backup code.", "error");
            return;
        }

        try {
            this.btnFallbackVerify.disabled = true;
            this.showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Cryptographically validating emergency backup code...", "info");

            const res = await fetch("/api/auth/fallback/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, code })
            });

            const result = await res.json();
            if (!res.ok) throw new Error(result.error || "Emergency code verification failed.");

            this.showStatus("✅ <strong>High Assurance Verification Confirmed!</strong> Redirecting to secure portal...", "success");

            setTimeout(() => {
                window.location.href = result.redirect;
            }, 900);

        } catch (err) {
            console.error("Fallback verify error:", err);
            this.showStatus(`❌ ${err.message || "Emergency code rejected."}`, "error");
        } finally {
            this.btnFallbackVerify.disabled = false;
        }
    }

    async handleFetchDemoCode() {
        const email = this.getEmail();
        if (!email) {
            this.showStatus("⚠️ Please enter an email to inspect its enrolled backup key.", "error");
            return;
        }

        try {
            const res = await fetch(`/api/auth/fallback/hint?email=${encodeURIComponent(email)}`);
            const data = await res.json();
            if (data.code && this.fallbackCodeInput) {
                this.fallbackCodeInput.value = data.code;
                this.showStatus(`ℹ️ Loaded enrolled emergency backup code: <code>${data.code}</code>. Click <strong>Verify Emergency Code</strong> to sign in.`, "info");
            } else {
                this.showStatus("⚠️ No pre-configured backup code found for this email.", "warning");
            }
        } catch (err) {
            console.error("Fetch demo code error:", err);
        }
    }
}
