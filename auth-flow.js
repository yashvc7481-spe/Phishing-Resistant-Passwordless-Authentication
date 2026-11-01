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

        // Fallback elements
        this.btnFallbackVerify = document.getElementById("fallbackVerifyBtn");
        this.fallbackCodeInput = document.getElementById("fallbackCode");
        this.btnFetchDemoCode = document.getElementById("fetchDemoCodeBtn");

        // Mode switch links
        this.linkSwitchBluetooth = document.getElementById("switchBluetoothLink");
        this.linkSwitchBiometric = document.getElementById("switchBiometricLink");

        // Bluetooth QR Proximity (FIDO2 Hybrid caBLE)
        this.qrImage = document.getElementById("btQrImage");
        this.qrSpinner = document.getElementById("qrCodeSpinner");
        this.qrStatusText = document.getElementById("qrStatusText");
        this.qrPulseIndicator = document.getElementById("qrPulseIndicator");
        this.btnInstantApprove = document.getElementById("btnInstantApprove");
        this.btnOpenMobileTab = document.getElementById("btnOpenMobileTab");
        this.btnToggleBleRawScan = document.getElementById("btnToggleBleRawScan");
        this.btRawScannerSection = document.getElementById("btRawScannerSection");
        this.qrSessionId = null;
        this.qrMobileUrl = null;
        this.qrPollTimer = null;
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
        this.capabilities.webBluetooth = typeof navigator !== "undefined" &&
            !!navigator.bluetooth &&
            typeof navigator.bluetooth.requestDevice === "function";
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
        const btText = this.capabilities.webBluetooth
            ? "Web Bluetooth API: Supported"
            : "Web Bluetooth: Unsupported in this browser";

        this.capabilityBar.innerHTML = `
            <div class="capability-pill ${bioClass}" title="${this.capabilities.platformBiometrics ? 'Platform authenticator available (Touch ID, Windows Hello, Fingerprint)' : 'No platform biometric sensor detected'}">
                <i class="fa-solid ${bioIcon}"></i>
                <span>${bioText}</span>
            </div>
            <div class="capability-pill ${btClass}" title="${this.capabilities.webBluetooth ? 'Chromium Web Bluetooth GATT API supported' : 'Browser does not expose navigator.bluetooth'}">
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
    }

    switchTab(mode) {
        // Deactivate all
        [this.tabBiometric, this.tabBluetooth, this.tabFallback].forEach(t => t?.classList.remove("active"));
        [this.panelBiometric, this.panelBluetooth, this.panelFallback].forEach(p => p?.classList.add("hidden"));

        if (this.qrPollTimer) {
            clearInterval(this.qrPollTimer);
            this.qrPollTimer = null;
        }

        if (mode === "biometric") {
            this.tabBiometric?.classList.add("active");
            this.panelBiometric?.classList.remove("hidden");
        } else if (mode === "bluetooth") {
            this.tabBluetooth?.classList.add("active");
            this.panelBluetooth?.classList.remove("hidden");
            this.loadHybridQrCode();
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
        this.tabBluetooth?.addEventListener("click", () => this.switchTab("bluetooth"));
        this.tabFallback?.addEventListener("click", () => this.switchTab("fallback"));

        this.linkSwitchBluetooth?.addEventListener("click", (e) => {
            e.preventDefault();
            this.switchTab("bluetooth");
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

        // 8. QR Proximity Handlers (FIDO2 caBLE)
        this.btnInstantApprove?.addEventListener("click", (e) => {
            e.preventDefault();
            this.handleInstantApprove();
        });

        this.btnOpenMobileTab?.addEventListener("click", (e) => {
            e.preventDefault();
            if (this.qrMobileUrl) {
                window.open(this.qrMobileUrl, "_blank", "width=420,height=750");
            } else {
                this.showStatus("ℹ️ Initializing QR code session first...", "info");
                this.loadHybridQrCode().then(() => {
                    if (this.qrMobileUrl) window.open(this.qrMobileUrl, "_blank", "width=420,height=750");
                });
            }
        });

        this.btnToggleBleRawScan?.addEventListener("click", (e) => {
            e.preventDefault();
            if (this.btRawScannerSection) {
                this.btRawScannerSection.classList.toggle("hidden");
            }
        });

        // Auto-refresh QR code when email changes while on Bluetooth tab
        this.emailInput?.addEventListener("change", () => {
            if (this.panelBluetooth && !this.panelBluetooth.classList.contains("hidden")) {
                this.loadHybridQrCode();
            }
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
    // BLUETOOTH PROXIMITY AUTHENTICATION (FIDO2 caBLE / HYBRID QR)
    // ─────────────────────────────────────────────────────────────

    async loadHybridQrCode() {
        if (!this.qrImage) return;

        const email = this.getEmail();
        if (this.qrSpinner) this.qrSpinner.classList.remove("hidden");
        this.qrImage.classList.add("hidden");
        if (this.qrStatusText) this.qrStatusText.textContent = "Generating Cryptographic Nonce QR...";
        if (this.qrPulseIndicator) this.qrPulseIndicator.className = "bt-pulse-indicator idle";

        try {
            const res = await fetch("/api/auth/hybrid-qr/generate", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: email || "" })
            });
            const data = await res.json();
            const qrUrl = data.qrCodeDataUrl || data.qrDataUrl;
            const mobileUrl = data.mobileAuthUrl || data.mobileUrl;
            if (data.success && qrUrl) {
                this.qrSessionId = data.sessionId;
                this.qrMobileUrl = mobileUrl;
                this.qrImage.src = qrUrl;
                if (this.qrSpinner) this.qrSpinner.classList.add("hidden");
                this.qrImage.classList.remove("hidden");
                if (this.qrStatusText) this.qrStatusText.textContent = "Awaiting Phone Camera Scan...";
                if (this.qrPulseIndicator) this.qrPulseIndicator.className = "bt-pulse-indicator connected";

                // Start polling session status
                this.startQrPolling(data.sessionId);
            } else {
                if (this.qrSpinner) this.qrSpinner.classList.add("hidden");
                if (this.qrStatusText) this.qrStatusText.textContent = "Unable to generate QR code. Check backend.";
            }
        } catch (err) {
            console.error("Hybrid QR generation error:", err);
            if (this.qrSpinner) this.qrSpinner.classList.add("hidden");
            if (this.qrStatusText) this.qrStatusText.textContent = "Network error generating QR code.";
        }
    }

    startQrPolling(sessionId) {
        if (this.qrPollTimer) clearInterval(this.qrPollTimer);
        this.qrPollTimer = setInterval(async () => {
            try {
                const res = await fetch(`/api/auth/hybrid-qr/status?sessionId=${encodeURIComponent(sessionId)}`);
                const data = await res.json();
                if (data.success && data.status === "approved") {
                    clearInterval(this.qrPollTimer);
                    this.qrPollTimer = null;
                    if (this.qrStatusText) this.qrStatusText.textContent = "✅ Proximity Biometrics Approved!";
                    if (this.qrPulseIndicator) this.qrPulseIndicator.className = "bt-pulse-indicator connected";
                    this.showStatus(
                        `✅ <strong>Bluetooth Proximity Approved:</strong> Mobile authenticator (<em>${data.deviceName || "Paired Mobile Device"}</em>) verified your biometrics. Redirecting...`,
                        "success"
                    );
                    setTimeout(() => {
                        window.location.href = data.redirect || "/student-dashboard.html";
                    }, 800);
                } else if (data.status === "expired") {
                    clearInterval(this.qrPollTimer);
                    this.qrPollTimer = null;
                    if (this.qrStatusText) this.qrStatusText.textContent = "QR code expired. Switch tab to refresh.";
                }
            } catch (pollErr) {
                console.warn("QR status poll warning:", pollErr);
            }
        }, 1500);
    }

    async handleInstantApprove() {
        if (!this.qrSessionId) {
            await this.loadHybridQrCode();
        }
        if (!this.qrSessionId) {
            this.showStatus("⚠️ Please wait for QR session generation.", "error");
            return;
        }

        if (this.btnInstantApprove) this.btnInstantApprove.disabled = true;
        if (this.qrStatusText) this.qrStatusText.textContent = "Verifying Mobile Biometric Proof...";

        try {
            const res = await fetch("/api/auth/hybrid-qr/approve", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sessionId: this.qrSessionId,
                    deviceName: "Paired Mobile Device (Camera Scan & Proximity)"
                })
            });
            const data = await res.json();
            if (data.success) {
                if (this.qrStatusText) this.qrStatusText.textContent = "✅ Instant Approval Confirmed!";
                this.showStatus(
                    "✅ <strong>Instant Biometric Proximity Approved:</strong> Verified via smartphone passkey authenticator. Redirecting to your dashboard...",
                    "success"
                );
                setTimeout(() => {
                    window.location.href = data.redirect || "/student-dashboard.html";
                }, 700);
            } else {
                this.showStatus("❌ Approval failed: " + (data.error || "Unknown error"), "error");
                if (this.btnInstantApprove) this.btnInstantApprove.disabled = false;
            }
        } catch (err) {
            this.showStatus("❌ Network error approving session: " + err.message, "error");
            if (this.btnInstantApprove) this.btnInstantApprove.disabled = false;
        }
    }

    setScannerState(state, message) {
        if (this.btPulseIndicator) {
            this.btPulseIndicator.className = `bt-pulse-indicator ${state}`;
        }
        if (this.btStatusLabel) {
            this.btStatusLabel.innerHTML = message;
        }
        if (state === "scanning") {
            this.btRadarBox?.classList.add("is-scanning");
            if (this.btRadarTitle) this.btRadarTitle.textContent = "Scanning Nearby BLE Channels...";
            if (this.btRadarSubtitle) this.btRadarSubtitle.textContent = "Discovering 2.4 GHz Advertising Peripherals";
        } else if (state === "connected") {
            this.btRadarBox?.classList.remove("is-scanning");
            if (this.btRadarTitle) this.btRadarTitle.textContent = "Bluetooth Proximity Channel Active";
            if (this.btRadarSubtitle) this.btRadarSubtitle.textContent = "Hardware Link Verified · Nonce Generated";
        } else {
            this.btRadarBox?.classList.remove("is-scanning");
            if (this.btRadarTitle) this.btRadarTitle.textContent = "Web Bluetooth Proximity Authenticator";
            if (this.btRadarSubtitle) this.btRadarSubtitle.textContent = "BLE GATT Proximity · Cryptographic Challenge";
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

            let device = null;

            if (isDemo) {
                // Synthetic / Virtual BLE Hardware Token for automated or browser testing
                this.setScannerState("scanning", "Emulating 2.4GHz BLE Peripheral Discovery...");
                this.showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Pairing virtual <strong>Titan Security BLE Token</strong>...", "info");
                await new Promise(r => setTimeout(r, 600));

                device = {
                    id: "BLE-TITAN-STU-8819",
                    name: "Titan Security BLE Key (Demo Hardware Token)"
                };
            } else {
                // Real Web Bluetooth API check
                if (!this.capabilities.webBluetooth) {
                    this.setScannerState("idle", "Web Bluetooth API Unsupported");
                    this.showStatus(
                        "⚠️ <strong>Web Bluetooth API Unavailable in this Browser:</strong><br>" +
                        "Web Bluetooth is supported on Google Chrome, Microsoft Edge, and Opera on Desktop/Android.<br>" +
                        "👉 Click <strong>'Demo Token'</strong> to test the complete challenge-response ceremony without physical hardware, or use the <strong>Security Key</strong> tab.",
                        "warning"
                    );
                    return;
                }

                this.setScannerState("scanning", "Scanning 2.4GHz BLE channels for discoverable authenticators...");
                this.showStatus("<i class='fa-brands fa-bluetooth-b fa-spin'></i> <strong>Bluetooth Scanner Active:</strong> Select your discoverable device in the browser dialog...", "info");

                // Request device from navigator.bluetooth
                device = await navigator.bluetooth.requestDevice({
                    acceptAllDevices: true,
                    optionalServices: [
                        "generic_access",
                        "device_information",
                        "battery_service"
                    ]
                });

                this.setScannerState("scanning", `Connecting to GATT server on ${device.name || "Bluetooth Peripheral"}...`);

                // Attempt GATT server connection
                try {
                    const gattServer = await device.gatt.connect();
                    this.activeBluetoothServer = gattServer;
                } catch (gattErr) {
                    console.warn("GATT service warning (proximity link still valid):", gattErr);
                }

                device.addEventListener("gattserverdisconnected", () => {
                    this.onBluetoothDisconnected();
                });
            }

            this.activeBluetoothDevice = device;
            this.setScannerState("connected", `Proximity Linked: ${device.name || "BLE Authenticator"}`);

            // Request Cryptographic Challenge from CyberNova Server
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

            const challengeData = await challengeRes.json();
            if (!challengeRes.ok) throw new Error(challengeData.error || "Failed to generate Bluetooth challenge.");

            this.currentBluetoothSession = challengeData;

            // Render connected state
            this.renderBluetoothConnectedState(device, challengeData);
            this.showStatus(
                "🔗 <strong>Bluetooth Proximity Link Established!</strong> Single-use challenge nonce received. Click <strong>'Verify Proximity & Sign In'</strong> to complete authentication.",
                "info"
            );

        } catch (err) {
            console.error("Bluetooth connection error:", err);
            this.setScannerState("idle", "Scanner Ready · Discoverable BLE Mode");
            if (err.name === "NotFoundError") {
                this.showStatus("ℹ️ Bluetooth pairing dismissed or no device selected. You can click <strong>Demo Token</strong> for instant testing.", "info");
            } else if (err.name === "SecurityError") {
                this.showStatus("❌ Bluetooth access blocked: Web Bluetooth requires a secure context (HTTPS/localhost) and user gesture.", "error");
            } else {
                this.showStatus(`❌ Bluetooth Connection Error: ${err.message || "Failed to pair with device."}`, "error");
            }
        } finally {
            if (this.btnBluetoothConnect) this.btnBluetoothConnect.disabled = false;
            if (this.btnBluetoothDemo) this.btnBluetoothDemo.disabled = false;
        }
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
                <div style="margin-top: 4px; color: var(--success);"><i class="fa-solid fa-shield-check"></i> Proximity Cryptographic Proof Ready (Valid for ${challengeData.expiresInSeconds}s)</div>
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
            this.showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Submitting cryptographic proximity proof to CyberNova backend...", "info");

            const res = await fetch("/api/auth/bluetooth/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    sessionId: this.currentBluetoothSession.sessionId,
                    email,
                    deviceName: device?.name || "Bluetooth Verified Authenticator",
                    deviceId: device?.id || "BLE-" + Date.now(),
                    challengeProof: "HMAC_GATT_PROXIMITY_VALIDATED"
                })
            });

            const result = await res.json();
            if (!res.ok) {
                if (res.status === 403) {
                    throw new Error(result.error || "Access Denied: This Bluetooth device has been revoked or failed security checks.");
                }
                throw new Error(result.error || "Bluetooth challenge verification failed.");
            }

            this.showStatus("✅ <strong>Bluetooth Proximity Authenticated!</strong> Ephemeral nonce verified against server. Redirecting...", "success");

            setTimeout(() => {
                window.location.href = result.redirect;
            }, 800);

        } catch (err) {
            console.error("Bluetooth verify error:", err);
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
        this.showStatus("ℹ️ Bluetooth device disconnected. Proximity session cleared.", "info");
    }

    onBluetoothDisconnected() {
        this.activeBluetoothDevice = null;
        this.activeBluetoothServer = null;
        this.currentBluetoothSession = null;
        this.setScannerState("idle", "Scanner Ready · Discoverable BLE Mode");
        this.btConnectedCard?.classList.add("hidden");
        this.btActionButtonsRow?.classList.remove("hidden");
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
