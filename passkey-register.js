async function safeJson(res) {
    const text = await res.text();
    try {
        return JSON.parse(text);
    } catch {
        if (!res.ok) {
            throw new Error(`Backend service is offline or unreachable (HTTP ${res.status}). Ensure the Render backend is running.`);
        }
        throw new Error(text.length > 120 ? "Invalid server response." : text);
    }
}

import { startRegistration } from "https://esm.sh/@simplewebauthn/browser@14.0.0";

const registerBtn = document.getElementById("registerPasskey");
const statusBox = document.getElementById("statusMessage");

function showStatus(text, type = "info") {
    if (!statusBox) return;
    statusBox.className = `status-box ${type}`;
    statusBox.innerHTML = text;
    statusBox.classList.remove("hidden");
}

if (registerBtn) {
    registerBtn.addEventListener("click", async () => {
        const email = document.getElementById("username")?.value.trim().toLowerCase();
        if (!email) {
            showStatus("⚠️ Please enter your email address first.", "error");
            return;
        }

        try {
            registerBtn.disabled = true;
            showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Preparing biometric enrollment challenge...", "info");

            // 1. Fetch registration options from server
            const res = await fetch("/api/register/options", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email })
            });

            const options = await safeJson(res);
            if (!res.ok) throw new Error(options.error || "Failed to initialize registration.");

            showStatus("<i class='fa-solid fa-fingerprint'></i> Touch your sensor, scan Face ID, or pair phone via QR...", "info");

            // 2. Invoke WebAuthn API on browser
            const credential = await startRegistration({ optionsJSON: options });

            // 3. Prompt user for device nickname (e.g. 'Anush MacBook' or 'iPhone 15 Pro')
            const deviceName = prompt("Give this passkey a nickname (e.g. 'My Laptop TouchID' or 'iPhone FaceID'):", "Primary Biometric Token") || "Primary Authenticator";

            showStatus("<i class='fa-solid fa-lock'></i> Cryptographically verifying attestation on server...", "info");

            // 4. Send credential to backend for verification and storage
            const verifyRes = await fetch("/api/register/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email,
                    response: credential,
                    deviceName
                })
            });

            const result = await safeJson(verifyRes);
            if (!verifyRes.ok) throw new Error(result.error || "Enrollment failed.");

            showStatus("✅ <strong>Success!</strong> Passkey securely enrolled. You can now log in instantly.", "success");
        } catch (err) {
            console.error("Enrollment error:", err);
            showStatus(`❌ ${err.message || "Registration cancelled."}`, "error");
        } finally {
            registerBtn.disabled = false;
        }
    });
}