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

import { startAuthentication } from "https://esm.sh/@simplewebauthn/browser@14.0.0";

const loginBtn = document.getElementById("passkeyLogin");
const statusBox = document.getElementById("statusMessage");

function showStatus(text, type = "info") {
    if (!statusBox) return;
    statusBox.className = `status-box ${type}`;
    statusBox.innerHTML = text;
    statusBox.classList.remove("hidden");
}

if (loginBtn) {
    loginBtn.addEventListener("click", async (e) => {
        e.preventDefault();
        const email = document.getElementById("username")?.value.trim().toLowerCase();

        if (!email) {
            showStatus("⚠️ Please enter your email address.", "error");
            return;
        }

        try {
            loginBtn.disabled = true;
            showStatus("<i class='fa-solid fa-spinner fa-spin'></i> Requesting cryptographic challenge...", "info");

            // 1. Request authentication options
            const res = await fetch("/api/login/options", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email })
            });

            const options = await safeJson(res);
            if (!res.ok) throw new Error(options.error || "Failed to start passkey login.");

            showStatus("<i class='fa-solid fa-fingerprint'></i> Scan Fingerprint / Face ID or authenticate via Phone Bluetooth...", "info");

            // 2. Invoke WebAuthn Assertion
            const credential = await startAuthentication({ optionsJSON: options });

            showStatus("<i class='fa-solid fa-shield-halved'></i> Verifying cryptographic signature...", "info");

            // 3. Verify response on backend
            const verifyRes = await fetch("/api/login/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email,
                    response: credential
                })
            });

            const result = await safeJson(verifyRes);
            if (!verifyRes.ok) throw new Error(result.error || "Authentication failed.");

            showStatus("✅ <strong>Identity Verified!</strong> Redirecting to secure portal...", "success");

            setTimeout(() => {
                window.location.href = result.redirect;
            }, 1000);

        } catch (err) {
            console.error("Login error:", err);
            showStatus(`❌ ${err.message || "Passkey verification aborted."}`, "error");
        } finally {
            loginBtn.disabled = false;
        }
    });
}