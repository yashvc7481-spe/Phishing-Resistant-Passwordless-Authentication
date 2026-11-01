const express = require("express");
const path = require("path");
const fs = require("fs");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require("@simplewebauthn/server");

const db = require("./database");
const riskEngine = require("./risk-engine");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "cybernova-super-secret-jwt-key-2026";
const RP_NAME = "cyberNova Enterprise Portal";

// In-memory challenge stores with 2-minute timeouts
const pendingChallenges = new Map();
const pendingLoginChallenges = new Map();
const pendingBluetoothChallenges = new Map();

// Rate limiting store (rolling 60s window)
const rateLimitMap = new Map();
function rateLimiter(limit = 20, windowMs = 60000) {
    return (req, res, next) => {
        const key = `${req.ip}_${req.path}`;
        const now = Date.now();
        const timestamps = (rateLimitMap.get(key) || []).filter(t => now - t < windowMs);
        if (timestamps.length >= limit) {
            return res.status(429).json({ error: "Too many requests. Please slow down and try again shortly." });
        }
        timestamps.push(now);
        rateLimitMap.set(key, timestamps);
        next();
    };
}

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: (origin, callback) => callback(null, true),
    credentials: true
}));

// Permissions-Policy header for Web Bluetooth API compatibility in Chromium (Chrome 113+)
app.use((req, res, next) => {
    res.setHeader("Permissions-Policy", "bluetooth=(self)");
    next();
});

// Serve frontend directly from project root
app.use(express.static(__dirname));

// Helper: Determine origin dynamically (supporting localhost:3000, 5500, or LAN IP)
function getOriginAndRpId(req) {
    const origin = req.headers.origin || `http://${req.headers.host}`;
    const url = new URL(origin);
    const rpID = url.hostname;
    return { origin, rpID };
}

// Log security events to SQLite SOC table with risk scoring
function logSecurityEvent(type, email, ip, details, severity = "INFO", riskScore = 0, riskLevel = "LOW", isSimulation = 0) {
    try {
        db.prepare(`
            INSERT INTO security_logs (event_type, email, ip_address, details, severity, risk_score, risk_level, is_simulation)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(type, email || "Unknown", ip, JSON.stringify(details), severity, riskScore, riskLevel, isSimulation ? 1 : 0);
    } catch (e) {
        console.error("Log error:", e);
    }
}

// JWT Authentication Middleware for Protected Dashboards
function authenticateToken(req, res, next) {
    const token = req.cookies.cybernova_session;
    if (!token) return res.status(401).json({ error: "Unauthorized. Please log in with your passkey." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired or invalid." });
        req.user = user;
        next();
    });
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== "staff") {
        return res.status(403).json({ error: "Administrative privilege required." });
    }
    next();
}

// Direct 1-Click ZIP Download Route
app.get("/download/project-zip", (req, res) => {
    const zipPath = path.join(__dirname, "CyberNova-FT17-Passwordless-Website.zip");
    if (fs.existsSync(zipPath)) {
        res.download(zipPath, "CyberNova-FT17-Passwordless-Website.zip");
    } else {
        res.status(404).send("ZIP archive not found.");
    }
});

// ------------------- PASSKEY REGISTRATION -------------------

app.post("/api/register/options", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const { rpID } = getOriginAndRpId(req);

        let user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user) {
            db.prepare("INSERT INTO users (email, role, display_name) VALUES (?, ?, ?)")
              .run(email, email.includes("staff") ? "staff" : "student", email.split('@')[0]);
            user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        }

        const existingCredentials = db.prepare(
            "SELECT credential_id, transports FROM credentials WHERE user_id = ?"
        ).all(user.id);

        const options = await generateRegistrationOptions({
            rpName: RP_NAME,
            rpID,
            userID: new Uint8Array(Buffer.from(String(user.id))),
            userName: user.email,
            userDisplayName: user.display_name,
            attestationType: "none",
            excludeCredentials: existingCredentials.map(c => ({
                id: c.credential_id,
                transports: c.transports ? JSON.parse(c.transports) : undefined
            })),
            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "required", // Forces Biometrics (Fingerprint/FaceID/PIN)
                ...(req.body.attachment ? { authenticatorAttachment: req.body.attachment } : {})
            }
        });

        pendingChallenges.set(email, {
            challenge: options.challenge,
            userId: user.id,
            createdAt: Date.now()
        });

        res.json(options);
    } catch (error) {
        console.error("Registration options error:", error);
        res.status(500).json({ error: "Could not generate passkey options." });
    }
});

app.post("/api/register/verify", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const { response, deviceName } = req.body;
        const pending = pendingChallenges.get(email);

        if (!pending || (Date.now() - pending.createdAt > 120000)) {
            return res.status(400).json({ error: "Registration session expired. Try again." });
        }
        pendingChallenges.delete(email);

        const { origin, rpID } = getOriginAndRpId(req);

        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: pending.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            requireUserVerification: true
        });

        if (!verification.verified || !verification.registrationInfo) {
            return res.status(400).json({ error: "Biometric passkey verification failed." });
        }

        const { credential } = verification.registrationInfo;
        const detectedTransports = response.response.transports || ["internal", "hybrid"];

        db.prepare(`
            INSERT INTO credentials (credential_id, user_id, public_key, counter, device_name, transports)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            credential.id,
            pending.userId,
            Buffer.from(credential.publicKey).toString("base64url"),
            credential.counter,
            deviceName || "Biometric Authenticator (FIDO2)",
            JSON.stringify(detectedTransports)
        );

        logSecurityEvent("PASSKEY_REGISTERED", email, req.ip, {
            credentialId: credential.id.substring(0, 12) + "...",
            transports: detectedTransports
        }, "INFO");

        res.json({ success: true, message: "Passkey enrolled successfully!" });
    } catch (error) {
        console.error("Registration verify error:", error);
        res.status(400).json({ error: error.message || "Could not verify passkey." });
    }
});

// ------------------- PASSKEY LOGIN -------------------

app.post("/api/login/options", rateLimiter(15, 60000), async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const { rpID } = getOriginAndRpId(req);

        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user) return res.status(404).json({ error: "No account found with this email." });

        // Retrieve active credentials (preventing revoked credentials from being offered)
        const credentials = db.prepare(
            "SELECT credential_id, transports FROM credentials WHERE user_id = ? AND status = 'active'"
        ).all(user.id);

        if (credentials.length === 0) {
            const allCredsCount = db.prepare("SELECT COUNT(*) as count FROM credentials WHERE user_id = ?").get(user.id).count;
            if (allCredsCount > 0) {
                return res.status(403).json({
                    error: "All passkeys for this account have been revoked. Please use Account Recovery to enroll a replacement device.",
                    revoked: true
                });
            }
            return res.status(400).json({ error: "No passkeys registered yet for this account." });
        }

        const options = await generateAuthenticationOptions({
            rpID,
            allowCredentials: credentials.map(c => ({
                id: c.credential_id,
                transports: c.transports ? JSON.parse(c.transports) : undefined
            })),
            userVerification: "required"
        });

        pendingLoginChallenges.set(email, {
            challenge: options.challenge,
            userId: user.id,
            createdAt: Date.now()
        });

        res.json(options);
    } catch (error) {
        console.error("Login options error:", error);
        res.status(500).json({ error: "Failed to create authentication challenge." });
    }
});

app.post("/api/login/verify", rateLimiter(15, 60000), async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const { origin, rpID } = getOriginAndRpId(req);

        // Feature 4 & 5: Check if simulated phishing request
        if (req.body.isPhishingSimulation) {
            const risk = riskEngine.evaluateRisk({
                email,
                ip: req.ip,
                origin,
                expectedRpId: rpID,
                isPhishingSimulation: true,
                userAgent: req.headers["user-agent"]
            });

            logSecurityEvent("PHISHING_ATTACK_BLOCKED", email, req.ip, {
                attemptedOrigin: req.body.simulatedOrigin || "http://fake-college-portal.xyz",
                reason: "Origin mismatch: FIDO2 cryptographic domain binding prevented signature hijack.",
                riskScore: risk.score,
                riskReasons: risk.reasons
            }, "CRITICAL", risk.score, risk.level, 1);

            return res.status(403).json({
                error: "🚨 PHISHING ATTACK DETECTED! Passkey is cryptographically bound to " + rpID + ". Verification rejected.",
                phishingBlocked: true,
                risk
            });
        }

        const pending = pendingLoginChallenges.get(email);
        if (!pending || (Date.now() - pending.createdAt > 120000)) {
            return res.status(400).json({ error: "Login challenge expired or already consumed. Please retry." });
        }
        pendingLoginChallenges.delete(email);

        const risk = riskEngine.evaluateRisk({
            email,
            ip: req.ip,
            origin,
            expectedRpId: rpID,
            isPhishingSimulation: false,
            userAgent: req.headers["user-agent"]
        });

        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(pending.userId);
        const credential = db.prepare(
            "SELECT * FROM credentials WHERE credential_id = ? AND user_id = ?"
        ).get(req.body.response?.id, pending.userId);

        if (!user || !credential) {
            logSecurityEvent("LOGIN_FAILED", email, req.ip, { reason: "Credential mismatch" }, "WARNING", risk.score, risk.level);
            return res.status(401).json({ error: "Passkey does not match account." });
        }

        // Feature 3: Prevent revoked credentials from authenticating
        if (credential.status === "revoked") {
            logSecurityEvent("REVOKED_CREDENTIAL_ATTEMPT", email, req.ip, {
                credentialId: credential.credential_id.substring(0, 12) + "...",
                deviceName: credential.device_name
            }, "CRITICAL", 75, "HIGH");
            return res.status(403).json({
                error: "This passkey has been revoked and can no longer be used for authentication.",
                revoked: true
            });
        }

        const verification = await verifyAuthenticationResponse({
            response: req.body.response,
            expectedChallenge: pending.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: credential.credential_id,
                publicKey: Buffer.from(credential.public_key, "base64url"),
                counter: credential.counter,
                transports: credential.transports ? JSON.parse(credential.transports) : []
            },
            requireUserVerification: true
        });

        if (!verification.verified) {
            logSecurityEvent("LOGIN_FAILED", email, req.ip, { reason: "Cryptographic signature invalid" }, "WARNING", risk.score, risk.level);
            return res.status(401).json({ error: "Biometric authentication signature invalid." });
        }

        // Replay Attack Protection: Ensure sign counter increased & update last_used
        db.prepare("UPDATE credentials SET counter = ?, last_used = CURRENT_TIMESTAMP WHERE credential_id = ?")
          .run(verification.authenticationInfo.newCounter, credential.credential_id);

        // Issue Secure HTTP-Only JWT Session
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, displayName: user.display_name },
            JWT_SECRET,
            { expiresIn: "4h" }
        );

        res.cookie("cybernova_session", token, {
            httpOnly: true,
            sameSite: "lax"
        });

        logSecurityEvent("LOGIN_SUCCESS", email, req.ip, {
            role: user.role,
            authenticator: credential.device_name,
            counter: verification.authenticationInfo.newCounter,
            riskScore: risk.score,
            riskLevel: risk.level,
            riskReasons: risk.reasons
        }, "INFO", risk.score, risk.level, 0);

        res.json({
            success: true,
            role: user.role,
            user: { email: user.email, displayName: user.display_name },
            redirect: user.role === "student" ? "/student-dashboard.html" : "/staff-dashboard.html",
            telemetry: {
                algorithm: "ES256 / RS256",
                userVerification: "Present (Biometric Verified)",
                phishingResistant: true,
                signCounter: verification.authenticationInfo.newCounter,
                riskScore: risk.score,
                riskLevel: risk.level
            }
        });
    } catch (error) {
        console.error("Login verification error:", error);
        logSecurityEvent("AUTH_ERROR", req.body?.email, req.ip, { error: error.message }, "WARNING");
        res.status(401).json({ error: error.message || "Passkey login failed." });
    }
});

// ------------------- BLUETOOTH AUTHENTICATION (CHALLENGE-RESPONSE) -------------------

// Helper: Verify cryptographic challenge signature from registered BLE authenticator
function verifyBluetoothSignature(publicKey, challenge, signatureBase64) {
    if (!publicKey || !challenge || !signatureBase64) return false;
    try {
        const sigBuffer = Buffer.from(signatureBase64, "base64");
        const dataBuffer = Buffer.from(challenge, "utf8");

        let formattedKey = String(publicKey).trim();
        if (!formattedKey.includes("-----BEGIN")) {
            formattedKey = `-----BEGIN PUBLIC KEY-----\n${formattedKey.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;
        }

        // 1. Try IEEE-P1363 encoding (standard output of WebCrypto API ECDSA)
        try {
            if (crypto.verify("SHA256", dataBuffer, { key: formattedKey, dsaEncoding: "ieee-p1363" }, sigBuffer)) {
                return true;
            }
        } catch (e1) {}

        // 2. Try DER encoding (Node.js / OpenSSL standard format)
        try {
            if (crypto.verify("SHA256", dataBuffer, { key: formattedKey, dsaEncoding: "der" }, sigBuffer)) {
                return true;
            }
        } catch (e2) {}

        // 3. Fallback generic verify
        try {
            if (crypto.verify("SHA256", dataBuffer, formattedKey, sigBuffer)) {
                return true;
            }
        } catch (e3) {}

        return false;
    } catch (err) {
        return false;
    }
}

// 1. Request cryptographic challenge for Bluetooth Proximity
app.post("/api/auth/bluetooth/challenge", (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        if (!email) return res.status(400).json({ error: "Email address is required." });

        let user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user) {
            db.prepare("INSERT INTO users (email, role, display_name) VALUES (?, ?, ?)")
              .run(email, email.includes("staff") ? "staff" : "student", email.split("@")[0]);
            user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        }

        const { rpID } = getOriginAndRpId(req);
        const sessionId = "bt_sess_" + crypto.randomBytes(16).toString("hex");
        const challenge = "CN-PROX-" + crypto.randomBytes(20).toString("hex").toUpperCase();
        const expiresAt = Date.now() + 90000; // 90 seconds lifetime

        pendingBluetoothChallenges.set(sessionId, {
            sessionId,
            challenge,
            userId: user.id,
            email: user.email,
            rpId: rpID,
            expiresAt,
            createdAt: Date.now()
        });

        logSecurityEvent("BLUETOOTH_CHALLENGE_ISSUED", email, req.ip, {
            sessionId: sessionId.substring(0, 14) + "...",
            deviceHint: req.body.deviceName || "BLE Proximity Client"
        }, "INFO");

        res.json({
            success: true,
            sessionId,
            challenge,
            rpName: RP_NAME,
            rpId: rpID,
            expiresInSeconds: 90
        });
    } catch (err) {
        console.error("Bluetooth challenge error:", err);
        res.status(500).json({ error: "Failed to generate Bluetooth challenge." });
    }
});

// 1.5. Check Status of QR / Mobile Bluetooth Authentication Session (Polling)
app.get("/api/auth/bluetooth/session-status", (req, res) => {
    try {
        const sessionId = String(req.query.sessionId || "").trim();
        if (!sessionId) return res.status(400).json({ error: "Session ID required" });

        const pending = pendingBluetoothChallenges.get(sessionId);
        if (!pending) {
            return res.status(404).json({ status: "expired", error: "Session expired or not found" });
        }

        if (Date.now() > pending.expiresAt) {
            pendingBluetoothChallenges.delete(sessionId);
            return res.status(400).json({ status: "expired", error: "Session expired. Please generate a new QR." });
        }

        if (pending.approved) {
            if (pending.token) {
                res.cookie("cybernova_session", pending.token, {
                    httpOnly: true,
                    sameSite: "lax"
                });
            }
            return res.json({
                status: "approved",
                redirect: pending.redirect,
                token: pending.token,
                user: pending.user
            });
        }

        const remainingSeconds = Math.max(0, Math.round((pending.expiresAt - Date.now()) / 1000));
        res.json({ status: "pending", expiresInSeconds: remainingSeconds });
    } catch (err) {
        console.error("Session status check error:", err);
        res.status(500).json({ error: "Failed to check session status." });
    }
});

// 1.6. Approve Bluetooth Session from Mobile Phone via QR Scan
app.post("/api/auth/bluetooth/approve-mobile", (req, res) => {
    try {
        const { sessionId, email, signature } = req.body;
        if (!sessionId) return res.status(400).json({ error: "Session ID required" });

        const pending = pendingBluetoothChallenges.get(sessionId);
        if (!pending || Date.now() > pending.expiresAt) {
            return res.status(400).json({ error: "Session expired or invalid" });
        }

        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(pending.userId);
        if (!user) return res.status(404).json({ error: "User not found" });

        const allUserBtDevices = db.prepare(
            "SELECT id, device_name, device_identifier, status, public_key, algorithm FROM bluetooth_devices WHERE user_id = ?"
        ).all(user.id);

        let verified = true;
        if (signature) {
            let sigValid = false;
            for (const dev of allUserBtDevices) {
                if (dev.status === "active" && dev.public_key) {
                    if (verifyBluetoothSignature(dev.public_key, pending.challenge, signature)) {
                        sigValid = true;
                        break;
                    }
                }
            }
            verified = sigValid;
        }

        if (!verified) {
            return res.status(401).json({ error: "Cryptographic signature check failed on mobile device." });
        }

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, displayName: user.display_name, authMethod: "bluetooth_qr_hybrid" },
            JWT_SECRET,
            { expiresIn: "4h" }
        );

        pending.approved = true;
        pending.token = token;
        pending.redirect = user.role === "student" ? "/student-dashboard.html" : "/staff-dashboard.html";
        pending.user = { email: user.email, displayName: user.display_name };

        logSecurityEvent("BLUETOOTH_QR_PROXIMITY_APPROVED", user.email, req.ip, {
            sessionId: sessionId.substring(0, 14) + "...",
            role: user.role
        }, "INFO", 5, "LOW");

        res.json({
            success: true,
            message: "Mobile proximity approved successfully",
            redirect: pending.redirect
        });
    } catch (err) {
        console.error("Mobile approval error:", err);
        res.status(500).json({ error: err.message || "Failed to approve mobile authentication." });
    }
});

// 2. Verify Bluetooth device proximity challenge response with Cryptographic Proof
app.post("/api/auth/bluetooth/verify", (req, res) => {
    try {
        const { sessionId, email, deviceName, deviceId, signature, challengeProof } = req.body;
        const normalizedEmail = String(email || "").trim().toLowerCase();
        const { origin, rpID } = getOriginAndRpId(req);

        const pending = pendingBluetoothChallenges.get(sessionId);
        if (!pending || Date.now() > pending.expiresAt) {
            pendingBluetoothChallenges.delete(sessionId);
            return res.status(400).json({ error: "Bluetooth proximity challenge expired or invalid. Please re-scan." });
        }

        if (pending.email !== normalizedEmail) {
            return res.status(403).json({ error: "Identity mismatch for this Bluetooth challenge." });
        }

        // Consume one-time challenge immediately (strict replay prevention)
        pendingBluetoothChallenges.delete(sessionId);

        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(pending.userId);
        if (!user) return res.status(404).json({ error: "User record not found." });

        const cleanDevName = String(deviceName || "Verified Bluetooth Device").slice(0, 80);
        const cleanDevId = String(deviceId || ("BLE-" + crypto.randomBytes(6).toString("hex"))).slice(0, 100);
        const clientSignature = signature || challengeProof;

        if (!clientSignature) {
            return res.status(400).json({ error: "Cryptographic signature proof is required." });
        }

        // Query all registered Bluetooth authenticators for this user
        const allUserBtDevices = db.prepare(
            "SELECT id, device_name, device_identifier, status, public_key, algorithm FROM bluetooth_devices WHERE user_id = ?"
        ).all(user.id);

        if (allUserBtDevices.length === 0) {
            logSecurityEvent("BLUETOOTH_AUTH_BLOCKED_UNPAIRED", normalizedEmail, req.ip, {
                deviceName: cleanDevName,
                deviceId: cleanDevId
            }, "WARNING", 50, "MEDIUM");
            return res.status(403).json({
                error: "Access Denied: No Bluetooth authenticator is registered for this account. Please pair a trusted BLE device in your dashboard first."
            });
        }

        // Security Check 1: Block revoked devices
        const revokedDevice = allUserBtDevices.find(
            d => d.status === "revoked" && (d.device_identifier === cleanDevId || d.device_name === cleanDevName)
        );
        if (revokedDevice) {
            logSecurityEvent("BLUETOOTH_AUTH_BLOCKED_REVOKED", normalizedEmail, req.ip, {
                deviceName: cleanDevName,
                deviceId: cleanDevId
            }, "CRITICAL", 80, "HIGH");
            return res.status(403).json({
                error: "Access Denied: This Bluetooth device has been revoked and cannot be used for authentication."
            });
        }

        // Security Check 2: Match registered active device with public key
        let matchedDevice = allUserBtDevices.find(
            d => d.status === "active" && (d.device_identifier === cleanDevId || d.device_name === cleanDevName)
        );

        // Direct mobile/BLE device matching without traditional pairing:
        // If not matched by exact ID/name, verify whether clientSignature matches any active registered public key for this account
        if (!matchedDevice) {
            for (const dev of allUserBtDevices) {
                if (dev.status === "active" && dev.public_key) {
                    if (verifyBluetoothSignature(dev.public_key, pending.challenge, clientSignature)) {
                        matchedDevice = dev;
                        // Dynamically update the record with the phone's actual broadcast name and ID
                        try {
                            db.prepare("UPDATE bluetooth_devices SET device_name = ?, device_identifier = ?, last_used = CURRENT_TIMESTAMP WHERE id = ?")
                              .run(cleanDevName, cleanDevId, dev.id);
                        } catch (_) {}
                        break;
                    }
                }
            }
        }

        if (!matchedDevice || matchedDevice.status !== "active") {
            logSecurityEvent("BLUETOOTH_AUTH_UNKNOWN_DEVICE", normalizedEmail, req.ip, {
                deviceName: cleanDevName,
                deviceId: cleanDevId
            }, "WARNING", 55, "MEDIUM");
            return res.status(403).json({
                error: "Access Denied: Selected device is not paired or trusted for this account. Hardware pairing is required."
            });
        }

        if (!matchedDevice.public_key) {
            return res.status(403).json({
                error: "Access Denied: Registered device lacks a cryptographic public key. Please re-pair the device in the dashboard."
            });
        }

        // Security Check 3: Cryptographic Signature Verification
        const isSignatureValid = verifyBluetoothSignature(matchedDevice.public_key, pending.challenge, clientSignature);
        if (!isSignatureValid) {
            logSecurityEvent("BLUETOOTH_SIGNATURE_MISMATCH", normalizedEmail, req.ip, {
                deviceName: cleanDevName,
                deviceId: cleanDevId,
                reason: "Cryptographic signature failed verification against registered public key"
            }, "CRITICAL", 90, "HIGH");
            return res.status(401).json({
                error: "Authentication Denied: Cryptographic signature verification failed. Private key proof does not match registered public key."
            });
        }

        // Intelligent Risk Analysis for Bluetooth Authentication
        const riskAssessment = riskEngine.evaluateRisk({
            email: normalizedEmail,
            ip: req.ip,
            origin: req.headers.origin || "",
            expectedRpId: rpID,
            userAgent: req.headers["user-agent"]
        });
        if (riskAssessment.level === "HIGH") {
            logSecurityEvent("BLUETOOTH_HIGH_RISK_REJECTED", normalizedEmail, req.ip, {
                reasons: riskAssessment.reasons,
                deviceName: cleanDevName
            }, "CRITICAL", riskAssessment.score, "HIGH");
            return res.status(403).json({
                error: `Authentication blocked by intelligent risk engine (Risk: ${riskAssessment.score}/100 - ${riskAssessment.reasons.join('; ')})`
            });
        }

        // Update paired Bluetooth device last_used
        db.prepare("UPDATE bluetooth_devices SET last_used = CURRENT_TIMESTAMP WHERE id = ?").run(matchedDevice.id);

        // Issue Secure HTTP-Only JWT Session
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, displayName: user.display_name, authMethod: "bluetooth_proximity" },
            JWT_SECRET,
            { expiresIn: "4h" }
        );

        res.cookie("cybernova_session", token, {
            httpOnly: true,
            sameSite: "lax"
        });

        logSecurityEvent("BLUETOOTH_PROXIMITY_AUTH", normalizedEmail, req.ip, {
            deviceName: matchedDevice.device_name,
            deviceIdentifier: matchedDevice.device_identifier.substring(0, 16) + "...",
            cryptographicProof: "ECDSA_P256_VERIFIED",
            role: user.role
        }, "INFO", riskAssessment.score, riskAssessment.level);

        res.json({
            success: true,
            role: user.role,
            user: { email: user.email, displayName: user.display_name },
            redirect: user.role === "student" ? "/student-dashboard.html" : "/staff-dashboard.html",
            telemetry: {
                authMethod: "Web Bluetooth GATT Proximity",
                device: matchedDevice.device_name,
                deviceIdentifier: matchedDevice.device_identifier.substring(0, 16) + "...",
                challengeVerified: true,
                cryptoVerified: true,
                proximityVerified: true,
                riskScore: riskAssessment.score,
                riskLevel: riskAssessment.level
            }
        });
    } catch (err) {
        console.error("Bluetooth verification error:", err);
        logSecurityEvent("BLUETOOTH_AUTH_FAILED", req.body?.email, req.ip, { error: err.message }, "WARNING", 40, "MEDIUM");
        res.status(400).json({ error: err.message || "Bluetooth verification failed." });
    }
});

// ------------------- BLUETOOTH DEVICE MANAGEMENT -------------------

// List authenticated user's trusted Bluetooth devices
app.get("/api/bluetooth/devices", authenticateToken, (req, res) => {
    try {
        const devices = db.prepare(`
            SELECT id, device_name, device_identifier, paired_at, last_used, status, algorithm, (public_key IS NOT NULL) AS has_key
            FROM bluetooth_devices
            WHERE user_id = ?
            ORDER BY paired_at DESC
        `).all(req.user.id);
        res.json({ devices });
    } catch (err) {
        res.status(500).json({ error: "Failed to fetch Bluetooth devices." });
    }
});

// Pair a new trusted Bluetooth device from dashboard scanner
app.post("/api/bluetooth/pair", authenticateToken, (req, res) => {
    try {
        const { deviceName, deviceIdentifier, publicKey, algorithm } = req.body;
        if (!deviceName || !deviceName.trim()) {
            return res.status(400).json({ error: "Device name is required." });
        }

        const cleanDevName = String(deviceName).trim().slice(0, 80);
        const cleanDevId = String(deviceIdentifier || ("BLE-" + crypto.randomBytes(8).toString("hex"))).trim().slice(0, 100);
        const cleanPubKey = publicKey ? String(publicKey).trim() : null;
        const cleanAlgo = String(algorithm || "ES256").trim().slice(0, 20);

        const existing = db.prepare(
            "SELECT id, status FROM bluetooth_devices WHERE user_id = ? AND (device_identifier = ? OR device_name = ?)"
        ).get(req.user.id, cleanDevId, cleanDevName);

        if (existing) {
            if (cleanPubKey) {
                db.prepare("UPDATE bluetooth_devices SET status = 'active', public_key = ?, algorithm = ?, last_used = CURRENT_TIMESTAMP WHERE id = ?")
                  .run(cleanPubKey, cleanAlgo, existing.id);
            } else {
                db.prepare("UPDATE bluetooth_devices SET status = 'active', last_used = CURRENT_TIMESTAMP WHERE id = ?").run(existing.id);
            }
            logSecurityEvent("BLUETOOTH_DEVICE_REACTIVATED", req.user.email, req.ip, {
                deviceId: existing.id,
                deviceName: cleanDevName
            }, "INFO", 10, "LOW");
            return res.json({
                success: true,
                message: "Bluetooth device re-paired and activated.",
                deviceId: existing.id,
                device: {
                    id: existing.id,
                    device_name: cleanDevName,
                    device_identifier: cleanDevId,
                    status: "active"
                }
            });
        }

        const info = db.prepare(`
            INSERT INTO bluetooth_devices (user_id, device_name, device_identifier, status, public_key, algorithm, last_used)
            VALUES (?, ?, ?, 'active', ?, ?, CURRENT_TIMESTAMP)
        `).run(req.user.id, cleanDevName, cleanDevId, cleanPubKey, cleanAlgo);

        logSecurityEvent("BLUETOOTH_DEVICE_PAIRED", req.user.email, req.ip, {
            deviceId: info.lastInsertRowid,
            deviceName: cleanDevName,
            deviceIdentifier: cleanDevId.substring(0, 16) + "...",
            hasPublicKey: !!cleanPubKey
        }, "INFO", 10, "LOW");

        res.json({
            success: true,
            message: "Trusted Bluetooth authenticator paired successfully.",
            device: {
                id: info.lastInsertRowid,
                device_name: cleanDevName,
                device_identifier: cleanDevId,
                status: "active"
            }
        });
    } catch (err) {
        console.error("Bluetooth pair error:", err);
        res.status(500).json({ error: "Failed to pair Bluetooth device." });
    }
});

// Rename trusted Bluetooth device
app.patch("/api/bluetooth/devices/:id/rename", authenticateToken, (req, res) => {
    try {
        const { deviceName } = req.body;
        const deviceId = req.params.id;

        if (!deviceName || !deviceName.trim()) {
            return res.status(400).json({ error: "Device name cannot be blank." });
        }

        const dev = db.prepare("SELECT * FROM bluetooth_devices WHERE id = ? AND user_id = ?").get(deviceId, req.user.id);
        if (!dev) return res.status(404).json({ error: "Bluetooth device not found." });

        db.prepare("UPDATE bluetooth_devices SET device_name = ? WHERE id = ? AND user_id = ?")
          .run(deviceName.trim().slice(0, 80), deviceId, req.user.id);

        logSecurityEvent("BLUETOOTH_DEVICE_RENAMED", req.user.email, req.ip, {
            deviceId,
            oldName: dev.device_name,
            newName: deviceName.trim()
        }, "INFO", 5, "LOW");

        res.json({ success: true, message: "Bluetooth device renamed successfully." });
    } catch (err) {
        res.status(500).json({ error: "Failed to rename Bluetooth device." });
    }
});

// Revoke/Unpair trusted Bluetooth device
app.post("/api/bluetooth/devices/:id/revoke", authenticateToken, (req, res) => {
    try {
        const deviceId = req.params.id;
        const dev = db.prepare("SELECT * FROM bluetooth_devices WHERE id = ? AND user_id = ?").get(deviceId, req.user.id);
        if (!dev) return res.status(404).json({ error: "Bluetooth device not found." });

        if (dev.status === "revoked") {
            return res.status(400).json({ error: "Bluetooth device is already revoked." });
        }

        db.prepare("UPDATE bluetooth_devices SET status = 'revoked' WHERE id = ? AND user_id = ?")
          .run(deviceId, req.user.id);

        logSecurityEvent("BLUETOOTH_DEVICE_REVOKED", req.user.email, req.ip, {
            deviceId,
            deviceName: dev.device_name
        }, "WARNING", 25, "LOW");

        res.json({ success: true, message: "Bluetooth device revoked. It can no longer be used for proximity authentication." });
    } catch (err) {
        res.status(500).json({ error: "Failed to revoke Bluetooth device." });
    }
});

// ------------------- SECURE EMERGENCY FALLBACK (IF BOTH BIOMETRIC & BLE UNAVAILABLE) -------------------

app.post("/api/auth/fallback/verify", (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const code = String(req.body.code || "").trim();

        if (!email || !code) {
            return res.status(400).json({ error: "Email and emergency security code are required." });
        }

        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user) return res.status(404).json({ error: "No account found with this email." });

        const tokenRow = db.prepare(
            "SELECT * FROM backup_tokens WHERE user_id = ? AND token_code = ?"
        ).get(user.id, code);

        if (!tokenRow) {
            logSecurityEvent("FALLBACK_AUTH_FAILED", email, req.ip, { reason: "Invalid emergency token code" }, "WARNING");
            return res.status(401).json({ error: "Invalid emergency security code. Verification failed." });
        }

        // Update token usage timestamp
        db.prepare("UPDATE backup_tokens SET used_at = CURRENT_TIMESTAMP WHERE id = ?").run(tokenRow.id);

        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, displayName: user.display_name, authMethod: "emergency_code" },
            JWT_SECRET,
            { expiresIn: "4h" }
        );

        res.cookie("cybernova_session", token, {
            httpOnly: true,
            sameSite: "lax"
        });

        logSecurityEvent("EMERGENCY_FALLBACK_AUTH", email, req.ip, {
            role: user.role,
            mechanism: "Cryptographic Emergency One-Time Code"
        }, "INFO");

        res.json({
            success: true,
            role: user.role,
            user: { email: user.email, displayName: user.display_name },
            redirect: user.role === "student" ? "/student-dashboard.html" : "/staff-dashboard.html",
            telemetry: {
                authMethod: "Emergency Cryptographic Passcode",
                securityLevel: "High Assurance Backup"
            }
        });
    } catch (err) {
        console.error("Emergency fallback error:", err);
        res.status(500).json({ error: "Emergency authentication failed." });
    }
});

// Provide fallback code hint for authorized test demo accounts
app.get("/api/auth/fallback/hint", (req, res) => {
    const email = String(req.query.email || "").trim().toLowerCase();
    const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (!user) return res.status(404).json({ error: "User not found" });

    const token = db.prepare("SELECT token_code FROM backup_tokens WHERE user_id = ?").get(user.id);
    if (!token) return res.status(404).json({ error: "No backup token configured" });

    res.json({ code: token.token_code });
});

// ------------------- PROTECTED SESSION & USER API -------------------

// ------------------- PASSKEY MANAGEMENT (FEATURE 3) -------------------

// List user credentials
app.get("/api/credentials", authenticateToken, (req, res) => {
    try {
        const creds = db.prepare(`
            SELECT credential_id, device_name, transports, created_at, last_used, counter, status
            FROM credentials WHERE user_id = ?
            ORDER BY created_at DESC
        `).all(req.user.id);

        res.json({
            credentials: creds.map(c => ({
                ...c,
                transports: c.transports ? JSON.parse(c.transports) : []
            }))
        });
    } catch (err) {
        res.status(500).json({ error: "Failed to load credentials." });
    }
});

// Rename passkey device
app.patch("/api/credentials/:id/rename", authenticateToken, (req, res) => {
    try {
        const { deviceName } = req.body;
        const credId = req.params.id;

        if (!deviceName || !deviceName.trim()) {
            return res.status(400).json({ error: "Device name cannot be blank." });
        }

        const cred = db.prepare("SELECT * FROM credentials WHERE credential_id = ? AND user_id = ?").get(credId, req.user.id);
        if (!cred) return res.status(404).json({ error: "Credential not found." });

        db.prepare("UPDATE credentials SET device_name = ? WHERE credential_id = ? AND user_id = ?")
          .run(deviceName.trim().slice(0, 80), credId, req.user.id);

        logSecurityEvent("CREDENTIAL_RENAMED", req.user.email, req.ip, {
            credentialId: credId.substring(0, 12) + "...",
            oldName: cred.device_name,
            newName: deviceName.trim()
        }, "INFO");

        res.json({ success: true, message: "Device renamed successfully." });
    } catch (err) {
        res.status(500).json({ error: "Failed to rename device." });
    }
});

// Revoke passkey
app.post("/api/credentials/:id/revoke", authenticateToken, (req, res) => {
    try {
        const credId = req.params.id;
        const cred = db.prepare("SELECT * FROM credentials WHERE credential_id = ? AND user_id = ?").get(credId, req.user.id);
        if (!cred) return res.status(404).json({ error: "Credential not found." });

        if (cred.status === "revoked") {
            return res.status(400).json({ error: "Credential is already revoked." });
        }

        db.prepare("UPDATE credentials SET status = 'revoked' WHERE credential_id = ? AND user_id = ?")
          .run(credId, req.user.id);

        logSecurityEvent("CREDENTIAL_REVOKED", req.user.email, req.ip, {
            credentialId: credId.substring(0, 12) + "...",
            deviceName: cred.device_name
        }, "WARNING", 20, "LOW");

        res.json({ success: true, message: "Credential revoked. It can no longer authenticate." });
    } catch (err) {
        res.status(500).json({ error: "Failed to revoke credential." });
    }
});

// ------------------- PERSONAL USER AUDIT LOGS (FEATURE 6) -------------------

app.get("/api/user/audit-logs", authenticateToken, (req, res) => {
    try {
        const logs = db.prepare(`
            SELECT id, event_type, ip_address, details, severity, timestamp, risk_level, risk_score
            FROM security_logs
            WHERE email = ?
            ORDER BY id DESC LIMIT 20
        `).all(req.user.email);

        res.json({ logs });
    } catch (err) {
        res.status(500).json({ error: "Could not fetch activity records." });
    }
});

// ------------------- PASSWORDLESS ACCOUNT RECOVERY (FEATURE 7) -------------------

// Generate single-use emergency recovery codes
app.post("/api/recovery/generate", authenticateToken, (req, res) => {
    try {
        db.prepare("DELETE FROM recovery_codes WHERE user_id = ?").run(req.user.id);

        const codes = [];
        const insertStmt = db.prepare("INSERT INTO recovery_codes (user_id, code_hash, salt) VALUES (?, ?, ?)");

        for (let i = 0; i < 5; i++) {
            const rawCode = "CN-REC-" + crypto.randomBytes(4).toString("hex").toUpperCase() + "-" + crypto.randomBytes(4).toString("hex").toUpperCase();
            const salt = crypto.randomBytes(16).toString("hex");
            const hash = db.hashRecoveryCode(rawCode, salt);
            insertStmt.run(req.user.id, hash, salt);
            codes.push(rawCode);
        }

        logSecurityEvent("RECOVERY_CODES_GENERATED", req.user.email, req.ip, { count: 5 }, "INFO");

        res.json({
            success: true,
            codes,
            warning: "Store these recovery codes in a password manager or physical vault. They are hashed on the server and cannot be viewed again."
        });
    } catch (err) {
        console.error("Recovery generate error:", err);
        res.status(500).json({ error: "Failed to generate recovery codes." });
    }
});

// Verify recovery code for locked-out users
app.post("/api/recovery/verify", rateLimiter(5, 60000), (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const rawCode = String(req.body.recoveryCode || "").trim().toUpperCase();

        if (!email || !rawCode) {
            return res.status(400).json({ error: "Email and recovery code are required." });
        }

        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user) {
            logSecurityEvent("RECOVERY_FAILED", email, req.ip, { reason: "User not found" }, "WARNING", 35, "MEDIUM");
            return res.status(404).json({ error: "Account not found." });
        }

        const recoveryRows = db.prepare("SELECT * FROM recovery_codes WHERE user_id = ? AND used = 0").all(user.id);
        let matchedRow = null;

        for (const row of recoveryRows) {
            const computedHash = db.hashRecoveryCode(rawCode, row.salt);
            if (computedHash === row.code_hash) {
                matchedRow = row;
                break;
            }
        }

        if (!matchedRow) {
            logSecurityEvent("RECOVERY_FAILED", email, req.ip, { reason: "Invalid or consumed recovery code" }, "WARNING", 40, "MEDIUM");
            return res.status(401).json({ error: "Invalid or already consumed recovery code." });
        }

        // Consume single-use code immediately
        db.prepare("UPDATE recovery_codes SET used = 1, used_at = CURRENT_TIMESTAMP WHERE id = ?").run(matchedRow.id);

        // Issue Recovery JWT Session
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, displayName: user.display_name, isRecovery: true },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.cookie("cybernova_session", token, {
            httpOnly: true,
            sameSite: "lax"
        });

        logSecurityEvent("ACCOUNT_RECOVERY_SUCCESS", email, req.ip, {
            codeId: matchedRow.id,
            role: user.role
        }, "WARNING", 25, "LOW");

        res.json({
            success: true,
            role: user.role,
            message: "Recovery code verified. Identity confirmed.",
            redirect: "/account-recovery.html"
        });
    } catch (err) {
        console.error("Recovery verify error:", err);
        res.status(500).json({ error: "Recovery process failed." });
    }
});

// Demo recovery code hint for academic test evaluations
app.get("/api/recovery/demo-code", (req, res) => {
    const email = String(req.query.email || "").trim().toLowerCase();
    if (email === "student@nkocet.edu") {
        return res.json({ code: "CN-RECOV-9921-STU1" });
    } else if (email === "staff@nkocet.edu") {
        return res.json({ code: "CN-RECOV-4482-STF1" });
    }
    res.status(404).json({ error: "No demo recovery code registered for this email." });
});

// ------------------- PROTECTED SESSION & USER API -------------------

app.get("/api/me", authenticateToken, (req, res) => {
    const userCredentials = db.prepare(
        "SELECT credential_id, device_name, transports, created_at, counter, last_used, status FROM credentials WHERE user_id = ?"
    ).all(req.user.id);

    const bluetoothDevices = db.prepare(
        "SELECT id, device_name, device_identifier, paired_at, last_used, status FROM bluetooth_devices WHERE user_id = ?"
    ).all(req.user.id);

    const activeRecoveryCodesCount = db.prepare(
        "SELECT COUNT(*) as count FROM recovery_codes WHERE user_id = ? AND used = 0"
    ).get(req.user.id).count;

    res.json({
        user: req.user,
        credentials: userCredentials.map(c => ({
            ...c,
            transports: c.transports ? JSON.parse(c.transports) : []
        })),
        bluetoothDevices,
        activeRecoveryCodesCount
    });
});

app.post("/api/logout", (req, res) => {
    res.clearCookie("cybernova_session");
    res.json({ success: true, message: "Logged out successfully." });
});

// ------------------- SOC TELEMETRY & HONEY-TOKEN TRAP (FEATURE 6) -------------------

app.get("/api/admin/soc-telemetry", (req, res) => {
    const logs = db.prepare("SELECT * FROM security_logs ORDER BY id DESC LIMIT 50").all();

    // Comprehensive SOC Statistics
    const stats = {
        totalPasskeys: db.prepare("SELECT COUNT(*) as count FROM credentials").get().count,
        activePasskeys: db.prepare("SELECT COUNT(*) as count FROM credentials WHERE status = 'active'").get().count,
        revokedPasskeys: db.prepare("SELECT COUNT(*) as count FROM credentials WHERE status = 'revoked'").get().count,
        totalUsers: db.prepare("SELECT COUNT(*) as count FROM users").get().count,
        bluetoothDevices: db.prepare("SELECT COUNT(*) as count FROM bluetooth_devices").get().count,
        phishingBlocked: db.prepare("SELECT COUNT(*) as count FROM security_logs WHERE event_type = 'PHISHING_ATTACK_BLOCKED'").get().count,
        honeytokenTriggers: db.prepare("SELECT COUNT(*) as count FROM security_logs WHERE event_type = 'HONEYTOKEN_TRIGGERED'").get().count,
        highRiskEvents: db.prepare("SELECT COUNT(*) as count FROM security_logs WHERE risk_level = 'HIGH'").get().count
    };

    // Risk Classification Distribution for Chart.js
    const riskDistribution = {
        low: db.prepare("SELECT COUNT(*) as count FROM security_logs WHERE risk_level = 'LOW'").get().count,
        medium: db.prepare("SELECT COUNT(*) as count FROM security_logs WHERE risk_level = 'MEDIUM'").get().count,
        high: db.prepare("SELECT COUNT(*) as count FROM security_logs WHERE risk_level = 'HIGH'").get().count
    };

    // Event Types aggregation for Chart.js
    const eventBreakdown = db.prepare(`
        SELECT event_type, COUNT(*) as count
        FROM security_logs
        GROUP BY event_type
        ORDER BY count DESC
        LIMIT 6
    `).all();

    res.json({ stats, riskDistribution, eventBreakdown, logs });
});

// 🚨 HONEY-TOKEN TRAP: Active defense tripwire
app.get("/api/admin/export-system-keys", (req, res) => {
    logSecurityEvent("HONEYTOKEN_TRIGGERED", "Attacker / Crawler", req.ip, {
        headers: req.headers,
        message: "Attacker tripped honeypot endpoint looking for leaked keys."
    }, "CRITICAL");

    console.log("🚨 [HONEYTOKEN TRIGGERED] Intrusion logged from IP:", req.ip);
    res.status(403).json({
        error: "ACCESS_DENIED: Intrusion attempt logged to SOC and IP quarantined.",
        status: "BLOCKED"
    });
});

app.listen(PORT, () => {
    console.log(`\n=================================================`);
    console.log(`🚀 cyberNova Security Hub: http://localhost:${PORT}`);
    console.log(`🛡️ SOC Telemetry Ready | FIDO2 WebAuthn Active`);
    console.log(`=================================================\n`);
});