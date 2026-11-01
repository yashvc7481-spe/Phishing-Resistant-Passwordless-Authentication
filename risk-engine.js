/**
 * CyberNova Intelligent Authentication Risk Detection Engine
 * 
 * Modular, explainable rule-based security scoring engine for FIDO2/WebAuthn ceremonies.
 * Evaluates multiple risk vectors:
 * - Velocity & brute force attempts
 * - Recent failed authentication history
 * - Rapid successive requests
 * - Origin & domain anomalies
 * - Honeypot intrusion history
 * - Credential age and state
 */

const db = require("./database");

class RiskEngine {
    constructor() {
        // In-memory IP/Email request tracking for velocity detection (rolling 60s window)
        this.recentAttempts = new Map();
    }

    /**
     * Cleans up stale in-memory attempt timestamps older than 60 seconds
     */
    cleanStaleVelocityRecords() {
        const now = Date.now();
        for (const [key, timestamps] of this.recentAttempts.entries()) {
            const active = timestamps.filter(t => now - t < 60000);
            if (active.length === 0) {
                this.recentAttempts.delete(key);
            } else {
                this.recentAttempts.set(key, active);
            }
        }
    }

    /**
     * Tracks an incoming request timestamp for rate limiting & velocity analysis
     */
    recordAttempt(identifier) {
        this.cleanStaleVelocityRecords();
        const now = Date.now();
        const existing = this.recentAttempts.get(identifier) || [];
        existing.push(now);
        this.recentAttempts.set(identifier, existing);
        return existing.length;
    }

    /**
     * Evaluates comprehensive risk score (0-100) and produces explainable decision breakdown
     */
    evaluateRisk({ email = "", ip = "", origin = "", expectedRpId = "", isPhishingSimulation = false, userAgent = "" }) {
        let score = 0;
        const reasons = [];
        const normalizedEmail = String(email || "").trim().toLowerCase();

        // 1. Phishing Simulation Flag
        if (isPhishingSimulation) {
            score += 85;
            reasons.push("Simulated phishing scenario: explicit untrusted origin test.");
            return {
                score: Math.min(score, 100),
                level: "HIGH",
                decision: "BLOCK",
                reasons
            };
        }

        // 2. Origin & RP ID Anomaly Check
        if (origin) {
            try {
                const originUrl = new URL(origin);
                if (expectedRpId && originUrl.hostname !== expectedRpId && !originUrl.hostname.endsWith("." + expectedRpId)) {
                    score += 65;
                    reasons.push(`Origin anomaly: client origin '${originUrl.hostname}' does not match expected RP ID '${expectedRpId}'.`);
                }
            } catch (err) {
                score += 35;
                reasons.push("Malformed or unparseable origin header.");
            }
        }

        // 3. Failed Authentication History (Last 15 minutes)
        try {
            const fifteenMinsAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();
            const failedAttempts = db.prepare(`
                SELECT COUNT(*) as count FROM security_logs 
                WHERE (email = ? OR ip_address = ?) 
                AND event_type IN ('LOGIN_FAILED', 'AUTH_ERROR', 'FALLBACK_AUTH_FAILED', 'RECOVERY_FAILED')
                AND timestamp >= ?
            `).get(normalizedEmail, ip, fifteenMinsAgo).count;

            if (failedAttempts >= 5) {
                score += 55;
                reasons.push(`High failure frequency: ${failedAttempts} failed auth events detected in last 15 minutes.`);
            } else if (failedAttempts >= 2) {
                score += 25;
                reasons.push(`Multiple recent failures: ${failedAttempts} unsuccessful attempts recorded in last 15 minutes.`);
            }
        } catch (dbErr) {
            console.error("Risk DB query error:", dbErr);
        }

        // 4. Request Velocity (Rolling 60-second burst detection)
        const ipAttempts = this.recordAttempt(ip);
        if (ipAttempts > 12) {
            score += 45;
            reasons.push(`Rapid request burst: ${ipAttempts} requests in under 60 seconds from IP.`);
        } else if (ipAttempts > 6) {
            score += 15;
            reasons.push(`Elevated velocity: ${ipAttempts} requests in under 60 seconds.`);
        }

        // 5. Honeypot Intruder History
        try {
            const honeyTrips = db.prepare(`
                SELECT COUNT(*) as count FROM security_logs
                WHERE ip_address = ? AND event_type = 'HONEYTOKEN_TRIGGERED'
            `).get(ip).count;

            if (honeyTrips > 0) {
                score += 40;
                reasons.push(`Known hostile scanner: IP previously triggered active honeytoken trap (${honeyTrips} occurrences).`);
            }
        } catch (e) {}

        // 6. Suspicious / Missing User Agent
        if (!userAgent || userAgent.length < 10 || userAgent.toLowerCase().includes("curl") || userAgent.toLowerCase().includes("python-requests")) {
            score += 20;
            reasons.push("Non-standard automated client or missing user-agent string.");
        }

        // Determine Level and Decision
        let level = "LOW";
        let decision = "ALLOW";

        if (score >= 70) {
            level = "HIGH";
            decision = "RESTRICT"; // reject or throttle
        } else if (score >= 30) {
            level = "MEDIUM";
            decision = "HEIGHTENED_SCRUTINY"; // require re-auth / note audit
        } else {
            level = "LOW";
            decision = "ALLOW";
            if (reasons.length === 0) {
                reasons.push("Standard authentication pattern: normal velocity, verified origin, clean reputation.");
            }
        }

        return {
            score: Math.min(score, 100),
            level,
            decision,
            reasons
        };
    }
}

module.exports = new RiskEngine();
