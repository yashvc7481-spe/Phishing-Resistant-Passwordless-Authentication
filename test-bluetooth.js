const assert = require("assert");
const crypto = require("crypto");

async function runTests() {
    console.log("=================================================");
    console.log("📡 Secure Cryptographic Bluetooth Authentication Test");
    console.log("=================================================\n");

    const baseUrl = "http://localhost:3000";

    // Student Demo Private Key corresponding to seeded Titan Security BLE Key
    const studentDemoPrivateKeyPem = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgj3OZ1lDndLmqlA8r
2VWwWnlotLVuG1hkSPpiC1RDSaGhRANCAARAK2yKY0YlX0PFRJZ47OugdA1uMM5h
2NG4ymOj2K1BPBZfHVI1TK0Bv9tuy3l0keWQj3BKpsmsYPHF4pTLnx56
-----END PRIVATE KEY-----`;

    function signChallenge(challenge, privateKeyPem) {
        const sign = crypto.createSign("SHA256");
        sign.update(challenge);
        return sign.sign(privateKeyPem, "base64");
    }

    // 1. Request Challenge
    console.log("[TEST 1] Request Cryptographic Challenge for Bluetooth...");
    const chalRes = await fetch(`${baseUrl}/api/auth/bluetooth/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            email: "student@nkocet.edu",
            deviceName: "Titan Security BLE Key (Hardware Token)",
            deviceId: "BLE-TITAN-STU-8819"
        })
    });
    assert.strictEqual(chalRes.status, 200, "Challenge request should succeed");
    const chalData = await chalRes.json();
    assert.ok(chalData.challenge.startsWith("CN-PROX-"), "Challenge should have CN-PROX- prefix");
    assert.ok(chalData.sessionId, "Session ID should be present");
    console.log("  ✓ Challenge generated:", chalData.challenge);

    // 2. Complete Verification with Real ECDSA P-256 Signature
    console.log("\n[TEST 2] Complete Bluetooth Challenge-Response Verification with Real ECDSA Signature...");
    const validSignature = signChallenge(chalData.challenge, studentDemoPrivateKeyPem);

    const verifyRes = await fetch(`${baseUrl}/api/auth/bluetooth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            sessionId: chalData.sessionId,
            email: "student@nkocet.edu",
            deviceName: "Titan Security BLE Key (Hardware Token)",
            deviceId: "BLE-TITAN-STU-8819",
            signature: validSignature
        })
    });
    assert.strictEqual(verifyRes.status, 200, "Verification should succeed with 200");
    const verifyData = await verifyRes.json();
    assert.strictEqual(verifyData.success, true);
    assert.strictEqual(verifyData.telemetry.cryptoVerified, true);
    assert.strictEqual(verifyData.telemetry.proximityVerified, true);
    console.log("  ✓ Bluetooth verification succeeded, session cookie issued:", verifyData.redirect);

    // Grab session cookie for authenticated management tests
    const sessionCookie = verifyRes.headers.get("set-cookie");
    assert.ok(sessionCookie, "Session cookie must be returned");

    // 3. Challenge Replay Prevention
    console.log("\n[TEST 3] Challenge Replay / Reuse Prevention...");
    const replayRes = await fetch(`${baseUrl}/api/auth/bluetooth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            sessionId: chalData.sessionId,
            email: "student@nkocet.edu",
            deviceName: "Titan Security BLE Key (Hardware Token)",
            deviceId: "BLE-TITAN-STU-8819",
            signature: validSignature
        })
    });
    assert.strictEqual(replayRes.status, 400, "Replayed challenge must be rejected with 400");
    console.log("  ✓ Replayed Bluetooth challenge successfully rejected");

    // 4. Tampered / Invalid Signature Rejection
    console.log("\n[TEST 4] Tampered Cryptographic Signature Rejection...");
    const chal2Res = await fetch(`${baseUrl}/api/auth/bluetooth/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            email: "student@nkocet.edu",
            deviceName: "Titan Security BLE Key (Hardware Token)",
            deviceId: "BLE-TITAN-STU-8819"
        })
    });
    const chal2Data = await chal2Res.json();

    // Sign with wrong/foreign private key
    const foreignKeys = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const forgedSignature = signChallenge(chal2Data.challenge, foreignKeys.privateKey);

    const forgedRes = await fetch(`${baseUrl}/api/auth/bluetooth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            sessionId: chal2Data.sessionId,
            email: "student@nkocet.edu",
            deviceName: "Titan Security BLE Key (Hardware Token)",
            deviceId: "BLE-TITAN-STU-8819",
            signature: forgedSignature
        })
    });
    assert.strictEqual(forgedRes.status, 401, "Forged signature must be rejected with 401 Unauthorized");
    console.log("  ✓ Forged/invalid cryptographic signature successfully blocked (401)");

    // 5. Unregistered / Unpaired Device Rejection
    console.log("\n[TEST 5] Unregistered Device Rejection...");
    const chal3Res = await fetch(`${baseUrl}/api/auth/bluetooth/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            email: "student@nkocet.edu",
            deviceName: "Attacker Fake Dongle",
            deviceId: "BLE-ATTACKER-UNKNOWN-999"
        })
    });
    const chal3Data = await chal3Res.json();
    const attackerSig = signChallenge(chal3Data.challenge, foreignKeys.privateKey);

    const unregRes = await fetch(`${baseUrl}/api/auth/bluetooth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            sessionId: chal3Data.sessionId,
            email: "student@nkocet.edu",
            deviceName: "Attacker Fake Dongle",
            deviceId: "BLE-ATTACKER-UNKNOWN-999",
            signature: attackerSig
        })
    });
    assert.strictEqual(unregRes.status, 403, "Unregistered device must be rejected with 403 Forbidden");
    console.log("  ✓ Unregistered Bluetooth device successfully blocked (403)");

    // 6. Authenticated Bluetooth Device List
    console.log("\n[TEST 6] Authenticated Bluetooth Device Listing...");
    const listRes = await fetch(`${baseUrl}/api/bluetooth/devices`, {
        headers: { "Cookie": sessionCookie }
    });
    assert.strictEqual(listRes.status, 200);
    const listData = await listRes.json();
    assert.ok(Array.isArray(listData.devices));
    console.log(`  ✓ Successfully fetched ${listData.devices.length} registered Bluetooth devices`);

    // 7. Pair New Trusted Device with Public Key
    console.log("\n[TEST 7] Pair New Trusted Bluetooth Device with Public Key...");
    const newDeviceKeys = crypto.generateKeyPairSync("ec", {
        namedCurve: "prime256v1",
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" }
    });

    const pairRes = await fetch(`${baseUrl}/api/bluetooth/pair`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Cookie": sessionCookie
        },
        body: JSON.stringify({
            deviceName: "Nordic Semi nRF52840 Dongle",
            deviceIdentifier: "BLE-NRF-9944",
            publicKey: newDeviceKeys.publicKey,
            algorithm: "ES256"
        })
    });
    assert.strictEqual(pairRes.status, 200);
    const pairData = await pairRes.json();
    assert.strictEqual(pairData.success, true);
    const newDeviceId = pairData.device.id;
    console.log("  ✓ Paired new device with ID and public key:", newDeviceId);

    // 8. Rename Trusted Bluetooth Device
    console.log("\n[TEST 8] Rename Trusted Bluetooth Device...");
    const renameRes = await fetch(`${baseUrl}/api/bluetooth/devices/${newDeviceId}/rename`, {
        method: "PATCH",
        headers: {
            "Content-Type": "application/json",
            "Cookie": sessionCookie
        },
        body: JSON.stringify({
            deviceName: "Nordic BLE Hardware Token (Lab Unit)"
        })
    });
    assert.strictEqual(renameRes.status, 200);
    console.log("  ✓ Device renamed successfully");

    // 9. Revoke/Unpair Bluetooth Device
    console.log("\n[TEST 9] Revoke/Unpair Trusted Bluetooth Device...");
    const revokeRes = await fetch(`${baseUrl}/api/bluetooth/devices/${newDeviceId}/revoke`, {
        method: "POST",
        headers: { "Cookie": sessionCookie }
    });
    assert.strictEqual(revokeRes.status, 200);
    console.log("  ✓ Device marked as revoked in database");

    // 10. Prevent Revoked Device from Authenticating
    console.log("\n[TEST 10] Verify Revoked Device Cannot Authenticate...");
    const revokedChalRes = await fetch(`${baseUrl}/api/auth/bluetooth/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            email: "student@nkocet.edu",
            deviceName: "Nordic BLE Hardware Token (Lab Unit)",
            deviceId: "BLE-NRF-9944"
        })
    });
    const revokedChalData = await revokedChalRes.json();
    const revokedSig = signChallenge(revokedChalData.challenge, newDeviceKeys.privateKey);

    const blockedRes = await fetch(`${baseUrl}/api/auth/bluetooth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            sessionId: revokedChalData.sessionId,
            email: "student@nkocet.edu",
            deviceName: "Nordic BLE Hardware Token (Lab Unit)",
            deviceId: "BLE-NRF-9944",
            signature: revokedSig
        })
    });
    assert.strictEqual(blockedRes.status, 403, "Revoked device must be blocked with 403 Forbidden");
    const blockedData = await blockedRes.json();
    assert.ok(blockedData.error.includes("revoked"), "Error message should mention device is revoked");
    console.log("  ✓ Revoked Bluetooth device successfully blocked from authentication:", blockedData.error);

    console.log("\n=================================================");
    console.log("🎉 ALL 10 BLUETOOTH AUTHENTICATION TESTS PASSED!");
    console.log("=================================================");
}

runTests().catch(err => {
    console.error("❌ Test failed:", err);
    process.exit(1);
});
