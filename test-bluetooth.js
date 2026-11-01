const assert = require("assert");

async function runTests() {
    console.log("=================================================");
    console.log("📡 Bluetooth-Based Authentication & Device Management Test");
    console.log("=================================================\n");

    const baseUrl = "http://localhost:3000";

    // 1. Request Challenge
    console.log("[TEST 1] Request Cryptographic Challenge for Bluetooth...");
    const chalRes = await fetch(`${baseUrl}/api/auth/bluetooth/challenge`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            email: "student@nkocet.edu",
            deviceName: "Titan BLE Security Key",
            deviceId: "BLE-TITAN-KEY-001"
        })
    });
    assert.strictEqual(chalRes.status, 200, "Challenge request should succeed");
    const chalData = await chalRes.json();
    assert.ok(chalData.challenge.startsWith("CN-PROX-"), "Challenge should have CN-PROX- prefix");
    assert.ok(chalData.sessionId, "Session ID should be present");
    console.log("  ✓ Challenge generated:", chalData.challenge);

    // 2. Complete Verification
    console.log("\n[TEST 2] Complete Bluetooth Challenge-Response Verification...");
    const verifyRes = await fetch(`${baseUrl}/api/auth/bluetooth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            sessionId: chalData.sessionId,
            email: "student@nkocet.edu",
            deviceName: "Titan BLE Security Key",
            deviceId: "BLE-TITAN-KEY-001",
            challengeProof: "HMAC_GATT_PROXIMITY_VALIDATED"
        })
    });
    assert.strictEqual(verifyRes.status, 200, "Verification should succeed with 200");
    const verifyData = await verifyRes.json();
    assert.strictEqual(verifyData.success, true);
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
            deviceName: "Titan BLE Security Key",
            deviceId: "BLE-TITAN-KEY-001"
        })
    });
    assert.strictEqual(replayRes.status, 400, "Replayed challenge must be rejected with 400");
    console.log("  ✓ Replayed Bluetooth challenge successfully rejected");

    // 4. Authenticated Bluetooth Device List
    console.log("\n[TEST 4] Authenticated Bluetooth Device Listing...");
    const listRes = await fetch(`${baseUrl}/api/bluetooth/devices`, {
        headers: { "Cookie": sessionCookie }
    });
    assert.strictEqual(listRes.status, 200);
    const listData = await listRes.json();
    assert.ok(Array.isArray(listData.devices));
    console.log(`  ✓ Successfully fetched ${listData.devices.length} registered Bluetooth devices`);

    // 5. Pair New Trusted Device
    console.log("\n[TEST 5] Pair New Trusted Bluetooth Device...");
    const pairRes = await fetch(`${baseUrl}/api/bluetooth/pair`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Cookie": sessionCookie
        },
        body: JSON.stringify({
            deviceName: "Nordic Semi nRF52840 Dongle",
            deviceIdentifier: "BLE-NRF-9944"
        })
    });
    assert.strictEqual(pairRes.status, 200);
    const pairData = await pairRes.json();
    assert.strictEqual(pairData.success, true);
    const newDeviceId = (pairData.device && pairData.device.id) || pairData.deviceId;
    console.log("  ✓ Paired new device with ID:", newDeviceId);

    // 6. Rename Trusted Bluetooth Device
    console.log("\n[TEST 6] Rename Trusted Bluetooth Device...");
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

    // 7. Revoke/Unpair Bluetooth Device
    console.log("\n[TEST 7] Revoke/Unpair Trusted Bluetooth Device...");
    const revokeRes = await fetch(`${baseUrl}/api/bluetooth/devices/${newDeviceId}/revoke`, {
        method: "POST",
        headers: { "Cookie": sessionCookie }
    });
    assert.strictEqual(revokeRes.status, 200);
    console.log("  ✓ Device marked as revoked in database");

    // 8. Prevent Revoked Device from Authenticating
    console.log("\n[TEST 8] Verify Revoked Device Cannot Authenticate...");
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

    const blockedRes = await fetch(`${baseUrl}/api/auth/bluetooth/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            sessionId: revokedChalData.sessionId,
            email: "student@nkocet.edu",
            deviceName: "Nordic BLE Hardware Token (Lab Unit)",
            deviceId: "BLE-NRF-9944"
        })
    });
    assert.strictEqual(blockedRes.status, 403, "Revoked device must be blocked with 403 Forbidden");
    const blockedData = await blockedRes.json();
    assert.ok(blockedData.error.includes("revoked"), "Error message should mention device is revoked");
    console.log("  ✓ Revoked Bluetooth device successfully blocked from authentication:", blockedData.error);

    console.log("\n=================================================");
    console.log("🎉 ALL BLUETOOTH AUTHENTICATION TESTS PASSED!");
    console.log("=================================================");
}

runTests().catch(err => {
    console.error("❌ Test failed:", err);
    process.exit(1);
});
