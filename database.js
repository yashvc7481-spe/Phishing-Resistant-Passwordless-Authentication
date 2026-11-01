const Database = require("better-sqlite3");
const db = new Database("cybernova.db");

// Initialize tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('student', 'staff'))
    );

    CREATE TABLE IF NOT EXISTS credentials (
        credential_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        public_key TEXT NOT NULL,
        counter INTEGER NOT NULL DEFAULT 0,
        device_name TEXT DEFAULT 'Security Authenticator',
        transports TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS security_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        email TEXT,
        ip_address TEXT,
        details TEXT,
        severity TEXT CHECK(severity IN ('INFO', 'WARNING', 'CRITICAL')),
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS bluetooth_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        device_name TEXT NOT NULL,
        device_identifier TEXT NOT NULL,
        paired_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS backup_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_code TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        used_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS recovery_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        used INTEGER DEFAULT 0,
        used_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
`);

// Safe Schema Migrations
try { db.exec("ALTER TABLE credentials ADD COLUMN status TEXT DEFAULT 'active'"); } catch (e) {}
try { db.exec("ALTER TABLE credentials ADD COLUMN last_used DATETIME"); } catch (e) {}
try { db.exec("ALTER TABLE security_logs ADD COLUMN risk_score INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE security_logs ADD COLUMN risk_level TEXT DEFAULT 'LOW'"); } catch (e) {}
try { db.exec("ALTER TABLE security_logs ADD COLUMN is_simulation INTEGER DEFAULT 0"); } catch (e) {}
try { db.exec("ALTER TABLE bluetooth_devices ADD COLUMN status TEXT DEFAULT 'active'"); } catch (e) {}
try { db.exec("ALTER TABLE bluetooth_devices ADD COLUMN public_key TEXT"); } catch (e) {}
try { db.exec("ALTER TABLE bluetooth_devices ADD COLUMN algorithm TEXT DEFAULT 'ES256'"); } catch (e) {}

const DEMO_STUDENT_BT_PUBKEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQCtsimNGJV9DxUSWeOzroHQNbjDO
YdjRuMpjo9itQTwWXx1SNUytAb/bbst5dJHlkI9wSqbJrGDxxeKUy58eeg==
-----END PUBLIC KEY-----`;

const DEMO_STAFF_BT_PUBKEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAET1CFm5fRxfKUtOvPtLamwTICDyzp
3EFCnOuokyabQpgTEJVdpnYbjyNxpq9wHMaoYpO1XwHSlw79/r9v7LP6YQ==
-----END PUBLIC KEY-----`;

try {
    db.prepare("UPDATE bluetooth_devices SET public_key = ?, algorithm = 'ES256' WHERE (device_identifier LIKE '%TITAN%' OR device_name LIKE '%Titan%') AND public_key IS NULL")
      .run(DEMO_STUDENT_BT_PUBKEY);
} catch (e) {}

const crypto = require("crypto");
function hashRecoveryCode(code, salt) {
    return crypto.createHash("sha256").update(code.trim().toUpperCase() + salt).digest("hex");
}

// Insert default demo accounts if not already present
const addUser = db.prepare(`
    INSERT OR IGNORE INTO users (email, display_name, role)
    VALUES (?, ?, ?)
`);

addUser.run("student@nkocet.edu", "Demo Student", "student");
addUser.run("staff@nkocet.edu", "Demo Staff", "staff");

// Seed backup emergency tokens if not present
const studentUser = db.prepare("SELECT id FROM users WHERE email = ?").get("student@nkocet.edu");
const staffUser = db.prepare("SELECT id FROM users WHERE email = ?").get("staff@nkocet.edu");

if (studentUser) {
    const existingToken = db.prepare("SELECT id FROM backup_tokens WHERE user_id = ?").get(studentUser.id);
    if (!existingToken) {
        db.prepare("INSERT INTO backup_tokens (user_id, token_code) VALUES (?, ?)").run(studentUser.id, "CN-SECURE-STU-9921");
    }

    const existingRecovery = db.prepare("SELECT id FROM recovery_codes WHERE user_id = ?").get(studentUser.id);
    if (!existingRecovery) {
        const salt = crypto.randomBytes(16).toString("hex");
        const code = "CN-RECOV-9921-STU1";
        db.prepare("INSERT INTO recovery_codes (user_id, code_hash, salt) VALUES (?, ?, ?)")
          .run(studentUser.id, hashRecoveryCode(code, salt), salt);
    }

    const existingBtStudent = db.prepare("SELECT id, public_key FROM bluetooth_devices WHERE user_id = ?").get(studentUser.id);
    if (!existingBtStudent) {
        db.prepare(`
            INSERT INTO bluetooth_devices (user_id, device_name, device_identifier, status, public_key, algorithm, last_used)
            VALUES (?, ?, ?, 'active', ?, 'ES256', CURRENT_TIMESTAMP)
        `).run(studentUser.id, "Titan Security BLE Key (Hardware Token)", "BLE-TITAN-STU-8819", DEMO_STUDENT_BT_PUBKEY);
    } else if (!existingBtStudent.public_key) {
        db.prepare("UPDATE bluetooth_devices SET public_key = ?, algorithm = 'ES256' WHERE id = ?")
          .run(DEMO_STUDENT_BT_PUBKEY, existingBtStudent.id);
    }
}

if (staffUser) {
    const existingToken = db.prepare("SELECT id FROM backup_tokens WHERE user_id = ?").get(staffUser.id);
    if (!existingToken) {
        db.prepare("INSERT INTO backup_tokens (user_id, token_code) VALUES (?, ?)").run(staffUser.id, "CN-SECURE-STF-4482");
    }

    const existingRecovery = db.prepare("SELECT id FROM recovery_codes WHERE user_id = ?").get(staffUser.id);
    if (!existingRecovery) {
        const salt = crypto.randomBytes(16).toString("hex");
        const code = "CN-RECOV-4482-STF1";
        db.prepare("INSERT INTO recovery_codes (user_id, code_hash, salt) VALUES (?, ?, ?)")
          .run(staffUser.id, hashRecoveryCode(code, salt), salt);
    }

    const existingBtStaff = db.prepare("SELECT id, public_key FROM bluetooth_devices WHERE user_id = ?").get(staffUser.id);
    if (!existingBtStaff) {
        db.prepare(`
            INSERT INTO bluetooth_devices (user_id, device_name, device_identifier, status, public_key, algorithm, last_used)
            VALUES (?, ?, ?, 'active', ?, 'ES256', CURRENT_TIMESTAMP)
        `).run(staffUser.id, "YubiKey 5C NFC/BLE Proximity Token", "BLE-YUBI-STF-4412", DEMO_STAFF_BT_PUBKEY);
    } else if (!existingBtStaff.public_key) {
        db.prepare("UPDATE bluetooth_devices SET public_key = ?, algorithm = 'ES256' WHERE id = ?")
          .run(DEMO_STAFF_BT_PUBKEY, existingBtStaff.id);
    }
}

console.log("✓ Database initialized with Users, Credentials, Bluetooth, and Recovery tables.");

module.exports = db;
module.exports.hashRecoveryCode = hashRecoveryCode;