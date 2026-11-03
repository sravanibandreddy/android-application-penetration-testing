# Android Static Security Scan Report (scan_report)

- **Target:** `target_app`
- **Generated (UTC):** 2026-11-03T05:08:16.376614+00:00
- **Total findings:** 14

> Pattern-based triage only. Validate findings manually; no findings does not prove security.

## Severity summary

| Severity | Count |
|---|---:|
| Critical | 1 |
| High | 7 |
| Medium | 5 |
| Low | 0 |
| Info | 1 |

## Findings

### F001 — Application is debuggable (High)

- **Category:** Android Manifest
- **Location:** `AndroidManifest.xml:14`
- **Evidence:** `android:debuggable="true"`
- **Why it matters:** Debug builds can expose runtime state and facilitate instrumentation.
- **Recommended fix:** Set android:debuggable="false" in release builds.

### F002 — Application backup is enabled (Medium)

- **Category:** Android Manifest
- **Location:** `AndroidManifest.xml:13`
- **Evidence:** `android:allowBackup="true"`
- **Why it matters:** Backups may expose app data depending on Android version and backup configuration.
- **Recommended fix:** Review backup rules and set android:allowBackup="false" when backups are not required.

### F003 — Cleartext network traffic is permitted (High)

- **Category:** Android Manifest
- **Location:** `AndroidManifest.xml:15`
- **Evidence:** `android:usesCleartextTraffic="true"`
- **Why it matters:** The app permits HTTP traffic, which can expose data to network interception.
- **Recommended fix:** Set android:usesCleartextTraffic="false" and use HTTPS for all endpoints.

### F004 — Sensitive permission requested: android.permission.WRITE_EXTERNAL_STORAGE (Medium)

- **Category:** Excessive Permissions
- **Location:** `AndroidManifest.xml:9`
- **Evidence:** `android:name="android.permission.WRITE_EXTERNAL_STORAGE"`
- **Why it matters:** This permission is sensitive or broad and should be justified by a clear feature need.
- **Recommended fix:** Remove unused permissions and request the minimum permissions required.

### F005 — Sensitive permission requested: android.permission.READ_SMS (Medium)

- **Category:** Excessive Permissions
- **Location:** `AndroidManifest.xml:10`
- **Evidence:** `android:name="android.permission.READ_SMS"`
- **Why it matters:** This permission is sensitive or broad and should be justified by a clear feature need.
- **Recommended fix:** Remove unused permissions and request the minimum permissions required.

### F006 — Exported activity: .AdminPanel (Medium)

- **Category:** Android Manifest
- **Location:** `AndroidManifest.xml:37`
- **Evidence:** `.AdminPanel, android:exported='true'`
- **Why it matters:** An exported component may be reachable by other apps; access controls must be checked.
- **Recommended fix:** Set android:exported="false" if external access is not needed, or protect it with appropriate permissions.

### F007 — Potential hardcoded key or secret (High)

- **Category:** M5 - Insufficient Cryptography
- **Location:** `src\com\android\insecurebankv2\CryptoClass.java:11`
- **Evidence:** `private static final String STATIC_KEY = "1234567890123456";`
- **Why it matters:** A constant resembling a cryptographic key or secret appears in source code.
- **Recommended fix:** Do not embed reusable secrets in client apps; use server-side secret management or Android Keystore for device-held keys.

### F008 — Weak hash algorithm (High)

- **Category:** M5 - Insufficient Cryptography
- **Location:** `src\com\android\insecurebankv2\CryptoClass.java:18`
- **Evidence:** `MessageDigest md = MessageDigest.getInstance("MD5");`
- **Why it matters:** MD5 and SHA-1 are not suitable for modern security-sensitive hashing.
- **Recommended fix:** For passwords, use a salted password KDF such as Argon2id, scrypt, bcrypt, or PBKDF2 with suitable parameters.

### F009 — Weak cipher or ECB mode (High)

- **Category:** M5 - Insufficient Cryptography
- **Location:** `src\com\android\insecurebankv2\CryptoClass.java:36`
- **Evidence:** `Cipher cipher = Cipher.getInstance("DES");`
- **Why it matters:** DES is obsolete and ECB mode can reveal patterns in encrypted data.
- **Recommended fix:** Use authenticated encryption such as AES-GCM with nonce management and platform-managed keys.

### F010 — HTTP endpoint in source (High)

- **Category:** M3 - Insecure Communication
- **Location:** `src\com\android\insecurebankv2\LoginActivity.java:13`
- **Evidence:** `private static final String AUTH_ENDPOINT = "http://insecurebank.local:8080/login";`
- **Why it matters:** An HTTP URL is not encrypted in transit and may expose requests or responses.
- **Recommended fix:** Use HTTPS with valid certificate validation; disable cleartext traffic unless a documented exception is required.

### F011 — Sensitive data in logs (Medium)

- **Category:** M2 - Insecure Data Storage
- **Location:** `src\com\android\insecurebankv2\LoginActivity.java:26`
- **Evidence:** `Log.d(TAG, "Attempting authentication for user: " + username + " with password: " + password);`
- **Why it matters:** Logging authentication or secret-related data may expose it through device logs.
- **Recommended fix:** Remove sensitive values from logs; avoid logging credentials and tokens in all builds.

### F012 — Hardcoded credential check (Critical)

- **Category:** M4 - Insecure Authentication
- **Location:** `src\com\android\insecurebankv2\LoginActivity.java:29`
- **Evidence:** `if (username.equals("admin") && password.equals("admin")) {`
- **Why it matters:** A known credential string is compared directly in client-side logic.
- **Recommended fix:** Perform authentication and authorization on a trusted backend; never embed fixed user credentials in the app.

### F013 — Use of SharedPreferences (Info)

- **Category:** Review - Data Storage
- **Location:** `src\com\android\insecurebankv2\LoginActivity.java:40`
- **Evidence:** `SharedPreferences pref = getSharedPreferences("credentials", Context.MODE_PRIVATE);`
- **Why it matters:** SharedPreferences is not automatically insecure, but sensitive values stored without encryption require review.
- **Recommended fix:** Do not store passwords or long-lived tokens in plaintext preferences; use an appropriate secure storage design.

### F014 — Sensitive value written to preferences (High)

- **Category:** M2 - Insecure Data Storage
- **Location:** `src\com\android\insecurebankv2\LoginActivity.java:43`
- **Evidence:** `editor.putString("password", password); // Stored in cleartext in shared_prefs/credentials.xml`
- **Why it matters:** A secret-like value is written to preferences; confirm whether it is encrypted and necessary.
- **Recommended fix:** Avoid storing passwords. For tokens, use short lifetimes and platform-backed secure storage.

