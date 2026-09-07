# VIVA VOCE & ORAL DEFENSE PREPARATION GUIDE
## Android Application Penetration Testing & Vulnerability Assessment

This guide contains the 15 most frequent and critical questions asked by academic examiners and interviewers for mobile cybersecurity projects. Memorize these concise points to score top marks.

---

### Question 1: What is the fundamental difference between Static Analysis (SAST) and Dynamic Analysis (DAST)?
* **Answer:**
  * **Static Analysis (SAST):** Evaluates the application's source code, manifest, and decompiled bytecode without running the application. Tools used: Jadx-GUI, APKTool, and our custom Python scanner. It is excellent for finding configuration flaws, hardcoded credentials, and insecure APIs.
  * **Dynamic Analysis (DAST):** Evaluates the application in real-time while it is running on a device or emulator. Tools used: Burp Suite (for network traffic) and Frida (for runtime hooking). It tests live authentication flows, session handling, and memory manipulation.

---

### Question 2: What is an APK file, and what happens during reverse engineering?
* **Answer:**
  * An APK (Android Package Kit) is an archive format (essentially a ZIP file) containing `classes.dex` (compiled Dalvik/ART bytecode), `AndroidManifest.xml`, `resources.arsc`, and asset files.
  * When we reverse engineer an APK using **Jadx**, it converts the binary `classes.dex` bytecode back into readable Java source code. **APKTool** decodes the manifest and compiled XML resources into editable plaintext and extracts Smali assembly code.

---

### Question 3: What does `android:exported="true"` mean, and why is it dangerous?
* **Answer:**
  * In Android, the `android:exported` attribute determines whether an Activity, Service, or Broadcast Receiver can be launched by components belonging to other applications on the device.
  * If an internal screen (like an AdminPanel or sensitive data view) is marked `android:exported="true"` without permission checks, any rogue application installed on the phone can invoke it using an Intent (`am start`), bypassing login and authorization controls entirely.

---

### Question 4: How does Insecure Data Storage happen in SharedPreferences?
* **Answer:**
  * `SharedPreferences` stores data as an unencrypted XML file in `/data/data/<package_name>/shared_prefs/`.
  * If a developer stores usernames, passwords, or session tokens there using standard `SharedPreferences`, anyone with physical access, root privileges, or `adb backup` capabilities can read the file in plain text.
  * **Fix:** Use Google's `EncryptedSharedPreferences`, which encrypts keys and values using AES-256 backed by the Android KeyStore.

---

### Question 5: Why is MD5 considered insecure for hashing passwords?
* **Answer:**
  * MD5 is vulnerable to collision attacks (where two different inputs produce the same hash output) and is computationally too fast, making it vulnerable to brute force and precomputed rainbow-table lookups.
  * For passwords, developers should use dedicated salted key-derivation functions such as **PBKDF2**, **bcrypt**, or **Argon2**. For cryptographic integrity, modern algorithms like **SHA-256** should be used.

---

### Question 6: What is the Android KeyStore, and why is it important?
* **Answer:**
  * The Android KeyStore is a security container that lets applications generate and store cryptographic keys in hardware (such as a Trusted Execution Environment or Secure Element).
  * When using KeyStore, the key material never enters the application process's RAM in unencrypted form, which means even if the device is rooted or memory is dumped, the private encryption keys cannot be extracted.

---

### Question 7: How does Burp Suite intercept HTTPS traffic from an Android application?
* **Answer:**
  * Burp Suite acts as a Man-in-the-Middle (MITM) proxy. To inspect encrypted HTTPS packets, Burp generates a custom Certificate Authority (CA) root certificate.
  * Once this CA certificate is installed into the Android device's trusted credentials and proxy settings point to Burp (`127.0.0.1:8080`), Burp can negotiate TLS sessions with both the client and server, decrypting and displaying traffic in transit.

---

### Question 8: What is SSL/TLS Certificate Pinning, and how does it prevent MITM attacks?
* **Answer:**
  * In standard HTTPS, the client trusts any certificate signed by any CA in the device's trust store.
  * **Certificate Pinning** hardcodes or pins the server's public key or certificate fingerprint directly inside the Android app. If an interceptor (like Burp Suite) presents its own CA certificate, the app rejects the connection because it doesn't match the pinned fingerprint.

---

### Question 9: What is Frida, and how did you use it in your project?
* **Answer:**
  * Frida is a dynamic runtime instrumentation toolkit that lets security engineers inject JavaScript snippets into native and Java processes at runtime.
  * In our project, Frida was used to hook the `authenticateUser` method inside `LoginActivity`. By overriding its implementation in memory, we forced the method to return `true`, demonstrating a complete client-side authentication bypass without knowing the password.

---

### Question 10: What is the difference between Intent Filters and Explicit Intents?
* **Answer:**
  * **Explicit Intent:** Specifies the exact component to start by class name (e.g., `Intent(this, TargetActivity.class)`). Safe and used within the same application.
  * **Implicit Intent:** Declares an action to perform (e.g., `ACTION_VIEW`), allowing any component registered with a matching `intent-filter` in its manifest to respond. If not properly secured, implicit intents can lead to Intent Spoofing and component hijacking.

---

### Question 11: Why is `android:usesCleartextTraffic="true"` a security risk?
* **Answer:**
  * It permits the application to make unencrypted HTTP requests. All communication travels across the network in cleartext, exposing sensitive information (tokens, passwords, PII) to eavesdroppers on public Wi-Fi networks or malicious network nodes.

---

### Question 12: What is the OWASP MASVS standard?
* **Answer:**
  * The OWASP **Mobile Application Security Verification Standard (MASVS)** is the industry benchmark for mobile app security requirements.
  * It defines security levels (L1: Standard Security, L2: Defense-in-Technical, R: Resilience against reverse engineering) across architecture, data storage, cryptography, authentication, network communication, platform interaction, and code quality.

---

### Question 13: What is RASP (Runtime Application Self-Protection)?
* **Answer:**
  * RASP refers to built-in security mechanisms that detect and neutralize attacks at runtime.
  * Examples include: Root detection (checking for `su` binary, Magisk), Emulator detection, Debugger detection (`android.os.Debug.isDebuggerConnected()`), and integrity checksum verification of the APK.

---

### Question 14: How does `android:allowBackup="true"` create a security exposure?
* **Answer:**
  * When `allowBackup="true"`, any user who connects the phone to a computer with USB debugging enabled can run `adb backup` to extract the application's private sandbox data (databases, shared preferences, caches) into a `.ab` archive file on their laptop, even without root permissions.

---

### Question 15: What did you learn and build personally for this project?
* **Answer:**
  * *"I built an automated Python-based Static Security Scanner that parses AndroidManifest.xml and decompiled Java files to flag OWASP Mobile Top 5 vulnerabilities automatically. I also performed reverse engineering with Jadx to uncover hardcoded credentials, analyzed insecure local storage, and demonstrated runtime hooking using Frida, providing production-grade remediations for every vulnerability."*
