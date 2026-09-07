# PRESENTATION SLIDES & SPEAKER SCRIPT

**Project Title:** Android Application Penetration Testing & Vulnerability Assessment  
**Standard:** OWASP Mobile Top 5 & MASVS  
**Target:** InsecureBankv2  

---

### Slide 1: Title Slide
* **Slide Title:** Android Application Penetration Testing & Vulnerability Assessment
* **Subtitle:** An In-Depth Security Audit based on OWASP Mobile Top 5
* **Details:** Presented by [Your Name] | Department of Computer Science & Cybersecurity
* **Speaker Script:**
  > *"Good morning, respected professors and examiners. Today, I am presenting my project on Android Application Penetration Testing and Vulnerability Assessment. With billions of active Android devices worldwide handling sensitive banking and personal transactions, securing mobile applications is critical. In this project, I established a security testing lab, audited an educational target application called InsecureBankv2, uncovered critical vulnerabilities, and implemented secure remediation strategies."*

---

### Slide 2: Problem Statement & Objectives
* **Key Points:**
  * Mobile applications distribute compiled code directly to untrusted devices.
  * Attackers can decompile, tamper with memory, and intercept network traffic.
  * **Core Goals:**
    1. Perform Static Application Security Testing (SAST) and reverse engineering.
    2. Assess vulnerabilities against the OWASP Mobile Top 5 standard.
    3. Demonstrate live proof-of-concept exploits in a controlled lab.
    4. Provide production-grade secure coding remediations.
* **Speaker Script:**
  > *"Unlike web applications where sensitive code stays protected on a secure server, Android applications reside directly on the user's phone. If an app has security flaws, anyone can decompile the APK and read its code. My objective was to systematically audit an application using OWASP standards, demonstrate how these flaws can be exploited, and provide concrete fixes."*

---

### Slide 3: Testing Methodology & Toolchain
* **Key Points:**
  * **Static Analysis (SAST):** Jadx-GUI (Decompilation), APKTool (Manifest & Smali analysis), Custom Python Scanner.
  * **Dynamic Analysis (DAST):** Burp Suite (Traffic interception), Frida (Runtime memory hooking).
  * **Device Interaction:** Android Debug Bridge (ADB) on rooted emulator testbed.
* **Speaker Script:**
  > *"Our assessment methodology combined both static analysis and dynamic analysis. In static analysis, we inspected the application's manifest and decompiled Java code without running it, using Jadx and our automated Python scanner. In dynamic analysis, we monitored the application while it was running, intercepting network requests with Burp Suite and instrumenting runtime memory with Frida."*

---

### Slide 4: M1 – Improper Platform Usage (Exported Components)
* **Finding:** Component `AdminPanel` declared with `android:exported="true"`.
* **Impact:** Any rogue application installed on the same phone can launch the Admin Panel without logging in.
* **PoC Command:** `adb shell am start -n com.android.insecurebankv2/.AdminPanel`
* **Fix:** Set `android:exported="false"` or require custom signature permissions.
* **Speaker Script:**
  > *"Our first finding is under OWASP M1: Improper Platform Usage. In AndroidManifest.xml, the AdminPanel activity had its exported attribute set to true without permission checks. This means any third-party app on the phone can invoke this administrative screen directly. We demonstrated this using ADB to launch the activity, completely bypassing the login page. The fix is simple: declare android:exported="false" for private components."*

---

### Slide 5: M2 – Insecure Data Storage (Plaintext SharedPreferences)
* **Finding:** Sensitive user credentials stored in cleartext XML.
* **Location:** `/data/data/com.android.insecurebankv2/shared_prefs/credentials.xml`
* **Impact:** Plaintext credential disclosure via physical access, device backups, or root access.
* **Fix:** Use Google's `EncryptedSharedPreferences` backed by the Android KeyStore.
* **Speaker Script:**
  > *"Under OWASP M2: Insecure Data Storage, we analyzed how the app stores user data locally. Upon login, the app writes usernames and passwords directly into a standard SharedPreferences XML file in plaintext. Using ADB, we pulled this file and easily read the stored credentials. To secure this, developers should use Android's EncryptedSharedPreferences, which uses AES-256 encryption tied to the hardware KeyStore."*

---

### Slide 6: M3 – Insecure Communication (Cleartext HTTP)
* **Finding:** Application communicates over plain `http://` with `usesCleartextTraffic="true"`.
* **Impact:** Vulnerable to Man-in-the-Middle (MITM) credential theft on public networks.
* **Fix:** Enforce TLS 1.3 and implement `network_security_config.xml` to disallow cleartext traffic.
* **Speaker Script:**
  > *"Under OWASP M3: Insecure Communication, the application's manifest permitted cleartext traffic, and login requests were sent via plain HTTP instead of HTTPS. An attacker on the same local Wi-Fi network can capture these requests using a proxy like Burp Suite and view credentials in transit. The remediation is to enforce HTTPS across all endpoints and restrict cleartext traffic in the network security configuration."*

---

### Slide 7: M4 – Insecure Authentication (Hardcoded Logic)
* **Finding:** Hardcoded credentials `admin` / `admin` evaluated directly in client-side bytecode.
* **Impact:** Instant reverse engineering reveals the master password; no brute force needed.
* **Fix:** Validate credentials against a remote backend server; never embed passwords in code.
* **Speaker Script:**
  > *"Under OWASP M4: Insecure Authentication, reviewing the decompiled source code in Jadx revealed a hardcoded check: if username equals admin and password equals admin, grant access. This is a severe anti-pattern because any decompilation tool reveals the logic instantly. Authentication must always take place on a secure remote server that issues time-limited session tokens."*

---

### Slide 8: M5 – Insufficient Cryptography (MD5 & Hardcoded Keys)
* **Finding:** Deprecated MD5 hashing and hardcoded AES encryption key `1234567890123456`.
* **Impact:** MD5 hashes are cracked via rainbow tables; hardcoded keys allow offline decryption.
* **Fix:** Adopt SHA-256 / PBKDF2 for hashing; generate random keys managed by Android KeyStore.
* **Speaker Script:**
  > *"Under OWASP M5: Insufficient Cryptography, the application used MD5 for password hashing and hardcoded a 16-character encryption key directly into the code. MD5 is cryptographically obsolete and vulnerable to collision attacks. Hardcoded keys compromise confidentiality completely. We recommend modern key derivation functions like PBKDF2 or Argon2, and hardware-managed keys via Android KeyStore."*

---

### Slide 9: Dynamic Analysis with Frida (Runtime Hooking)
* **Objective:** Demonstrate runtime vulnerability to function hooking on rooted environments.
* **Method:** Injected JavaScript into the running process using Frida to intercept the login method and force it to return `true`.
* **Result:** Successful authentication bypass without needing valid credentials.
* **Fix:** Implement Root Detection, emulator detection, and Runtime Application Self-Protection (RASP).
* **Speaker Script:**
  > *"To demonstrate dynamic runtime risks, we used Frida to hook the authenticateUser method in real time. Our JavaScript script intercepted the arguments and forced the method to return true, successfully bypassing login controls on the device. This proves that client-side controls alone cannot be trusted, and apps must implement anti-tampering and root-detection mechanisms."*

---

### Slide 10: Risk Rating Matrix & Vulnerability Summary
* **Summary Table:**
  * M1: Exported Admin Panel -> Medium (CVSS 5.3)
  * M2: Plaintext SharedPreferences -> High (CVSS 7.1)
  * M3: Cleartext HTTP Traffic -> Critical (CVSS 8.2)
  * M4: Hardcoded Admin Login -> Critical (CVSS 9.1)
  * M5: Broken MD5 & Static Keys -> High (CVSS 7.5)
* **Speaker Script:**
  > *"Here is our vulnerability distribution summary. We identified two Critical, two High, and one Medium severity vulnerability. The most severe threats were the hardcoded authentication logic and cleartext network transmission, both of which allow immediate compromise of user accounts."*

---

### Slide 11: Developer Best Practices & Secure SDLC
* **Key Takeaways:**
  1. Adopt the Principle of Least Privilege in permissions and exported components.
  2. Implement hardware-backed storage with Android KeyStore.
  3. Enforce TLS and Certificate Pinning for sensitive banking transactions.
  4. Integrate automated static scanning tools into CI/CD development pipelines.
* **Speaker Script:**
  > *"To build secure mobile applications, security must be integrated early into the software development life cycle. Developers should adopt automated SAST scanning during development, minimize component export exposure, utilize Android KeyStore for encryption, and never trust client-side validation alone."*

---

### Slide 12: Conclusion & Q&A
* **Slide Text:**
  * Project Successfully Completed: Full Penetration Testing Workflow Demonstrated.
  * Deliverables: Comprehensive 7-Chapter Report, Python SAST Analyzer Tool, and Remediation Blueprint.
  * Thank you! Any Questions?
* **Speaker Script:**
  > *"In conclusion, this project demonstrated how vulnerability assessment methodologies can identify critical mobile flaws before malicious actors do. Thank you for your time and attention, and I am now ready to answer any questions."*
