# ANDROID APPLICATION PENETRATION TESTING & VULNERABILITY ASSESSMENT

**Academic & Technical Project Report**  
**Assessment Target:** InsecureBankv2  
**Security Framework:** OWASP Mobile Application Security Verification Standard (MASVS) & Mobile Top 5  
**Testing Methodology:** Static Application Security Testing (SAST), Reverse Engineering & Dynamic Runtime Analysis  

---

## CHAPTER 1: INTRODUCTION

### 1.1 Background
The widespread adoption of smartphones has revolutionized the way individuals and organizations interact with digital services. Mobile devices are now the primary computing endpoints for mobile banking, digital wallets, healthcare management, enterprise communications, and social platforms. Android, developed by Google and the Open Handset Alliance, commands over 70% of the worldwide mobile operating system market, powering billions of active smartphones, tablets, and IoT devices.

As mobile applications handle increasingly sensitive financial and personally identifiable information (PII), their security posture has become paramount. Unlike traditional web applications where code execution occurs predominantly on secure backend servers, Android applications distribute client-side binaries (APKs) directly to untrusted user devices. If an application contains architecture, cryptographic, or permission weaknesses, adversaries can decompile the binary, inspect source code, tamper with runtime memory, or intercept network traffic.

### 1.2 Purpose of the Project
The primary objective of this project is to execute a rigorous, end-to-end security assessment of an Android mobile application following industry-standard penetration testing methodologies. 

Specific project goals include:
1. Deconstructing the Android application architecture (Activities, Services, Broadcast Receivers, Content Providers, and the Android Manifest).
2. Implementing a reproducible mobile security audit laboratory using industry tools (ADB, Jadx, APKTool, Burp Suite, Frida, and custom Python SAST tooling).
3. Analyzing decompiled bytecode and resource configurations against the **OWASP Mobile Top 5** vulnerability categories.
4. Demonstrating realistic proof-of-concept (PoC) security exposures in a controlled environment.
5. Formulating robust, developer-centric remediation code patterns using Android KeyStore, `EncryptedSharedPreferences`, and modern network security standards.

### 1.3 Threat Landscape & Need for Mobile Security Testing
Mobile applications operate within hostile host environments:
- **Device Compromise (Rooting/Jailbreaking):** Bypasses sandbox isolation and file permissions.
- **Reverse Engineering:** Android Dalvik/ART bytecode (`classes.dex`) is readily decompressible and decompilable back into readable Java/Kotlin source code using tools like Jadx.
- **Untrusted Network Interception:** Unprotected wireless channels allow Man-in-the-Middle (MITM) credential harvesting.
- **Inter-Process Tampering:** Improperly exported IPC components allow hostile local applications to invoke restricted internal functionality.

### 1.4 Android Application Architecture Overview
Every Android APK package comprises core modular components:
- **Activities:** Visual entry points representing individual user interface screens.
- **Services:** Background processes executing tasks without direct UI interaction.
- **Broadcast Receivers:** Event listeners that react to system-wide or app-specific Intent broadcasts.
- **Content Providers:** Structured data-sharing interfaces across process boundaries.
- **AndroidManifest.xml:** The root security manifest defining permissions, hardware features, and component export states.
- **DEX (Dalvik Executable) Files:** Bytecode executed by the Android Runtime (ART).

### 1.5 Built-in Android Security Controls
Android provides fundamental operating system protections:
- **Application Sandbox:** UID-based kernel-level process isolation (SELinux).
- **Explicit Permission Model:** Runtime and install-time capability grants.
- **Application Signing:** Cryptographic integrity validation preventing unauthorized code modification.
- **Verified Boot:** Cryptographic hardware root-of-trust verifying OS integrity.

Despite these low-level safeguards, flaws introduced by developers during implementation can completely undermine system security.

---

## CHAPTER 2: LABORATORY & TOOLING ENVIRONMENT

### 2.1 Laboratory Architecture
A dedicated, isolated penetration testing environment was deployed to safely execute assessments without exposing production networks or sensitive accounts.

```
┌────────────────────────────────────────────────────────────────────────┐
│                     Mobile Security Audit Lab                          │
├────────────────────────────────┬───────────────────────────────────────┤
│ Host Environment               │ Windows 10/11 / Linux Workstation     │
├────────────────────────────────┼───────────────────────────────────────┤
│ Reverse Engineering Tooling    │ Jadx-GUI (v1.4.7), APKTool (v2.9.0)   │
├────────────────────────────────┼───────────────────────────────────────┤
│ Automated SAST Tooling         │ Custom Python AST Scanner, MobSF      │
├────────────────────────────────┼───────────────────────────────────────┤
│ Dynamic Interception Proxy     │ Burp Suite Community Edition          │
├────────────────────────────────┼───────────────────────────────────────┤
│ Runtime Instrumentation        │ Frida Toolkit, ADB (Platform Tools)   │
├────────────────────────────────┼───────────────────────────────────────┤
│ Target Application             │ InsecureBankv2 (com.android.insecure)  │
└────────────────────────────────┴───────────────────────────────────────┘
```

### 2.2 Testing Target: InsecureBankv2
`InsecureBankv2` is a deliberately vulnerable open-source Android banking application developed for security researchers and penetration testers. It emulates common security antipatterns across authentication, local storage, inter-process communication, and encryption.

---

## CHAPTER 3: VULNERABILITY ASSESSMENT (OWASP TOP 5)

### 3.1 M1 – Improper Platform Usage: Exported Components & Permissions

#### Definition
Occurs when an application fails to properly configure Android platform security flags or IPC interfaces in `AndroidManifest.xml`, exposing restricted screens or services to third-party apps.

#### Static Code Analysis
Inspection of the decompiled `AndroidManifest.xml` identified an exported administrative screen:
```xml
<activity
    android:name=".AdminPanel"
    android:label="Admin Control Panel"
    android:exported="true">
</activity>
```

#### Risk & Impact
Because `android:exported="true"` is declared without permission constraints, any non-privileged application on the same smartphone can fire an Intent targeting `.AdminPanel`, bypassing authentication checks.

#### Proof of Concept (PoC)
Using Android Debug Bridge (ADB), the internal administration interface was invoked directly from an unauthorized shell state:
```bash
adb shell am start -n com.android.insecurebankv2/.AdminPanel
```
*Result:* The administrative control screen rendered immediately on screen without requesting user login credentials.

#### Developer Remediation
Explicitly set `android:exported="false"` for internal activities, or protect the component with a custom signature-level permission:
```xml
<!-- Secure Implementation -->
<activity
    android:name=".AdminPanel"
    android:exported="false" />
```

---

### 3.2 M2 – Insecure Data Storage: Plaintext SharedPreferences

#### Definition
Occurs when sensitive credentials, session tokens, or personal records are written to local file storage without hardware-backed cryptographic protection.

#### Static Code Analysis
Review of `LoginActivity.java` revealed that authentication credentials are saved into `SharedPreferences`:
```java
SharedPreferences pref = getSharedPreferences("credentials", Context.MODE_PRIVATE);
SharedPreferences.Editor editor = pref.edit();
editor.putString("username", username);
editor.putString("password", password);
editor.apply();
```

#### Risk & Impact
On rooted devices, through application backup extraction (`adb backup`), or via file system forensic extraction, an attacker can access `/data/data/com.android.insecurebankv2/shared_prefs/credentials.xml` and retrieve the user's password in plaintext.

#### Proof of Concept (PoC)
Extracting the preferences file via ADB:
```bash
adb shell cat /data/data/com.android.insecurebankv2/shared_prefs/credentials.xml
```
*Observed Content:*
```xml
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="username">admin</string>
    <string name="password">password123</string>
</map>
```

#### Developer Remediation
Adopt Google's `EncryptedSharedPreferences` backed by the Android KeyStore:
```java
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();

SharedPreferences securePrefs = EncryptedSharedPreferences.create(
    context,
    "secure_credentials",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
```

---

### 3.3 M3 – Insecure Communication: Cleartext HTTP Transmission

#### Definition
Transmitting sensitive application payloads across unencrypted communication channels (plain HTTP), making communications susceptible to eavesdropping and Man-in-the-Middle (MITM) attacks.

#### Manifest & Code Analysis
In `AndroidManifest.xml`:
```xml
<application android:usesCleartextTraffic="true" ... >
```
In `LoginActivity.java`:
```java
private static final String AUTH_ENDPOINT = "http://insecurebank.local:8080/login";
```

#### Risk & Impact
An adversary on the same local area network (public Wi-Fi hotspot or rogue access point) can inspect plaintext HTTP packets and intercept user authentication tokens using Burp Suite or Wireshark.

#### Developer Remediation
1. Disable cleartext communication in the manifest:
   ```xml
   <application android:usesCleartextTraffic="false" ... >
   ```
2. Enforce HTTPS and define a strict `res/xml/network_security_config.xml`:
   ```xml
   <network-security-config>
       <base-config cleartextTrafficPermitted="false">
           <trust-anchors>
               <certificates src="system" />
           </trust-anchors>
       </base-config>
   </network-security-config>
   ```

---

### 3.4 M4 – Insecure Authentication: Hardcoded Logic

#### Definition
Embedding static authentication criteria, secret master passwords, or hardcoded tokens within compiled client-side binaries.

#### Static Code Analysis
Inspection of `LoginActivity.java` in Jadx decompilation:
```java
public boolean authenticateUser(String username, String password) {
    if (username.equals("admin") && password.equals("admin")) {
        return true;
    }
    return false;
}
```

#### Risk & Impact
Anyone who downloads the APK can decompile the classes with open-source tools (Jadx/APKTool) and identify master credentials within seconds.

#### Developer Remediation
Client applications must never validate authentication credentials locally against hardcoded strings. Authentication must be delegated to a secure remote identity provider returning short-lived JSON Web Tokens (JWT) or OAuth2 bearer tokens.

---

### 3.5 M5 – Insufficient Cryptography: Broken MD5 & Hardcoded Keys

#### Definition
Employing deprecated cryptographic hash functions (MD5, SHA1) or embedding static symmetric encryption keys within source code.

#### Static Code Analysis
In `CryptoClass.java`:
```java
private static final String STATIC_KEY = "1234567890123456";

public static String hashPassword(String password) {
    MessageDigest md = MessageDigest.getInstance("MD5");
    // ...
}
```

#### Risk & Impact
- **MD5 Collisions & Rainbow Tables:** MD5 hashes can be looked up instantly against precomputed databases.
- **Key Extraction:** The symmetric key `"1234567890123456"` is permanently visible in the bytecode, allowing any attacker to decrypt stored application data.

#### Developer Remediation
- Use **PBKDF2WithHmacSHA256**, **bcrypt**, or **Argon2** for password hashing.
- Use **AES-256-GCM** with keys generated dynamically inside the hardware-backed **Android KeyStore provider**:
```java
KeyGenerator keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
keyGenerator.init(new KeyGenParameterSpec.Builder("MySecretKeyAlias",
    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .build());
SecretKey secretKey = keyGenerator.generateKey();
```

---

### 3.6 Dynamic Analysis: Runtime Hooking with Frida

#### Objective
To demonstrate that client-side controls can be dynamically altered at runtime on an unlocked or rooted Android environment.

#### Hook Script (`login_hook.js`)
```javascript
Java.perform(function () {
    var LoginActivity = Java.use("com.android.insecurebankv2.LoginActivity");
    LoginActivity.authenticateUser.implementation = function (user, pass) {
        console.log("[*] Intercepted Login Call:");
        console.log("    Username: " + user);
        console.log("    Password: " + pass);
        // Force authentication bypass
        return true;
    };
});
```

#### Finding
Dynamic instrumentation proves that client-side business logic cannot be trusted without server-side validation. Applications must implement Root Detection and Runtime Application Self-Protection (RASP) controls.

---

## CHAPTER 4: RESULTS & DISCUSSION

### 4.1 Assessment Summary Table
```
┌─────────┬────────────────────────┬───────────┬──────────────┬───────────────┐
│ Finding │ Vulnerability Type     │ Severity  │ CVSS v3.1    │ OWASP Mobile  │
├─────────┼────────────────────────┼───────────┼──────────────┼───────────────┤
│ SEC-01  │ Exported Admin Activity│ Medium    │ 5.3 (Medium) │ M1: Platform  │
│ SEC-02  │ Plaintext SharedPrefs  │ High      │ 7.1 (High)   │ M2: Storage   │
│ SEC-03  │ Cleartext HTTP Traffic │ Critical  │ 8.2 (High)   │ M3: Network   │
│ SEC-04  │ Hardcoded Admin Login  │ Critical  │ 9.1 (Crit)   │ M4: Auth      │
│ SEC-05  │ Insecure MD5 & Key     │ High      │ 7.5 (High)   │ M5: Crypto    │
└─────────┴────────────────────────┴───────────┴──────────────┴───────────────┘
```

### 4.2 Impact Breakdown
- **Confidentiality:** Severely compromised due to plaintext credential storage and cleartext HTTP transport.
- **Integrity:** Highly impacted by client-side authentication bypasses and lack of runtime anti-tampering.
- **Availability:** Low impact directly, though unauthorized admin panel access could allow resource destruction.

---

## CHAPTER 5: CONCLUSION & RECOMMENDATIONS

### 5.1 Project Summary
This project successfully constructed an end-to-end Android mobile penetration testing workflow. Through static reverse engineering and dynamic inspection of `InsecureBankv2`, multiple vulnerabilities spanning the **OWASP Mobile Top 5** were systematically documented, categorized by CVSS severity, and addressed with production-ready defensive patches.

### 5.2 Key Recommendations for Android Developers
1. **Never Trust Client Logic:** All authorization checks must be validated by remote backend APIs.
2. **Utilize Hardware KeyStore:** Sensitive cryptographic operations must be delegated to the Android KeyStore.
3. **Minimize Component Attack Surface:** Explicitly mark all activities, services, and receivers with `exported="false"` unless external invocation is strictly required.
4. **Enforce HTTPS Everywhere:** Mandate TLS 1.3 via `network_security_config.xml`.
5. **Integrate Automated SAST in CI/CD:** Continuously scan APK builds for hardcoded secrets, dangerous flags, and known antipatterns prior to production releases.

---

## CHAPTER 6: REFERENCES
1. OWASP Foundation. *OWASP Mobile Application Security Verification Standard (MASVS)*.
2. OWASP Foundation. *OWASP Mobile Security Testing Guide (MSTG)*.
3. Google Developers. *Android Core Security Guidelines & Cryptography Documentation*.
4. PortSwigger. *Mobile Penetration Testing with Burp Suite Proxy*.
5. Frida Development Team. *Frida Runtime Dynamic Instrumentation Toolkit Documentation*.
