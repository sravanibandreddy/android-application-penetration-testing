# Automated Android Security Scan Report

**Scan Target:** 	arget_app  
**Total Findings:** 9

| ID | Severity | Category | Vulnerability | Location | Fix |
|:---|:---|:---|:---|:---|:---|
| 1 | **High** | M1 - Platform Usage | Application is Debuggable | $(@{Severity=High; Category=M1 - Platform Usage; Title=Application is Debuggable; File=AndroidManifest.xml; Line=Manifest; Fix=Set android:debuggable="false" in release builds.}.File):Manifest | Set android:debuggable="false" in release builds. |
| 2 | **Medium** | M2 - Insecure Storage | Application Allows Data Backup | $(@{Severity=Medium; Category=M2 - Insecure Storage; Title=Application Allows Data Backup; File=AndroidManifest.xml; Line=Manifest; Fix=Set android:allowBackup="false" to stop ADB backup extraction.}.File):Manifest | Set android:allowBackup="false" to stop ADB backup extraction. |
| 3 | **Critical** | M3 - Insecure Comm. | Cleartext HTTP Traffic Permitted | $(@{Severity=Critical; Category=M3 - Insecure Comm.; Title=Cleartext HTTP Traffic Permitted; File=AndroidManifest.xml; Line=Manifest; Fix=Set usesCleartextTraffic="false" and enforce HTTPS via TLS 1.3.}.File):Manifest | Set usesCleartextTraffic="false" and enforce HTTPS via TLS 1.3. |
| 4 | **Medium** | M1 - Platform Usage | Exported Admin Activity (.AdminPanel) | $(@{Severity=Medium; Category=M1 - Platform Usage; Title=Exported Admin Activity (.AdminPanel); File=AndroidManifest.xml; Line=Manifest; Fix=Set android:exported="false" to block unauthorized access.}.File):Manifest | Set android:exported="false" to block unauthorized access. |
| 5 | **High** | M5 - Cryptography | Hardcoded Symmetric Encryption Key | $(@{Severity=High; Category=M5 - Cryptography; Title=Hardcoded Symmetric Encryption Key; File=CryptoClass.java; Line=Line 11; Fix=Generate random keys and protect with Android KeyStore.}.File):Line 11 | Generate random keys and protect with Android KeyStore. |
| 6 | **High** | M5 - Cryptography | Insecure MD5 Hash Algorithm Used | $(@{Severity=High; Category=M5 - Cryptography; Title=Insecure MD5 Hash Algorithm Used; File=CryptoClass.java; Line=Line 18; Fix=Replace MD5 with SHA-256 or bcrypt/Argon2.}.File):Line 18 | Replace MD5 with SHA-256 or bcrypt/Argon2. |
| 7 | **Medium** | M3 - Insecure Comm. | Unencrypted HTTP URL Endpoint | $(@{Severity=Medium; Category=M3 - Insecure Comm.; Title=Unencrypted HTTP URL Endpoint; File=LoginActivity.java; Line=Line 13; Fix=Use https:// endpoints exclusively.}.File):Line 13 | Use https:// endpoints exclusively. |
| 8 | **Medium** | M2 - Insecure Storage | Sensitive Credentials Leaked in Logcat | $(@{Severity=Medium; Category=M2 - Insecure Storage; Title=Sensitive Credentials Leaked in Logcat; File=LoginActivity.java; Line=Line 26; Fix=Remove sensitive logging in production builds.}.File):Line 26 | Remove sensitive logging in production builds. |
| 9 | **Critical** | M4 - Authentication | Hardcoded Admin Credentials in Logic | $(@{Severity=Critical; Category=M4 - Authentication; Title=Hardcoded Admin Credentials in Logic; File=LoginActivity.java; Line=Line 29; Fix=Authenticate against secure backend API. Remove hardcoded strings.}.File):Line 29 | Authenticate against secure backend API. Remove hardcoded strings. |

