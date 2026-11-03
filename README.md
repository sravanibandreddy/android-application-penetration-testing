# Android Application Penetration Testing & Vulnerability Assessment

A cybersecurity project focused on **Static Application Security Testing (SAST)** and vulnerability assessment of Android applications, using security principles from the **OWASP Mobile Application Security Verification Standard (MASVS)** and OWASP Mobile Top 10.

The project includes a Python-based Android security scanner, a sample vulnerable Android application, an interactive HTML security dashboard, scan reports, and an Android Studio demonstration application.

---

## 1. Project Objectives

- Identify potential security vulnerabilities in Android application source code.
- Detect insecure Android manifest configurations and permissions.
- Identify hardcoded credentials and cryptographic weaknesses.
- Examine insecure network communication and sensitive data storage.
- Generate structured vulnerability assessment reports.
- Demonstrate Android security assessment concepts through an Android application.

## 2. Project Directory Structure

```text
android-application-penetration-testing/
│
├── README.md
├── PROJECT_REPORT.md
├── PRESENTATION_SLIDES.md
├── VIVA_DEFENSE_GUIDE.md
│
├── android_security_scanner.py
├── android_scanner.ps1
├── security_portal.html
│
├── scan_report.json
├── scan_report.md
│
├── target_app/
│   ├── AndroidManifest.xml
│   └── src/
│       └── com/
│           └── android/
│               └── insecurebankv2/
│                   ├── LoginActivity.java
│                   └── CryptoClass.java
│
└── AndroidSecurityDemo/
    ├── app/
    │   └── src/
    │       └── main/
    │           ├── AndroidManifest.xml
    │           └── java/
    │               └── com/
    │                   └── example/
    │                       └── androidsecuritydemo/
    │                           └── MainActivity.kt
    ├── build.gradle.kts
    ├── settings.gradle.kts
    └── gradlew
```

## 3. Main Project Components

### 3.1 Python Android Security Scanner

File: `android_security_scanner.py`

A custom Python-based static security analysis tool that examines Android source code and manifest files for potential security weaknesses.

It checks for patterns such as:

- Exported Android components.
- Cleartext network traffic.
- Application debugging configurations.
- Insecure permissions.
- Hardcoded credentials and cryptographic keys.
- Weak hashing algorithms such as MD5.
- Weak encryption algorithms such as DES.
- Insecure HTTP endpoints.
- Sensitive information in application logs.
- Passwords stored in SharedPreferences.

**How to execute:**

Open the project folder in VS Code and run:

```powershell
python android_security_scanner.py target_app
```

The scanner produces vulnerability findings and generates JSON and Markdown reports.

### 3.2 Security Assessment Dashboard

File: `security_portal.html`

An interactive HTML dashboard for viewing the scanner's results.

Features:

- Upload and display JSON scan reports.
- View total vulnerability findings.
- View severity-wise vulnerability counts.
- Filter findings by severity.
- Search vulnerability findings.
- Export scan results where supported.

**How to open:**

```powershell
Start-Process ".\security_portal.html"
```

Upload `scan_report.json` through the dashboard to view the assessment results.

### 3.3 Android Studio Demonstration Application

Folder: `AndroidSecurityDemo/`

A separate Android application developed using **Kotlin and Jetpack Compose** in Android Studio.

The application demonstrates important Android security assessment concepts through a checklist-based interface.

The demonstration includes:

1. Application Debugging.
2. Cleartext Traffic.
3. Hardcoded Credentials.
4. Weak Cryptography.
5. Sensitive Data Storage.

It also contains a **Complete Demo Check** button that displays a completion message.

**How to open:**

1. Open Android Studio.
2. Select **Open**.
3. Navigate to the project directory.
4. Select the `AndroidSecurityDemo` folder.
5. Allow Gradle synchronization to complete.
6. Start an Android virtual device.
7. Click **Run** to launch the application.

The application was successfully built and tested using the Pixel 7 virtual emulator.

**Note:** AndroidSecurityDemo is a demonstration application. It does not perform actual vulnerability scanning. The Python scanner is the project's static analysis component.

## 4. Vulnerability Assessment Results

The scanner identified **14 potential security findings** in the sample Android application.

### Severity Summary

| Severity | Findings |
|---|---:|
| Critical | 1 |
| High | 7 |
| Medium | 5 |
| Low | 0 |
| Informational | 1 |
| **Total** | **14** |

### Important Findings

| Finding | Vulnerability | Severity |
|---|---|---|
| F001 | Application debugging enabled | High |
| F002 | Application backup enabled | Medium |
| F003 | Cleartext network traffic permitted | High |
| F004 | WRITE_EXTERNAL_STORAGE permission | Medium |
| F005 | READ_SMS permission | Medium |
| F006 | Exported AdminPanel activity | Medium |
| F007 | Hardcoded cryptographic key | High |
| F008 | Weak MD5 hashing algorithm | High |
| F009 | Weak DES encryption algorithm | High |
| F010 | Insecure HTTP endpoint | High |
| F011 | Sensitive information in application logs | Medium |
| F012 | Hardcoded login credentials | Critical |
| F013 | SharedPreferences usage | Informational |
| F014 | Password stored in SharedPreferences | High |

### Report Files

- `scan_report.json` – Structured machine-readable vulnerability report.
- `scan_report.md` – Human-readable vulnerability assessment report.

These reports can be used to review findings and demonstrate the scanner's output.

**Important:** Findings are generated using pattern-based static analysis. They represent potential vulnerabilities and require manual validation. The scanner does not perform complete APK analysis, runtime testing, or dynamic penetration testing. An informational finding, such as SharedPreferences usage, is not necessarily a vulnerability by itself.

## 5. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Static security scanner |
| HTML, CSS, JavaScript | Security dashboard |
| Java | Sample Android application source |
| Kotlin | Android Studio demo application |
| Jetpack Compose | Android demo user interface |
| Android Studio | Android application development |
| Android Emulator | Application demonstration and testing |
| Git and GitHub | Version control and project hosting |
| OWASP MASVS | Mobile application security reference |

## 6. Installation and Execution

### Requirements

- Python 3.x
- Visual Studio Code
- Android Studio
- Android SDK and Android Emulator
- Git

### Run the Python Scanner

Navigate to the repository folder:

```powershell
cd android-application-penetration-testing
```

Run:

```powershell
python android_security_scanner.py target_app
```

### View the Dashboard

```powershell
Start-Process ".\security_portal.html"
```

Upload the generated `scan_report.json` file.

### Run the Android Studio Demo

Open `AndroidSecurityDemo/` in Android Studio, wait for Gradle synchronization, start a virtual device, and click Run.

## 7. Security Recommendations

Based on the identified findings, the following security improvements are recommended:

- Disable debugging in production builds.
- Disable unnecessary application backups.
- Restrict cleartext network communication and use HTTPS.
- Request only necessary Android permissions.
- Protect exported components with appropriate access controls.
- Avoid hardcoded credentials and cryptographic keys.
- Use modern cryptographic algorithms and secure key management.
- Never log passwords or sensitive authentication information.
- Avoid storing passwords directly in SharedPreferences.
- Use secure authentication and credential-management mechanisms.

## 8. Limitations

- The Python scanner uses predefined patterns and rules.
- Static analysis cannot confirm whether every finding is exploitable.
- The project does not implement complete dynamic penetration testing.
- The Android Studio demo is a checklist-based educational interface, not a scanning engine.
- Results require manual security verification.

## 9. Future Enhancements

- APK decompilation and analysis.
- Integration with MobSF.
- Dynamic testing using an Android emulator.
- Runtime monitoring with appropriate instrumentation tools.
- More advanced vulnerability detection rules.
- Automated PDF report generation.
- Integration with CI/CD security testing pipelines.

## 10. Conclusion

This project demonstrates how static security analysis can help identify potential weaknesses in Android applications.

It combines a custom Python security scanner, an interactive dashboard, a sample vulnerable Android application, structured vulnerability reports, and an Android Studio demonstration application.

The project provides practical exposure to Android application security assessment and introduces important mobile security concepts based on OWASP guidance.

---

**Project:** Android Application Penetration Testing & Vulnerability Assessment  
**Repository:** https://github.com/sravanibandreddy/android-application-penetration-testing  
**Purpose:** Academic Project and Cybersecurity Learning