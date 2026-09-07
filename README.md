# Android Application Penetration Testing & Vulnerability Assessment

A complete, professional cybersecurity project focused on **Static Application Security Testing (SAST)** and **Vulnerability Assessment** of Android applications aligned with the **OWASP Mobile Application Security Verification Standard (MASVS)** and **OWASP Mobile Top 5**.

---

## 📁 Project Directory Structure

```text
android-penetration-testing/
│
├── README.md                      <-- Project Overview & Quickstart Guide
├── PROJECT_REPORT.md              <-- Complete Final Project Report (Ready for submission)
├── PRESENTATION_SLIDES.md         <-- 12-Slide Deck with speaking script for your presentation
├── VIVA_DEFENSE_GUIDE.md          <-- Top 15 Viva/Oral exam questions with complete answers
│
├── android_security_scanner.py    <-- Python SAST Scanner Tool (Build & Demo artifact)
│
└── target_app/                    <-- Target testbed (Simulating InsecureBankv2)
    ├── AndroidManifest.xml        <-- Manifest containing M1 & M3 misconfigurations
    └── src/
        └── com/
            └── android/
                └── insecurebankv2/
                    ├── LoginActivity.java  <-- Demonstrating M2 & M4 vulnerabilities
                    └── CryptoClass.java    <-- Demonstrating M5 cryptographic flaws
```

---

## 🚀 How to Open and Use in VS Code

1. Open **Visual Studio Code**.
2. Click on **File** > **Open Folder...** (or press `Ctrl + K`, `Ctrl + O`).
3. Select this directory:
   ```text
   C:\Users\Sravani\.gemini\antigravity\scratch\android-penetration-testing
   ```
4. All project files, source code, and reports will be ready in the VS Code sidebar.

---

## 🛠️ The Deliverables Included in this Project

### 1. The Written Project Report (`PROJECT_REPORT.md`)
* Formatted into all 7 chapters matching standard university and industry requirements:
  * **Chapter 1:** Introduction & Mobile Threat Landscape
  * **Chapter 2:** Security Testing Environment & Architecture
  * **Chapter 3:** OWASP Mobile Top 5 Vulnerability Assessment (M1 to M5 + Frida Dynamic Analysis)
  * **Chapter 4:** Results & Security Impact Analysis
  * **Chapter 5:** Comprehensive Vulnerability Summary Matrix
  * **Chapter 6:** Conclusion, Lessons Learned & Future Scope
  * **Chapter 7:** References & Appendices
* *Tip:* In VS Code, you can right-click this file or use the Markdown Preview extension (`Ctrl + Shift + V`) to view or print as PDF.

### 2. The Python Security Scanner (`android_security_scanner.py`)
* Gives you a tangible tool to demonstrate if examiners ask what custom tooling was used.
* Scans manifests and source code for:
  * Exported Android components (`android:exported="true"`)
  * Unencrypted network traffic (`usesCleartextTraffic="true"`)
  * Plaintext credential storage in `SharedPreferences`
  * Hardcoded credentials and tokens
  * Insecure hashing algorithms (MD5, SHA-1) and hardcoded symmetric keys
* To execute in VS Code terminal:
  ```powershell
  python android_security_scanner.py target_app
  ```

### 3. Presentation Deck (`PRESENTATION_SLIDES.md`)
* 12 ready-to-use slides with exact bullet points and spoken explanation scripts.

### 4. Viva Exam Preparation (`VIVA_DEFENSE_GUIDE.md`)
* The 15 most commonly asked questions by professors and examiners with concise, impressive answers.
