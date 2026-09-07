#!/usr/bin/env python3
"""
Android Application Static Security Analyzer (SAST)
Aligned with OWASP Mobile Top 10 & MASVS

Description:
    Automated vulnerability scanner for Android applications. Analyzes AndroidManifest.xml
    and source files (Java/Kotlin) to identify high-risk security flaws including:
    - M1: Improper Platform Usage (Exported components, debuggable flags)
    - M2: Insecure Data Storage (Plaintext shared preferences, sensitive logs)
    - M3: Insecure Communication (Cleartext HTTP traffic)
    - M4: Insecure Authentication (Hardcoded credentials)
    - M5: Insufficient Cryptography (Weak hashing like MD5, hardcoded encryption keys)

Usage:
    python android_security_scanner.py
"""

import os
import sys
import re
import xml.etree.ElementTree as ET
from pathlib import Path

class AndroidSecurityScanner:
    def __init__(self, target_dir):
        self.target_dir = Path(target_dir)
        self.findings = []
        self.stats = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    def add_finding(self, category, title, severity, file_path, line_num, description, remediation):
        self.findings.append({
            "category": category,
            "title": title,
            "severity": severity,
            "file": str(file_path),
            "line": line_num,
            "description": description,
            "remediation": remediation
        })
        self.stats[severity] = self.stats.get(severity, 0) + 1

    def scan_manifest(self):
        """Scans AndroidManifest.xml for configuration weaknesses."""
        manifest_paths = list(self.target_dir.glob("**/AndroidManifest.xml"))
        if not manifest_paths:
            manifest_paths = list(Path(".").glob("**/AndroidManifest.xml"))

        if not manifest_paths:
            print("[!] Warning: AndroidManifest.xml not found.")
            return

        for manifest_path in manifest_paths:
            try:
                tree = ET.parse(manifest_path)
                root = tree.getroot()

                app = root.find('application')
                if app is not None:
                    # Check debuggable
                    debuggable = app.attrib.get('{http://schemas.android.com/apk/res/android}debuggable')
                    if debuggable == 'true':
                        self.add_finding(
                            "M1 - Improper Platform Usage",
                            "Application is Debuggable",
                            "High",
                            manifest_path,
                            1,
                            "android:debuggable is set to 'true'. This allows runtime hooking, memory inspection, and debugger attachment.",
                            "Set android:debuggable=\"false\" in production release builds."
                        )

                    # Check allowBackup
                    backup = app.attrib.get('{http://schemas.android.com/apk/res/android}allowBackup')
                    if backup == 'true' or backup is None:
                        self.add_finding(
                            "M2 - Insecure Data Storage",
                            "Application Allows Data Backup",
                            "Medium",
                            manifest_path,
                            1,
                            "android:allowBackup is enabled. Attackers can extract application data via 'adb backup'.",
                            "Set android:allowBackup=\"false\" to prevent unauthorized local extraction."
                        )

                    # Check cleartext traffic
                    cleartext = app.attrib.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
                    if cleartext == 'true':
                        self.add_finding(
                            "M3 - Insecure Communication",
                            "Cleartext HTTP Traffic Permitted",
                            "Critical",
                            manifest_path,
                            1,
                            "android:usesCleartextTraffic is set to 'true'. Transmitted data is vulnerable to Man-in-the-Middle (MITM) attacks.",
                            "Set android:usesCleartextTraffic=\"false\" and configure network_security_config.xml to enforce HTTPS."
                        )

                    # Check exported components
                    for comp_type in ['activity', 'service', 'receiver', 'provider']:
                        for comp in app.findall(comp_type):
                            name = comp.attrib.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                            exported = comp.attrib.get('{http://schemas.android.com/apk/res/android}exported')
                            intent_filters = comp.findall('intent-filter')

                            is_exported = (exported == 'true') or (exported is None and len(intent_filters) > 0)
                            
                            is_main_launcher = False
                            for ifilter in intent_filters:
                                action = ifilter.find('action')
                                if action is not None and 'MAIN' in action.attrib.get('{http://schemas.android.com/apk/res/android}name', ''):
                                    is_main_launcher = True

                            if is_exported and not is_main_launcher:
                                self.add_finding(
                                    "M1 - Improper Platform Usage",
                                    f"Exported {comp_type.capitalize()}: {name}",
                                    "Medium",
                                    manifest_path,
                                    1,
                                    f"Component '{name}' is publicly exported and accessible by any third-party app on the device without permission checks.",
                                    f"Set android:exported=\"false\" on <{comp_type}> or apply a signature-level custom permission."
                                )

            except Exception as e:
                print(f"[!] Error parsing manifest {manifest_path}: {e}")

    def scan_source_code(self):
        """Scans Java, Kotlin, and Smali source files for code-level security issues."""
        extensions = [".java", ".kt", ".smali"]
        code_files = [f for f in self.target_dir.rglob("*") if f.suffix.lower() in extensions]

        patterns = [
            (
                r'("admin"|"password"|"123456"|"secret")\s*\.equals|equals\s*\(\s*("admin"|"password"|"123456"|"secret")',
                "M4 - Insecure Authentication",
                "Hardcoded Credentials in Logic",
                "Critical",
                "Hardcoded credentials detected in conditional evaluation logic.",
                "Authenticate against a secure remote backend. Never embed plaintext credentials in client source code."
            ),
            (
                r'(String|var|val)\s+(password|passwd|apiKey|api_key|secret_key)\s*=\s*["\'][^"\']+["\']',
                "M4 - Insecure Authentication",
                "Hardcoded Secret / API Key",
                "High",
                "Hardcoded secret string found in source code.",
                "Store sensitive credentials in secure remote key management services or Android KeyStore."
            ),
            (
                r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']\s*\)',
                "M5 - Insufficient Cryptography",
                "Use of Insecure Hash Algorithm (MD5)",
                "High",
                "MD5 algorithm is vulnerable to collision attacks and rainbow-table cracking.",
                "Replace MD5 with SHA-256 or modern key derivation functions (PBKDF2, bcrypt, Argon2)."
            ),
            (
                r'Cipher\.getInstance\s*\(\s*["\']DES|AES/ECB["\']\s*\)',
                "M5 - Insufficient Cryptography",
                "Insecure Cipher Mode (DES / ECB)",
                "High",
                "DES is deprecated and ECB mode does not provide cryptographic semantic security.",
                "Use AES/GCM/NoPadding with authenticated encryption."
            ),
            (
                r'String\s+key\s*=\s*["\'][0-9a-zA-Z]{8,}|STATIC_KEY\s*=\s*["\'][0-9a-zA-Z]{8,}',
                "M5 - Insufficient Cryptography",
                "Hardcoded Symmetric Encryption Key",
                "High",
                "Static symmetric encryption key embedded in application binary.",
                "Generate cryptographically secure random keys and manage them with Android KeyStore."
            ),
            (
                r'Log\.(d|v|i)\s*\([^,]+,\s*.*(password|pin|token|credential|secret)',
                "M2 - Insecure Data Storage",
                "Sensitive Information Leaked to Logcat",
                "Medium",
                "Sensitive authentication or user data is printed to system logs.",
                "Strip debug logs in release builds using ProGuard/R8 rules."
            ),
            (
                r'getSharedPreferences\s*\(.*MODE_WORLD_READABLE',
                "M2 - Insecure Data Storage",
                "World Readable SharedPreferences",
                "High",
                "Shared preferences created with MODE_WORLD_READABLE can be inspected by any local application.",
                "Use MODE_PRIVATE or EncryptedSharedPreferences."
            ),
            (
                r'["\']http://[a-zA-Z0-9\./_-]+["\']',
                "M3 - Insecure Communication",
                "Unencrypted HTTP URL in Source",
                "Medium",
                "Communication with an HTTP URL exposes network traffic to eavesdropping.",
                "Enforce HTTPS across all network requests."
            )
        ]

        for file_path in code_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_num, line in enumerate(f, start=1):
                        for regex, category, title, severity, desc, rem in patterns:
                            if re.search(regex, line, re.IGNORECASE):
                                self.add_finding(category, title, severity, file_path, line_num, desc, rem)
            except Exception as e:
                print(f"[!] Error scanning file {file_path}: {e}")

    def generate_console_summary(self):
        print("\n" + "=" * 75)
        print("  ANDROID SECURITY ASSESSMENT - STATIC SCAN RESULTS (OWASP MASVS)")
        print("=" * 75)
        print(f"Target Scanned: {self.target_dir.resolve()}")
        print(f"Total Findings: {len(self.findings)}")
        print(f"  [CRITICAL]: {self.stats['Critical']} | [HIGH]: {self.stats['High']} | [MEDIUM]: {self.stats['Medium']} | [LOW]: {self.stats['Low']}")
        print("-" * 75)

        for idx, f in enumerate(self.findings, start=1):
            try:
                rel_file = os.path.relpath(f['file'], self.target_dir)
            except Exception:
                rel_file = f['file']
            print(f"#{idx} [{f['severity']}] {f['title']}")
            print(f"    Category    : {f['category']}")
            print(f"    Location    : {rel_file} (Line {f['line']})")
            print(f"    Description : {f['description']}")
            print(f"    Remediation : {f['remediation']}\n")
        print("=" * 75)

    def export_markdown_report(self, output_file="scan_report.md"):
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# Android Application Security Assessment Report\n\n")
            f.write(f"**Target Directory:** `{self.target_dir.resolve()}`  \n")
            f.write(f"**Total Findings:** {len(self.findings)}  \n\n")
            f.write("### Severity Summary\n")
            f.write(f"- **Critical:** {self.stats['Critical']}\n")
            f.write(f"- **High:** {self.stats['High']}\n")
            f.write(f"- **Medium:** {self.stats['Medium']}\n")
            f.write(f"- **Low:** {self.stats['Low']}\n\n")
            f.write("### Detailed Findings\n\n")
            f.write("| ID | Category | Finding | Severity | Location | Remediation |\n")
            f.write("|:---|:---|:---|:---|:---|:---|\n")
            for idx, item in enumerate(self.findings, start=1):
                try:
                    rel_file = os.path.relpath(item['file'], self.target_dir)
                except Exception:
                    rel_file = item['file']
                f.write(f"| {idx} | {item['category']} | {item['title']} | **{item['severity']}** | `{rel_file}:{item['line']}` | {item['remediation']} |\n")
        print(f"[+] Security report exported successfully to: {output_file}")

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    print(f"[*] Initiating Android SAST Scan against: {target}...")
    scanner = AndroidSecurityScanner(target)
    scanner.scan_manifest()
    scanner.scan_source_code()
    scanner.generate_console_summary()
    scanner.export_markdown_report("scan_report.md")

if __name__ == "__main__":
    main()
