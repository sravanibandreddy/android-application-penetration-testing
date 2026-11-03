#!/usr/bin/env python3
"""Defensive static scanner for Android source trees and manifests.

This tool reports suspicious patterns for manual review. It is not a full
penetration test and does not prove exploitability.
Usage: python android_security_scanner.py <target_directory>
"""
import json
import re
import sys
from pathlib import Path
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

class AndroidSecurityScanner:
    def __init__(self, target_dir):
        self.target_label = str(target_dir)
        self.target_dir = Path(target_dir).resolve()
        self.findings = []
        self.seen = set()

    def add(self, category, title, severity, file_path, line, evidence, description, remediation):
        try:
            location = str(Path(file_path).resolve().relative_to(self.target_dir))
        except ValueError:
            location = str(file_path)
        key = (category, title, location, line, evidence)
        if key in self.seen:
            return
        self.seen.add(key)
        self.findings.append({
            "id": f"F{len(self.findings)+1:03d}",
            "category": category, "title": title, "severity": severity,
            "file": location, "line": line, "evidence": evidence.strip()[:240],
            "description": description, "remediation": remediation
        })

    def _line_for(self, path, needle):
        try:
            for n, text in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if needle in text:
                    return n
        except OSError:
            pass
        return 1

    def scan_manifest(self):
        for path in self.target_dir.rglob("AndroidManifest.xml"):
            try:
                root = ET.parse(path).getroot()
            except (ET.ParseError, OSError) as exc:
                print(f"[!] Could not parse {path}: {exc}")
                continue
            app = root.find("application")
            if app is None:
                continue
            checks = [
                ("debuggable", "true", "High", "Application is debuggable",
                 "Debug builds can expose runtime state and facilitate instrumentation.",
                 'Set android:debuggable="false" in release builds.'),
                ("allowBackup", "true", "Medium", "Application backup is enabled",
                 "Backups may expose app data depending on Android version and backup configuration.",
                 'Review backup rules and set android:allowBackup="false" when backups are not required.'),
                ("usesCleartextTraffic", "true", "High", "Cleartext network traffic is permitted",
                 "The app permits HTTP traffic, which can expose data to network interception.",
                 'Set android:usesCleartextTraffic="false" and use HTTPS for all endpoints.')
            ]
            for attr, value, sev, title, desc, fix in checks:
                if app.attrib.get(ANDROID_NS + attr, "").lower() == value:
                    needle = f'android:{attr}="{value}"'
                    self.add("Android Manifest", title, sev, path, self._line_for(path, needle),
                             needle, desc, fix)
            for permission in root.findall("uses-permission"):
                name = permission.attrib.get(ANDROID_NS + "name", "")
                if name in {"android.permission.READ_SMS", "android.permission.WRITE_EXTERNAL_STORAGE"}:
                    needle = f'android:name="{name}"'
                    self.add("Excessive Permissions", f"Sensitive permission requested: {name}", "Medium",
                             path, self._line_for(path, needle), needle,
                             "This permission is sensitive or broad and should be justified by a clear feature need.",
                             "Remove unused permissions and request the minimum permissions required.")
            for kind in ("activity", "service", "receiver", "provider"):
                for comp in app.findall(kind):
                    name = comp.attrib.get(ANDROID_NS + "name", "Unknown")
                    exported = comp.attrib.get(ANDROID_NS + "exported")
                    filters = comp.findall("intent-filter")
                    is_launcher = any(
                        any(a.attrib.get(ANDROID_NS + "name") == "android.intent.action.MAIN"
                            for a in f.findall("action")) for f in filters)
                    is_exported = exported == "true" or (exported is None and bool(filters))
                    if is_exported and not is_launcher:
                        needle = f'android:name="{name}"'
                        self.add("Android Manifest", f"Exported {kind}: {name}", "Medium", path,
                                 self._line_for(path, needle), f"{name}, android:exported={exported!r}",
                                 "An exported component may be reachable by other apps; access controls must be checked.",
                                 f'Set android:exported="false" if external access is not needed, or protect it with appropriate permissions.')

    def scan_source(self):
        patterns = [
            (r'Log\.(?:d|v|i|w|e)\s*\([^;\n]*(?:password|passwd|token|secret|credential|pin)',
             "Sensitive data in logs", "Medium", "M2 - Insecure Data Storage",
             "Logging authentication or secret-related data may expose it through device logs.",
             "Remove sensitive values from logs; avoid logging credentials and tokens in all builds."),
            (r'getSharedPreferences\s*\(', "Use of SharedPreferences", "Info", "Review - Data Storage",
             "SharedPreferences is not automatically insecure, but sensitive values stored without encryption require review.",
             "Do not store passwords or long-lived tokens in plaintext preferences; use an appropriate secure storage design."),
            (r'\.putString\s*\(\s*["\'](?:password|passwd|token|secret|api[_-]?key)["\']',
             "Sensitive value written to preferences", "High", "M2 - Insecure Data Storage",
             "A secret-like value is written to preferences; confirm whether it is encrypted and necessary.",
             "Avoid storing passwords. For tokens, use short lifetimes and platform-backed secure storage."),
            (r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1)["\']\s*\)',
             "Weak hash algorithm", "High", "M5 - Insufficient Cryptography",
             "MD5 and SHA-1 are not suitable for modern security-sensitive hashing.",
             "For passwords, use a salted password KDF such as Argon2id, scrypt, bcrypt, or PBKDF2 with suitable parameters."),
            (r'Cipher\.getInstance\s*\(\s*["\'](?:DES|DESede|AES/ECB[^"\']*)["\']',
             "Weak cipher or ECB mode", "High", "M5 - Insufficient Cryptography",
             "DES is obsolete and ECB mode can reveal patterns in encrypted data.",
             "Use authenticated encryption such as AES-GCM with nonce management and platform-managed keys."),
            (r'(?:STATIC_KEY|SECRET_KEY|ENCRYPTION_KEY|API_KEY)\s*=\s*["\'][^"\']{8,}["\']',
             "Potential hardcoded key or secret", "High", "M5 - Insufficient Cryptography",
             "A constant resembling a cryptographic key or secret appears in source code.",
             "Do not embed reusable secrets in client apps; use server-side secret management or Android Keystore for device-held keys."),
            (r'["\']http://[^"\']+["\']',
             "HTTP endpoint in source", "High", "M3 - Insecure Communication",
             "An HTTP URL is not encrypted in transit and may expose requests or responses.",
             "Use HTTPS with valid certificate validation; disable cleartext traffic unless a documented exception is required."),
            (r'(?:equals\s*\(\s*["\'](?:admin|password|123456|secret)["\']|["\'](?:admin|password|123456|secret)["\']\s*\.equals)',
             "Hardcoded credential check", "Critical", "M4 - Insecure Authentication",
             "A known credential string is compared directly in client-side logic.",
             "Perform authentication and authorization on a trusted backend; never embed fixed user credentials in the app."),
        ]
        extensions = {".java", ".kt", ".smali"}
        skip_dirs = {".git", "build", ".gradle", "__pycache__"}
        for path in self.target_dir.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in extensions:
                continue
            if any(part in skip_dirs for part in path.parts):
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for line_no, line in enumerate(lines, 1):
                for pattern, title, severity, category, desc, fix in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        self.add(category, title, severity, path, line_no, line, desc, fix)

    def result(self):
        counts = {s: sum(f["severity"] == s for f in self.findings) for s in SEVERITIES}
        return {
            "tool": "Android Static Security Scanner",
            "version": "2.0",
            "scan_type": "Static pattern analysis",
            "target": self.target_label,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "limitations": "Pattern-based triage only. Findings require manual validation; absence of findings does not prove security.",
            "total_findings": len(self.findings),
            "severity_counts": counts,
            "findings": self.findings
        }

def main():
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "target_app")
    report_name = sys.argv[2] if len(sys.argv) > 2 else "scan_report"
    
    # Strip extension if provided
    if report_name.endswith(".json"):
        report_base = report_name[:-5]
    elif report_name.endswith(".md"):
        report_base = report_name[:-3]
    else:
        report_base = report_name

    if not target.exists() or not target.is_dir():
        print(f"[!] Target directory not found: {target}")
        print("Usage: python android_security_scanner.py <target_directory> [output_report_name]")
        return 2
    scanner = AndroidSecurityScanner(target)
    scanner.scan_manifest()
    scanner.scan_source()
    result = scanner.result()
    print(f"\nAndroid Static Security Scan — {result['target']}")
    print(f"Findings: {result['total_findings']}")
    for severity in SEVERITIES:
        print(f"  {severity}: {result['severity_counts'][severity]}")
    for item in result["findings"]:
        print(f"\n[{item['severity']}] {item['id']} {item['title']}")
        print(f"  Location: {item['file']}:{item['line']}")
        print(f"  Evidence: {item['evidence']}")
        print(f"  Why it matters: {item['description']}")
        print(f"  Recommended fix: {item['remediation']}")
    out_json = Path(f"{report_base}.json")
    out_md = Path(f"{report_base}.md")
    out_json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    with out_md.open("w", encoding="utf-8") as f:
        f.write(f"# Android Static Security Scan Report ({report_base})\n\n")
        f.write(f"- **Target:** `{result['target']}`\n- **Generated (UTC):** {result['generated_at_utc']}\n")
        f.write(f"- **Total findings:** {result['total_findings']}\n\n")
        f.write("> Pattern-based triage only. Validate findings manually; no findings does not prove security.\n\n")
        f.write("## Severity summary\n\n| Severity | Count |\n|---|---:|\n")
        for s in SEVERITIES:
            f.write(f"| {s} | {result['severity_counts'][s]} |\n")
        f.write("\n## Findings\n\n")
        for item in result["findings"]:
            f.write(f"### {item['id']} — {item['title']} ({item['severity']})\n\n")
            f.write(f"- **Category:** {item['category']}\n- **Location:** `{item['file']}:{item['line']}`\n")
            f.write(f"- **Evidence:** `{item['evidence'].replace('`', '')}`\n- **Why it matters:** {item['description']}\n")
            f.write(f"- **Recommended fix:** {item['remediation']}\n\n")
    print(f"\n[+] Wrote {out_json.resolve()} and {out_md.resolve()}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
