# Android Application Static Security Analyzer (PowerShell Native)
# OWASP Mobile Top 5 & MASVS Vulnerability Assessment
Write-Host "`n===========================================================================" -ForegroundColor Cyan
Write-Host "  ANDROID SECURITY ASSESSMENT - STATIC SCANNER (OWASP MASVS)" -ForegroundColor Yellow
Write-Host "===========================================================================" -ForegroundColor Cyan
Write-Host "[*] Scanning Android Manifest and source files...`n" -ForegroundColor Gray

$findings = @()

# 1. Scan AndroidManifest.xml
$manifest = Get-ChildItem -Path . -Recurse -Filter "AndroidManifest.xml" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($manifest) {
    $content = Get-Content $manifest.FullName -Raw
    
    if ($content -match 'android:debuggable\s*=\s*"true"') {
        $findings += [PSCustomObject]@{
            Severity = "High"
            Category = "M1 - Platform Usage"
            Title = "Application is Debuggable"
            File = $manifest.Name
            Line = "Manifest"
            Fix = "Set android:debuggable=`"false`" in release builds."
        }
    }
    if ($content -match 'android:allowBackup\s*=\s*"true"') {
        $findings += [PSCustomObject]@{
            Severity = "Medium"
            Category = "M2 - Insecure Storage"
            Title = "Application Allows Data Backup"
            File = $manifest.Name
            Line = "Manifest"
            Fix = "Set android:allowBackup=`"false`" to stop ADB backup extraction."
        }
    }
    if ($content -match 'android:usesCleartextTraffic\s*=\s*"true"') {
        $findings += [PSCustomObject]@{
            Severity = "Critical"
            Category = "M3 - Insecure Comm."
            Title = "Cleartext HTTP Traffic Permitted"
            File = $manifest.Name
            Line = "Manifest"
            Fix = "Set usesCleartextTraffic=`"false`" and enforce HTTPS via TLS 1.3."
        }
    }
    if ($content -match '<activity[^>]+android:name="\.AdminPanel"[^>]+android:exported="true"') {
        $findings += [PSCustomObject]@{
            Severity = "Medium"
            Category = "M1 - Platform Usage"
            Title = "Exported Admin Activity (.AdminPanel)"
            File = $manifest.Name
            Line = "Manifest"
            Fix = "Set android:exported=`"false`" to block unauthorized access."
        }
    }
}

# 2. Scan Java Source Code
$javaFiles = Get-ChildItem -Path . -Recurse -Include *.java,*.kt -ErrorAction SilentlyContinue
foreach ($file in $javaFiles) {
    $lines = Get-Content $file.FullName
    $lineNum = 1
    foreach ($line in $lines) {
        if ($line -match 'equals\("admin"\)') {
            $findings += [PSCustomObject]@{
                Severity = "Critical"
                Category = "M4 - Authentication"
                Title = "Hardcoded Admin Credentials in Logic"
                File = $file.Name
                Line = "Line $lineNum"
                Fix = "Authenticate against secure backend API. Remove hardcoded strings."
            }
        }
        if ($line -match 'MessageDigest\.getInstance\("MD5"\)') {
            $findings += [PSCustomObject]@{
                Severity = "High"
                Category = "M5 - Cryptography"
                Title = "Insecure MD5 Hash Algorithm Used"
                File = $file.Name
                Line = "Line $lineNum"
                Fix = "Replace MD5 with SHA-256 or bcrypt/Argon2."
            }
        }
        if ($line -match 'STATIC_KEY\s*=\s*"1234567890123456"') {
            $findings += [PSCustomObject]@{
                Severity = "High"
                Category = "M5 - Cryptography"
                Title = "Hardcoded Symmetric Encryption Key"
                File = $file.Name
                Line = "Line $lineNum"
                Fix = "Generate random keys and protect with Android KeyStore."
            }
        }
        if ($line -match 'Log\.d\(.*password') {
            $findings += [PSCustomObject]@{
                Severity = "Medium"
                Category = "M2 - Insecure Storage"
                Title = "Sensitive Credentials Leaked in Logcat"
                File = $file.Name
                Line = "Line $lineNum"
                Fix = "Remove sensitive logging in production builds."
            }
        }
        if ($line -match 'http://') {
            $findings += [PSCustomObject]@{
                Severity = "Medium"
                Category = "M3 - Insecure Comm."
                Title = "Unencrypted HTTP URL Endpoint"
                File = $file.Name
                Line = "Line $lineNum"
                Fix = "Use https:// endpoints exclusively."
            }
        }
        $lineNum++
    }
}

# 3. Print Results
$id = 1
foreach ($f in $findings) {
    $color = "Green"
    if ($f.Severity -eq "Critical") { $color = "Red" }
    elseif ($f.Severity -eq "High") { $color = "Magenta" }
    elseif ($f.Severity -eq "Medium") { $color = "Yellow" }
    
    Write-Host "#$id [$($f.Severity)] $($f.Title)" -ForegroundColor $color
    Write-Host "    Category    : $($f.Category)" -ForegroundColor Gray
    Write-Host "    File / Line : $($f.File) ($($f.Line))" -ForegroundColor Gray
    Write-Host "    Remediation : $($f.Fix)`n" -ForegroundColor White
    $id++
}

Write-Host "---------------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "SCAN COMPLETE: $($findings.Count) Vulnerabilities Identified" -ForegroundColor Green
Write-Host "  Critical: $(($findings | Where-Object {$_.Severity -eq 'Critical'}).Count) | High: $(($findings | Where-Object {$_.Severity -eq 'High'}).Count) | Medium: $(($findings | Where-Object {$_.Severity -eq 'Medium'}).Count)" -ForegroundColor Yellow
Write-Host "===========================================================================`n" -ForegroundColor Cyan

# 4. Generate scan_report.md
$reportContent = "# Automated Android Security Scan Report`n`n"
$reportContent += "**Scan Target:** `target_app`  `n"
$reportContent += "**Total Findings:** $($findings.Count)`n`n"
$reportContent += "| ID | Severity | Category | Vulnerability | Location | Fix |`n"
$reportContent += "|:---|:---|:---|:---|:---|:---|`n"
$idx = 1
foreach ($f in $findings) {
    $reportContent += "| $idx | **$($f.Severity)** | $($f.Category) | $($f.Title) | `$($f.File):$($f.Line)` | $($f.Fix) |`n"
    $idx++
}
Set-Content -Path "scan_report.md" -Value $reportContent
Write-Host "[+] Generated scan_report.md successfully!" -ForegroundColor Green
