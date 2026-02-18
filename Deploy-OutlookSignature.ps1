param(
    [string]$BaseUrl      = "https://raw.githubusercontent.com/ebenaviv/enav/refs/heads/HTML_LinkedImages/",
    [string]$SigFolderName = "EnavSignature",
    [switch]$VerboseLog
)

# --- 0. Security & Paths ---

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$localSigPath    = Join-Path $env:APPDATA "Microsoft\Signatures"
$localAssetsPath = Join-Path $localSigPath "SignatureAssets"
$logFolder       = Join-Path $localSigPath "Logs"
$logFile         = Join-Path $logFolder ("SignatureDeploy_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))

# Create folders quietly
$null = New-Item -ItemType Directory -Path $localSigPath, $localAssetsPath, $logFolder -Force

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] [$env:USERNAME] $Message"
    Add-Content -Path $logFile -Value $line
    if ($VerboseLog) { Write-Host $line }
}

Write-Log "=== Signature deployment started ==="

# Cleanup old logs (older than 30 days)
Get-ChildItem -Path $logFolder -Filter "*.log" -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

# --- 1. Write permissions check (Extended) ---

foreach ($path in @($localSigPath, $localAssetsPath)) {
    try {
        $testFile = Join-Path $path "write_test.tmp"
        "test" | Out-File -FilePath $testFile -ErrorAction Stop
        Remove-Item $testFile -Force
    } catch {
        Write-Log "No write permissions to $path. Aborting." "ERROR"
        exit 1
    }
}

# --- 2. Clean old signatures ---

Write-Log "Cleaning old signature files..."
Get-ChildItem -Path $localSigPath -Filter "$SigFolderName*" -ErrorAction SilentlyContinue |
    Remove-Item -Force -ErrorAction SilentlyContinue

# --- 3. Smart download (BITS + fallback) ---

$filesToDownload = @("signature_template1.htm", "signature_template1.csv", "banner.jpg", "enav.gif", "facebook.png", "instagram.png", "linkedin.png", "youtube.png")

foreach ($file in $filesToDownload) {
    $dest = Join-Path $localAssetsPath $file
    $shouldDownload = $true

    if (Test-Path $dest) {
        if ((Get-Item $dest).LastWriteTime -gt (Get-Date).AddHours(-24)) {
            Write-Log "Skipping download for $file (fresh copy exists)"
            $shouldDownload = $false
        }
    }

    if ($shouldDownload) {
        try {
            Write-Log "Downloading $file via BITS..."
            Start-BitsTransfer -Source "$BaseUrl/$file" -Destination $dest -Priority High -ErrorAction Stop
        } catch {
            Write-Log "BITS failed for $file, trying Invoke-WebRequest..." "WARN"
            try {
                Invoke-WebRequest -Uri "$BaseUrl/$file" -OutFile $dest -TimeoutSec 15 -ErrorAction Stop
            } catch {
                Write-Log "Failed to download $file. $_" "ERROR"
            }
        }
    }
}

# Validate files
$csvPath      = Join-Path $localAssetsPath "signature_template1.csv"
$templatePath = Join-Path $localAssetsPath "signature_template1.htm"

if (!(Test-Path $csvPath) -or (Get-Item $csvPath).Length -lt 10) {
    Write-Log "CSV missing or corrupted at $csvPath." "ERROR"
    exit 1
}
if (!(Test-Path $templatePath) -or (Get-Item $templatePath).Length -lt 50) {
    Write-Log "Template missing or corrupted at $templatePath." "ERROR"
    exit 1
}

Write-Log "CSV file validated: $csvPath"
Write-Log "Template file validated: $templatePath"

# --- 4. User resolution (Extended AD / Cloud / Office / whoami) ---

$currentUserEmail = ""

# 1: AD Searcher
try {
    $searcher = [adsisearcher]"(samaccountname=$env:USERNAME)"
    $result = $searcher.FindOne()
    if ($result) {
        $mail = $result.Properties["mail"]
        if ($mail -and $mail[0]) {
            $currentUserEmail = $mail[0]
            Write-Log "Resolved via AD Searcher: $currentUserEmail"
        }
    }
} catch {}

# 2: Cloud Join
if ([string]::IsNullOrWhiteSpace($currentUserEmail)) {
    try {
        $cloudJoin = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo\*" -ErrorAction SilentlyContinue
        if ($cloudJoin.UserEmail) {
            $currentUserEmail = $cloudJoin.UserEmail
            Write-Log "Resolved via CloudDomainJoin: $currentUserEmail"
        }
    } catch {}
}

# 3: Office Identity
if ([string]::IsNullOrWhiteSpace($currentUserEmail)) {
    try {
        $currentUserEmail = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\Identity" -Name "DefaultEmailAddress" -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty DefaultEmailAddress
        if ($currentUserEmail) { Write-Log "Resolved via Office Identity Registry: $currentUserEmail" }
    } catch {}
}

# 4: whoami
if ([string]::IsNullOrWhiteSpace($currentUserEmail)) {
    try {
        $currentUserEmail = (whoami /upn)
        Write-Log "Resolved via whoami: $currentUserEmail"
    } catch {}
}

if ([string]::IsNullOrWhiteSpace($currentUserEmail)) {
    Write-Log "Could not resolve user email. Aborting." "ERROR"
    exit 1
}

$currentUserEmail = $currentUserEmail.Trim().ToLower()
Write-Log "Final resolved user email: $currentUserEmail"

# --- 5. CSV hash & change detection ---

$hashFilePath = Join-Path $localAssetsPath "csv_hash.txt"
$currentHash  = (Get-FileHash -Path $csvPath -Algorithm MD5).Hash
$previousHash = if (Test-Path $hashFilePath) { Get-Content $hashFilePath } else { "" }
$sigFilePath  = Join-Path $localSigPath ("{0}.htm" -f $SigFolderName)
$txtFilePath  = Join-Path $localSigPath ("{0}.txt" -f $SigFolderName)

if ((Test-Path $sigFilePath) -and ($currentHash -eq $previousHash)) {
    Write-Log "No changes detected in CSV and signature exists. Exiting."
    exit 0
}

# --- 6. CSV parsing & validation ---

$rawCsv = Import-Csv -Path $csvPath -Encoding UTF8

if (-not $rawCsv -or $rawCsv.Count -eq 0) {
    Write-Log "CSV is empty or unreadable." "ERROR"
    exit 1
}

$requiredColumns = @("fullName", "jobTitle", "email")
$missingColumns = $requiredColumns | Where-Object { $_ -notin $rawCsv[0].PSObject.Properties.Name }

if ($missingColumns) {
    $errorMsg = "CSV is missing required columns: $($missingColumns -join ', ')"
    Write-Log $errorMsg "ERROR"
    exit 1
}

$employeeData = $rawCsv | Where-Object { $_.email -and $_.email.ToLower().Trim() -eq $currentUserEmail }

if (-not $employeeData) {
    Write-Log "User [$currentUserEmail] not found in CSV. Aborting." "ERROR"
    exit 1
}

foreach ($col in $requiredColumns) {
    if ([string]::IsNullOrWhiteSpace($employeeData.$col)) {
        Write-Log "Required field [$col] is empty for user [$currentUserEmail]. Aborting." "ERROR"
        exit 1
    }
}

# --- 7. Template processing (HTML + Plain Text) ---

$htmlContent = Get-Content -Path $templatePath -Raw -Encoding UTF8

if ($htmlContent.Length -lt 50) {
    Write-Log "HTML template appears empty or corrupted." "ERROR"
    exit 1
}

$replacements = @{
    "{{fullName}}" = $employeeData.fullName
    "{{jobTitle}}" = $employeeData.jobTitle
    "{{email}}"    = $employeeData.email
}

foreach ($key in $replacements.Keys) {
    $htmlContent = $htmlContent.Replace($key, $replacements[$key])
    Write-Log "Replaced placeholder $key"
}

# --- NEW: Validate HTML after replacements ---
if ($htmlContent -match "{{.*}}") {
    Write-Log "HTML still contains unresolved placeholders. Aborting." "ERROR"
    exit 1
}

# Plain text version
$plainTextContent = @(
    $employeeData.fullName
    $employeeData.jobTitle
    $employeeData.email
) -join [Environment]::NewLine

# Save with UTF-8 with BOM
try {
    $Utf8BomEncoding = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($sigFilePath, $htmlContent, $Utf8BomEncoding)
    [System.IO.File]::WriteAllText($txtFilePath, $plainTextContent, $Utf8BomEncoding)
    $currentHash | Out-File -FilePath $hashFilePath -Encoding utf8 -Force
    Write-Log "Signature files (HTML + TXT) created successfully."
} catch {
    Write-Log "Failed to write signature files: $_" "ERROR"
    exit 1
}

# --- 8. Set default signature (COM + Registry Binary Fallback + Roaming Fix) ---

Write-Log "Starting signature assignment..."

# 8a. Disable Outlook Roaming Signatures (Must be done first)
try {
    $setupPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Setup"
    if (!(Test-Path $setupPath)) { New-Item -Path $setupPath -Force | Out-Null }
    Set-ItemProperty -Path $setupPath -Name "DisableRoamingSignaturesTemporaryToggle" -Value 1 -Type DWord
    Write-Log "Roaming signatures disabled."
} catch {
    Write-Log "Failed to disable roaming signatures: $_" "WARN"
}

# 8b. Try setting via COM Object (Works best if Outlook is installed/open)
$comSucceeded = $false
try {
    $outlook = New-Object -ComObject Outlook.Application -ErrorAction Stop
    $signatureObject = $outlook.GetNamespace("MAPI").SignatureObject # אובייקט חתימות פנימי
    # הערה: COM לפעמים מוגבל בגרסאות מסוימות, לכן נמשיך ל-Registry בכל מקרה לביטחון
    $comSucceeded = $true
    Write-Log "Outlook COM object initialized (Assignment via Registry will follow for persistence)."
} catch {
    Write-Log "Outlook COM initialization skipped/failed (normal for silent deploy)."
}

# 8c. Registry Binary Assignment (The most reliable Enterprise method)
try {
    $OutlookBaseRegPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook"
    $profileName = (Get-ItemProperty -Path $OutlookBaseRegPath -ErrorAction SilentlyContinue).DefaultProfile
    
    if ($profileName) {
        Write-Log "Updating Registry for profile: $profileName"
        $sigKeyPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\$profileName\9375CFF0413111d3B88A00104B2A6676"
        $subKeys = Get-ChildItem -Path $sigKeyPath -ErrorAction SilentlyContinue
        
        # המרת שם החתימה לפורמט בינארי (UTF-16LE + Null Terminator)
        $sigNameBytes = [System.Text.Encoding]::Unicode.GetBytes($SigFolderName + "`0")

        foreach ($key in $subKeys) {
            # בדיקה אם המפתח מכיל הגדרות חשבון מייל
            $hasNew = Get-ItemProperty -Path $key.PSPath -Name "New Signature" -ErrorAction SilentlyContinue
            $hasReply = Get-ItemProperty -Path $key.PSPath -Name "Reply-Forward Signature" -ErrorAction SilentlyContinue
            
            if ($null -ne $hasNew) {
                Set-ItemProperty -Path $key.PSPath -Name "New Signature" -Value $sigNameBytes -Force
                Write-Log "Set 'New Signature' in $($key.PSChildName)"
            }
            if ($null -ne $hasReply) {
                Set-ItemProperty -Path $key.PSPath -Name "Reply-Forward Signature" -Value $sigNameBytes -Force
                Write-Log "Set 'Reply-Forward Signature' in $($key.PSChildName)"
            }
        }
        Write-Log "Registry binary update completed successfully."
    } else {
        Write-Log "No default Outlook profile found." "WARN"
    }
} catch {
    Write-Log "Registry assignment failed: $_" "ERROR"
}

Write-Log "=== Deployment Completed Successfully ==="

exit 0







