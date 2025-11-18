Write-Host "`n=== DFIR: Suspicious Network Activity Since Last Boot (CSV) ===`n"

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Host "Last Boot Time:" $boot "`n"

$knownBenign = @(
    "mspaint.exe","notepad.exe","calc.exe","explorer.exe",
    "winword.exe","excel.exe","powerpnt.exe","chrome.exe",
    "firefox.exe","Spotify.exe"
)

$spotifyHigh = 70000
$spotifyLow  = 45000
$thresholdBytes = 2MB
$suspiciousFolders = @("AppData","Temp","Downloads","Public","Recycle.Bin")

$csvFolder = "$env:USERPROFILE\Desktop\SRUM_Network.csv"

if (-not (Test-Path $csvFolder)) {
    Write-Host "Folder 'SRUM_Network.csv' not found on Desktop." -ForegroundColor Red
    return
}

$csvFiles = Get-ChildItem -Path $csvFolder -Filter *.csv

if ($csvFiles.Count -eq 0) {
    Write-Host "No CSV files found in folder 'SRUM_Network.csv'." -ForegroundColor Red
    return
}

$csvPath = $csvFiles[0].FullName
Write-Host "[+] Using CSV file:" $csvPath "`n"

$rawEvents = Import-Csv $csvPath

$events = @()
foreach ($row in $rawEvents) {
    try {
        $ts = [datetime]::Parse($row.TimeCreated)
        if ($ts -lt $boot) { continue }

        $bytesIn = if ($row.BytesIn) { [int64]$row.BytesIn } else { 0 }
        $bytesOut = if ($row.BytesOut) { [int64]$row.BytesOut } else { 0 }
        $image = if ($row.ExecutablePath) { $row.ExecutablePath } else { $null }

        $events += [pscustomobject]@{
            TimeCreated = $ts
            Image       = $image
            BytesOut    = $bytesOut
            BytesIn     = $bytesIn
            Destination = "SRUM NetworkUsage Entry"
        }
    } catch {}
}

Write-Host "[+] Loaded" $events.Count "NetworkUsage records since boot.`n"

$results = foreach ($e in $events) {
    $flags = @()
    $procName = if ($e.Image) { Split-Path $e.Image -Leaf } else { "Unknown" }

    if (-not $e.Image) { $flags += "No Process Path / Unknown Executable" }
    else {
        try {
            if (Test-Path $e.Image) {
                $sig = Get-AuthenticodeSignature $e.Image -ErrorAction Stop
                if ($sig.Status -ne "Valid") { $flags += "Unsigned Executable" }
            }
        } catch {}
    }

    foreach ($f in $suspiciousFolders) {
        if ($e.Image -and ($e.Image -like "*$f*")) { $flags += "Suspicious Directory ($f)" }
    }

    try {
        if ($e.Image -and (Test-Path $e.Image)) {
            $file = Get-Item $e.Image -ErrorAction Stop
            if ($file.CreationTime -gt $boot) { $flags += "New File Since Boot" }
        }
    } catch {}

    if ($e.BytesOut -gt $thresholdBytes -or $e.BytesIn -gt $thresholdBytes) { $flags += "Excessive Network Traffic" }

    if ($procName -ieq "Spotify.exe") {
        if ($e.BytesIn -gt $spotifyHigh -or $e.BytesOut -gt $spotifyHigh) { $flags += "Spotify Traffic Above Normal Range" }
        if ($e.BytesIn -lt $spotifyLow -or $e.BytesOut -lt $spotifyLow) { $flags += "Spotify Traffic Below Normal Range" }
    }

    if ($knownBenign -contains $procName) {
        if ($e.BytesOut -gt $thresholdBytes -or $e.BytesIn -gt $thresholdBytes) { $flags += "Benign App Using Excessive Traffic" }
    }

    if ($flags.Count -gt 0) {
        [pscustomobject]@{
            Time        = $e.TimeCreated
            Process     = if ($e.Image) { $e.Image } else { "Unknown" }
            Destination = $e.Destination
            BytesOut    = $e.BytesOut
            BytesIn     = $e.BytesIn
            Flags       = $flags -join ", "
        }
    }
}

Write-Host "`n=== Suspicious Findings (CSV) ===`n"
$results | Format-Table -AutoSize
$results | Export-Csv "$env:USERPROFILE\Desktop\Suspicious_Network_Activity_CSV.csv" -NoTypeInformation
Write-Host "`nReport saved to Desktop as 'Suspicious_Network_Activity_CSV.csv'"
Write-Host "Done.`n"
