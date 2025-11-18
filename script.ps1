Write-Host "`n=== DFIR: Suspicious Network Activity Since Last Boot (SRUM Direct) ===`n"

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

$sruPath = "C:\Windows\System32\sru\SRUDB.dat"
$tempCopy = "$env:TEMP\SRUDB_copy.dat"

try { Copy-Item -Path $sruPath -Destination $tempCopy -Force -ErrorAction Stop } 
catch { Write-Host "Failed to copy SRUDB.dat. Run PowerShell as Administrator." -ForegroundColor Red; return }

Add-Type -AssemblyName "System.Data"

function Read-SrumTable {
    param($dbPath, $tableName)
    $connection = New-Object -ComObject ADODB.Connection
    $recordset = New-Object -ComObject ADODB.Recordset
    $connStr = "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=$dbPath;Extended Properties='Text;HDR=No;FMT=Delimited';"
    try { $connection.Open($connStr); $recordset.Open("SELECT * FROM [$tableName]", $connection) } 
    catch { Write-Host "Failed to read table $tableName from SRUDB." -ForegroundColor Red; return @() }
    $results = @()
    while (-not $recordset.EOF) {
        $row = @{}
        for ($i=0; $i -lt $recordset.Fields.Count; $i++) { $row[$recordset.Fields.Item($i).Name] = $recordset.Fields.Item($i).Value }
        $results += $row
        $recordset.MoveNext()
    }
    $recordset.Close()
    $connection.Close()
    return $results
}

$networkEntries = Read-SrumTable -dbPath $tempCopy -tableName "NetworkUsage"

$events = @()
foreach ($entry in $networkEntries) {
    try {
        $ts = [datetime]::FromFileTimeUtc([int64]$entry["Timestamp"])
        if ($ts -lt $boot) { continue }
        $bytesIn = [int64]$entry["BytesReceived"]
        $bytesOut = [int64]$entry["BytesSent"]
        $appId = $entry["AppId"]
        $image = $null
        if ($appId) {
            try {
                $installPath = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\Repository\Families" -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -like "*$appId*" } |
                    ForEach-Object { (Get-ItemProperty -Path $_.PSPath -Name InstallLocation -ErrorAction SilentlyContinue).InstallLocation } |
                    Select-Object -First 1
                if ($installPath) {
                    $exe = Get-ChildItem -Path $installPath -Filter *.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($exe) { $image = $exe.FullName }
                }
            } catch {}
        }
        $events += [pscustomobject]@{
            TimeCreated = $ts
            Image       = $image
            BytesOut    = $bytesOut
            BytesIn     = $bytesIn
            Destination = "SRUM Historical Entry"
        }
    } catch {}
}

Write-Host "[+] Loaded" $events.Count "SRUM network usage records since boot.`n"

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

Write-Host "`n=== Suspicious Findings (SRUM Direct) ===`n"
$results | Format-Table -AutoSize
$results | Export-Csv "$env:USERPROFILE\Desktop\Suspicious_Network_Activity_SRUM.csv" -NoTypeInformation
Write-Host "`nReport saved to Desktop as 'Suspicious_Network_Activity_SRUM.csv'"
Write-Host "Done.`n"
