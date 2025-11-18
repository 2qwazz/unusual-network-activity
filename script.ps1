Write-Host "`n=== DFIR: Suspicious Network Activity Since Last Boot (SRUM) ===`n"

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Host "Last Boot Time:" $boot "`n"

$knownBenign = @(
    "mspaint.exe",
    "notepad.exe",
    "calc.exe",
    "explorer.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "chrome.exe",
    "firefox.exe",
    "Spotify.exe"
)

$spotifyHigh = 70000
$spotifyLow  = 45000
$thresholdBytes = 2MB
$suspiciousFolders = @("AppData", "Temp", "Downloads", "Public", "Recycle.Bin")

$sruPath = "C:\Windows\System32\sru\SRUDB.dat"
$tempCopy = "$env:TEMP\SRUDB_copy.dat"
try {
    Copy-Item -Path $sruPath -Destination $tempCopy -Force -ErrorAction Stop
} catch {
    Write-Host "Failed to copy SRUDB.dat. Run PowerShell as Administrator or ensure file exists." -ForegroundColor Red
    return
}

Add-Type -AssemblyName System.Data
$connection = $null
$dt = New-Object System.Data.DataTable

$providerStrings = @(
    "Provider=Microsoft.ACE.OLEDB.12.0;Data Source=$tempCopy;Persist Security Info=False;",
    "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$tempCopy;Persist Security Info=False;"
)

$openSuccess = $false
foreach ($ps in $providerStrings) {
    try {
        $cn = New-Object System.Data.OleDb.OleDbConnection($ps)
        $cn.Open()
        $connection = $cn
        $openSuccess = $true
        break
    } catch {}
}

if (-not $openSuccess) {
    Write-Host "Unable to open SRUDB with OLEDB providers. SRUM read failed." -ForegroundColor Red
    return
}

$schemaCmd = $connection.CreateCommand()
$schemaCmd.CommandText = "SELECT TOP 1 * FROM NetworkUsage"
$adapter = New-Object System.Data.OleDb.OleDbDataAdapter($schemaCmd)
try {
    $adapter.Fill($dt) | Out-Null
} catch {
    Write-Host "Failed to query NetworkUsage table from SRUDB." -ForegroundColor Red
    $connection.Close()
    return
}

$connection.Close()

if ($dt.Rows.Count -eq 0) {
    Write-Host "SRUM NetworkUsage table empty or not present." -ForegroundColor Yellow
}

$timeCol = $null
$bytesInCol = $null
$bytesOutCol = $null
$appIdCol = $null

foreach ($c in $dt.Columns) {
    $name = $c.ColumnName.ToLower()
    if ($name -match "time" -and -not $timeCol) { $timeCol = $c.ColumnName }
    if ($name -match "recv|recvd|bytesrec|bytes_recv" -and -not $bytesInCol) { $bytesInCol = $c.ColumnName }
    if ($name -match "sent|bytessent|bytes_sent" -and -not $bytesOutCol) { $bytesOutCol = $c.ColumnName }
    if ($name -match "appid|app_id" -and -not $appIdCol) { $appIdCol = $c.ColumnName }
}

$events = @()

foreach ($row in $dt.Rows) {
    try {
        $ts = $null
        if ($timeCol) {
            $raw = $row[$timeCol]
            if ($raw -is [DateTime]) { $ts = [DateTime]$raw }
            else {
                try { $ts = [DateTime]::Parse($raw) } catch {}
            }
        }

        if (-not $ts) { continue }
        if ($ts -lt $boot) { continue }

        $bytesIn = 0
        $bytesOut = 0
        if ($bytesInCol) { $bytesIn = [int64]($row[$bytesInCol]) }
        if ($bytesOutCol) { $bytesOut = [int64]($row[$bytesOutCol]) }

        $appId = $null
        if ($appIdCol) { $appId = $row[$appIdCol].ToString() }

        $image = $null
        if ($appId) {
            try {
                $regMatch = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModel\Repository\Families" -ErrorAction SilentlyContinue |
                    Where-Object { $_.PSChildName -like "*$appId*" } |
                    ForEach-Object {
                        try {
                            $p = Get-ItemProperty -Path ($_.PSPath) -Name InstallLocation -ErrorAction Stop
                            if ($p.InstallLocation) { return $p.InstallLocation }
                        } catch {}
                    } | Select-Object -First 1
                if ($regMatch) {
                    $exe = Get-ChildItem -Path $regMatch -Filter *.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($exe) { $image = $exe.FullName }
                }
            } catch {}
        }

        $events += [pscustomobject]@{
            TimeCreated = $ts
            Image = $image
            BytesOut = $bytesOut
            BytesIn = $bytesIn
            Destination = "SRUM Historical Entry"
        }
    } catch {}
}

Write-Host "[+] Loaded" $events.Count "SRUM network usage records since boot.`n"

$results = foreach ($e in $events) {
    $flags = @()
    $procName = if ($e.Image) { Split-Path $e.Image -Leaf } else { "Unknown" }

    if (-not $e.Image) {
        $flags += "No Process Path / Unknown Executable"
    } else {
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

Write-Host "`n=== Suspicious Findings (SRUM) ===`n"
$results | Format-Table -AutoSize
$results | Export-Csv "$env:USERPROFILE\Desktop\Suspicious_Network_Activity_SRUM.csv" -NoTypeInformation
Write-Host "`nReport saved to Desktop as 'Suspicious_Network_Activity_SRUM.csv'"
Write-Host "Done.`n"
