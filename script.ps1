Write-Host "`n=== DFIR: Suspicious Network Activity Since Last Boot (CSV) ===`n"

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Host "Last Boot Time:" $boot "`n"

$alwaysLog = @("calc.exe","mspaint.exe","vscode.exe","node.exe")
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
        $ts = [datetime]::Parse($row.Timestamp)
        if ($ts -lt $boot) { continue }

        $image = $row.'Exe Info'
        if (-not $image -and -not ($alwaysLog -contains $image)) { continue }

        $events += [pscustomobject]@{
            TimeCreated = $ts
            Image       = $image
            BytesOut    = [int64]$row.'Bytes Sent'
            BytesIn     = [int64]$row.'Bytes Received'
            Destination = "SRUM NetworkUsage Entry"
        }
    } catch {}
}

Write-Host "[+] Loaded" $events.Count "NetworkUsage records since boot.`n"

$results = foreach ($e in $events) {
    $procName = if ($e.Image) { $e.Image } else { "Unknown" }
    if ($procName -ieq "svchost.exe") { continue }

    [pscustomobject]@{
        Time        = $e.TimeCreated
        Process     = $procName
        Destination = $e.Destination
        BytesOut    = $e.BytesOut
        BytesIn     = $e.BytesIn
        Flags       = if ($alwaysLog -contains $procName) { "Always Logged Process" } else { "" }
    }
}

Write-Host "`n=== Suspicious Findings (CSV) ===`n"
$results | Format-Table -AutoSize
$results | Export-Csv "$env:USERPROFILE\Desktop\Suspicious_Network_Activity_CSV.csv" -NoTypeInformation
Write-Host "`nReport saved to Desktop as 'Suspicious_Network_Activity_CSV.csv'"
Write-Host "Done.`n"
