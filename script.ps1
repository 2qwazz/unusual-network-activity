Write-Host "`n=== DFIR: Network Usage Since Last Boot (CSV) ===`n"

$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
Write-Host "Last Boot Time:" $boot "`n"

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
        if ($ts -ge $boot) {
            $events += $row
        }
    } catch {}
}

Write-Host "[+] Loaded" $events.Count "records since boot.`n"

$outputPath = "$env:USERPROFILE\Desktop\SRUM_Network_Recent.csv"
$events | Export-Csv $outputPath -NoTypeInformation

Write-Host "`nFiltered report saved to Desktop as 'SRUM_Network_Recent.csv'"
Write-Host "Done.`n"
