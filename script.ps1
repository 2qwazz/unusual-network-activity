Write-Host "`n=== DFIR: Suspicious Network Activity (CSV) ===`n"

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
        $ts = if ($row.TimeCreated) { [datetime]::Parse($row.TimeCreated) } else { $null }
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

Write-Host "[+] Loaded" $events.Count "NetworkUsage records.`n"

$results = foreach ($e in $events) {
    [pscustomobject]@{
        Time        = $e.TimeCreated
        Process     = if ($e.Image) { $e.Image } else { "Unknown" }
        Destination = $e.Destination
        BytesOut    = $e.BytesOut
        BytesIn     = $e.BytesIn
        Flags       = ""
    }
}

Write-Host "`n=== All Network Usage Events ===`n"
$results | Format-Table -AutoSize
$results | Export-Csv "$env:USERPROFILE\Desktop\Suspicious_Network_Activity_CSV.csv" -NoTypeInformation
Write-Host "`nReport saved to Desktop as 'Suspicious_Network_Activity_CSV.csv'"
Write-Host "Done.`n"
