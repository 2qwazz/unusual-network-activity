Write-Host "`n=== DFIR: Suspicious Network Activity Since Last Boot ===`n"

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
    "firefox.exe"
)

$thresholdBytes = 2MB

function Get-NetworkEvents {

    $sysEvents = Get-WinEvent -FilterHashtable @{
        ProviderName = "Microsoft-Windows-Sysmon"
        Id = 3
        StartTime = $boot
    } -ErrorAction SilentlyContinue

    $netData = @()

    if ($sysEvents) {
        Write-Host "[+] Sysmon network events found.`n"

        foreach ($ev in $sysEvents) {
            $xml = [xml]$ev.ToXml()

            $netData += [pscustomobject]@{
                TimeCreated   = $ev.TimeCreated
                Image         = $xml.Event.EventData.Data[0].'#text'
                DestinationIp = $xml.Event.EventData.Data[3].'#text'
                DestinationPort = $xml.Event.EventData.Data[4].'#text'
                Protocol      = $xml.Event.EventData.Data[5].'#text'
                BytesOut      = $xml.Event.EventData.Data[10].'#text'
                BytesIn       = $xml.Event.EventData.Data[11].'#text'
            }
        }

        return $netData
    }

    Write-Host "[!] Sysmon not found. Using Get-NetTCPConnection.`n"

    Get-NetTCPConnection | ForEach-Object {
        try {
            $proc = Get-Process -Id $_.OwningProcess -ErrorAction Stop
            $exe = $proc.Path
        } catch {
            $exe = $null
        }

        [pscustomobject]@{
            TimeCreated   = (Get-Date)
            Image         = $exe
            DestinationIp = $_.RemoteAddress
            DestinationPort = $_.RemotePort
            Protocol      = "TCP"
            BytesOut      = 0
            BytesIn       = 0
        }
    }
}

$events = Get-NetworkEvents
Write-Host "[+] Found" $events.Count "network connection events since boot.`n"

$suspiciousFolders = @("AppData", "Temp", "Downloads", "Public", "Recycle.Bin")

$results = foreach ($e in $events) {

    if (-not $e.Image) { continue }

    $flags = @()

    $sig = Get-AuthenticodeSignature $e.Image -ErrorAction SilentlyContinue
    if ($sig.Status -ne "Valid") {
        $flags += "Unsigned Executable"
    }

    foreach ($f in $suspiciousFolders) {
        if ($e.Image -like "*$f*") {
            $flags += "Suspicious Directory ($f)"
        }
    }

    try {
        $file = Get-Item $e.Image -ErrorAction Stop
        if ($file.CreationTime -gt $boot) {
            $flags += "New File Since Boot"
        }
    } catch {}

    if ($e.BytesOut -gt $thresholdBytes -or $e.BytesIn -gt $thresholdBytes) {
        $flags += "Excessive Network Traffic"
    }

    $procName = Split-Path $e.Image -Leaf
    if ($knownBenign -contains $procName) {
        if ($e.BytesOut -gt $thresholdBytes -or $e.BytesIn -gt $thresholdBytes) {
            $flags += "Benign App Using Excessive Traffic"
        }
    }

    if ($flags.Count -gt 0) {
        [pscustomobject]@{
            Time        = $e.TimeCreated
            Process     = $e.Image
            Destination = "$($e.DestinationIp):$($e.DestinationPort)"
            BytesOut    = $e.BytesOut
            BytesIn     = $e.BytesIn
            Flags       = $flags -join ", "
        }
    }
}

Write-Host "`n=== Suspicious Findings ===`n"
$results | Format-Table -AutoSize

$results | Export-Csv "$env:USERPROFILE\Desktop\Suspicious_Network_Activity.csv" -NoTypeInformation

Write-Host "`nReport saved to Desktop as 'Suspicious_Network_Activity.csv'"
Write-Host "Done.`n"
