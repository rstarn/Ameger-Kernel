param(
    [Parameter(Mandatory = $true)][string]$Path
)

$ErrorActionPreference = 'Stop'

$noColour = ($env:AMEGER_NO_COLOR -eq '1')
$esc = [string][char]27
if ($noColour) {
    $G = ''; $E = ''; $X = ''
} else {
    $G = "$esc[92m"
    $E = "$esc[91m"
    $X = "$esc[0m"
}

if (-not (Test-Path -LiteralPath $Path)) { Write-Host "  $E[!]$X Export Strip: File Not Found: $Path"; exit 1 }

$b = [IO.File]::ReadAllBytes($Path)
$e = [BitConverter]::ToInt32($b, 0x3C)
if ([Text.Encoding]::ASCII.GetString($b, $e, 4) -ne "PE`0`0") { Write-Host "  $E[!]$X Export Strip: Not A PE"; exit 1 }

$coff = $e + 4
$opt = $coff + 20
$pe32p = ([BitConverter]::ToUInt16($b, $opt) -eq 0x20b)
$ddoff = if ($pe32p) { $opt + 112 } else { $opt + 96 }
$expRva = [BitConverter]::ToUInt32($b, $ddoff + 0)
$expSz = [BitConverter]::ToUInt32($b, $ddoff + 4)

if ($expRva -eq 0 -or $expSz -eq 0) {
    Write-Host "  $G[+]$X Export Directory Already Absent."
    exit 0
}

$secs = @()
$secBase = $opt + [BitConverter]::ToUInt16($b, $coff + 16)
$nsec = [BitConverter]::ToUInt16($b, $coff + 2)
for ($i = 0; $i -lt $nsec; $i++) {
    $o = $secBase + 40 * $i
    $secs += [pscustomobject]@{
        VA = [BitConverter]::ToUInt32($b, $o + 12)
        VS = [BitConverter]::ToUInt32($b, $o + 8)
        Ptr = [BitConverter]::ToUInt32($b, $o + 20)
        Sz = [BitConverter]::ToUInt32($b, $o + 16)
    }
}

function Convert-RvaToOffset([uint32]$rva) {
    foreach ($s in $secs) {
        $span = [Math]::Max($s.VS, $s.Sz)
        if ($rva -ge $s.VA -and $rva -lt ($s.VA + $span)) { return [int](($rva - $s.VA) + $s.Ptr) }
    }
    return -1
}

$eo = Convert-RvaToOffset $expRva
if ($eo -lt 0) { Write-Host "  $E[!]$X Export Strip: Export RVA 0x$($expRva.ToString('X')) Outside Every Section"; exit 1 }

$strings = New-Object System.Collections.Generic.List[int]
$nameRva = [BitConverter]::ToUInt32($b, $eo + 12)
if ($nameRva -ne 0) { $strings.Add((Convert-RvaToOffset $nameRva)) }
$nNames = [BitConverter]::ToUInt32($b, $eo + 24)
$anOff = Convert-RvaToOffset ([BitConverter]::ToUInt32($b, $eo + 32))
if ($nNames -gt 0 -and $anOff -ge 0) {
    if ($nNames -gt 65536) { Write-Host "  $E[!]$X Export Strip: Implausible Name Count $nNames"; exit 1 }
    for ($i = 0; $i -lt $nNames; $i++) {
        $nr = Convert-RvaToOffset ([BitConverter]::ToUInt32($b, $anOff + 4 * $i))
        if ($nr -ge 0) { $strings.Add($nr) }
    }
}

$zeroed = 0
foreach ($o in $strings) {
    if ($o -lt 0 -or $o -ge $b.Length) { continue }
    while ($o -lt $b.Length -and $b[$o] -ne 0) { $b[$o] = 0; $o++; $zeroed++ }
    if ($o -lt $b.Length) { $b[$o] = 0 }
}

$end = [Math]::Min($eo + [int]$expSz, $b.Length)
for ($o = $eo; $o -lt $end; $o++) { $b[$o] = 0 }
for ($o = $ddoff; $o -lt ($ddoff + 8); $o++) { $b[$o] = 0 }

[IO.File]::WriteAllBytes($Path, $b)

$v = [IO.File]::ReadAllBytes($Path)
$ve = [BitConverter]::ToInt32($v, 0x3C)
$vdd = if ($pe32p) { $ve + 4 + 20 + 112 } else { $ve + 4 + 20 + 96 }
$vRva = [BitConverter]::ToUInt32($v, $vdd + 0)
$vSz = [BitConverter]::ToUInt32($v, $vdd + 4)
if ($vRva -ne 0 -or $vSz -ne 0) { Write-Host "  $E[x]$X Export Strip: Data Directory Still Set"; exit 1 }
if ([Text.Encoding]::ASCII.GetString($v).Contains('ManualEntry')) { Write-Host "  $E[x]$X Export Strip: ManualEntry Still Present"; exit 1 }

Write-Host "  $G[+]$X Export Directory Stripped ($G$zeroed$X Name Byte(s) Zeroed, Directory Cleared)."
exit 0
