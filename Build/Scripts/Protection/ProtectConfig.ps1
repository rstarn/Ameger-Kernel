param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Destination,

    [string]$PinPayload,

    [string]$PayloadName,

    [string]$RuntimeName,

    [string]$ExportMap,

    [string]$DllDir,

    [string]$TestTarget,

    [string]$ConfigMagic
)

$ErrorActionPreference = "Stop"
if ([string]::IsNullOrEmpty($ConfigMagic)) {
    foreach ($p in @($Destination, $Source)) {
        if (-not [string]::IsNullOrEmpty($ConfigMagic)) { break }
        if (Test-Path -LiteralPath $p) {
            $probe = [IO.File]::ReadAllBytes($p)
            if ($probe.Length -gt 8) {
                $head = [Text.Encoding]::ASCII.GetString($probe, 0, 8)
                if ($head -match '^[A-Za-z0-9]{8}$') { $ConfigMagic = $head }
            }
        }
    }
    if ([string]::IsNullOrEmpty($ConfigMagic)) {
        Write-Host "ProtectConfig: No Config Magic Supplied And Neither File Carries One; Refusing A Static Fallback"
        exit 1
    }
}
if ($ConfigMagic -notmatch '^[A-Za-z0-9]{8}$') {
    Write-Host "ProtectConfig: Config Magic Must Be 8 ASCII Alphanumerics"
    exit 1
}
$magic = [Text.Encoding]::ASCII.GetBytes($ConfigMagic)

function Read-ConfigText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = [IO.File]::ReadAllBytes($Path)
    $enc = $false
    if ($raw.Length -gt $magic.Length) {
        $enc = $true
        for ($i = 0; $i -lt $magic.Length; $i++) {
            if ($raw[$i] -ne $magic[$i]) { $enc = $false; break }
        }
    }
    if ($enc) {
        Add-Type -AssemblyName System.Security | Out-Null
        $blob = New-Object byte[] ($raw.Length - $magic.Length)
        [Array]::Copy($raw, $magic.Length, $blob, 0, $blob.Length)
        $plainBytes = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
        return [Text.Encoding]::UTF8.GetString($plainBytes)
    }
    return [Text.Encoding]::UTF8.GetString($raw)
}

function Get-IniValue([string]$Text, [string]$Key) {
    if ($null -eq $Text) { return $null }
    foreach ($line in [regex]::Split($Text, "\r?\n")) {
        $trimmed = $line.Trim()
        if ($trimmed.Length -eq 0 -or $trimmed.StartsWith(";") -or $trimmed.StartsWith("#")) { continue }
        $eq = $trimmed.IndexOf("=")
        if ($eq -lt 1) { continue }
        if ($trimmed.Substring(0, $eq).Trim() -ieq $Key) { return $trimmed.Substring($eq + 1).Trim() }
    }
    return $null
}

function Set-IniKeys([string]$Text, $Pairs) {
    $order = @("PayloadName", "RuntimeName", "ExportMap", "DllDir", "TestTarget")
    $rx = '^\s*(PayloadName|RuntimeName|ExportMap|DllDir|TestTarget)\s*='
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($line in [regex]::Split($Text, "\r?\n")) {
        if ($line -match $rx) { continue }
        $lines.Add($line)
    }

    $insert = New-Object System.Collections.Generic.List[string]
    foreach ($k in $order) {
        if ($Pairs.ContainsKey($k) -and -not [string]::IsNullOrEmpty($Pairs[$k])) {
            $insert.Add($k + " = " + $Pairs[$k])
        }
    }
    if ($insert.Count -eq 0) { return ($lines -join "`r`n") }

    $anchor = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*PayloadSha256\s*=') { $anchor = $i; break }
    }
    if ($anchor -lt 0) {
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i].Trim() -ieq "[General]") { $anchor = $i; break }
        }
    }
    if ($anchor -lt 0) {

        $lines.Insert(0, "")
        $lines.Insert(0, "[General]")
        $anchor = 0
    }

    for ($j = 0; $j -lt $insert.Count; $j++) {
        $lines.Insert($anchor + 1 + $j, $insert[$j])
    }
    return ($lines -join "`r`n")
}

if (-not (Test-Path -LiteralPath $Source)) { Write-Host "ProtectConfig: Source Not Found: $Source"; exit 1 }

$pinOverride = $null
if (-not [string]::IsNullOrEmpty($PinPayload)) {
    if (-not (Test-Path -LiteralPath $PinPayload)) {
        Write-Host "ProtectConfig: Pin Payload Not Found: $PinPayload"
        exit 1
    }
    $pinOverride = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([IO.File]::ReadAllBytes($PinPayload))) -replace "-", "")
}

$hasNewKeys = (-not [string]::IsNullOrEmpty($PayloadName)) -or
              (-not [string]::IsNullOrEmpty($RuntimeName)) -or
              (-not [string]::IsNullOrEmpty($ExportMap)) -or
              (-not [string]::IsNullOrEmpty($DllDir)) -or
              (-not [string]::IsNullOrEmpty($TestTarget))

$existing = [IO.File]::ReadAllBytes($Source)
$isEncrypted = $false
if ($existing.Length -gt $magic.Length) {
    $same = $true
    for ($i = 0; $i -lt $magic.Length; $i++) {
        if ($existing[$i] -ne $magic[$i]) { $same = $false; break }
    }
    $isEncrypted = $same
}
if ($isEncrypted) {
    if ($null -ne $pinOverride) {
        Write-Host "ProtectConfig: Cannot Apply A Pin Override To An Already-Encrypted Source"
        exit 1
    }
    if ($hasNewKeys) {
        Write-Host "ProtectConfig: Cannot Inject Deployment Keys Into An Already-Encrypted Source"
        exit 1
    }
    Write-Host "ProtectConfig: Source Is Already Encrypted; Copying Verbatim."
    Copy-Item -LiteralPath $Source -Destination $Destination -Force
    exit 0
}

$text = [Text.Encoding]::UTF8.GetString($existing)
$modified = $false

if ($null -ne $pinOverride) {
    if ($text -notmatch '(?m)^PayloadSha256\s*=.*$') {
        Write-Host "ProtectConfig: Source Has No PayloadSha256 Line To Override"
        exit 1
    }
    $text = [regex]::Replace($text, '(?m)^PayloadSha256\s*=.*$', 'PayloadSha256 = ' + $pinOverride)
    $modified = $true
    Write-Host ("ProtectConfig: PayloadSha256 = {0}" -f ("" + $pinOverride))
}

$preserved = $null
if ((-not $hasNewKeys) -and (Test-Path -LiteralPath $Destination)) {
    $preserved = Read-ConfigText $Destination
}

$pairs = @{}
if (-not [string]::IsNullOrEmpty($PayloadName)) {
    $pairs["PayloadName"] = $PayloadName
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "PayloadName"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["PayloadName"] = $carry }
}
if (-not [string]::IsNullOrEmpty($RuntimeName)) {
    $pairs["RuntimeName"] = $RuntimeName
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "RuntimeName"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["RuntimeName"] = $carry }
}
if (-not [string]::IsNullOrEmpty($ExportMap)) {
    $pairs["ExportMap"] = $ExportMap
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "ExportMap"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["ExportMap"] = $carry }
}
if (-not [string]::IsNullOrEmpty($DllDir)) {
    $pairs["DllDir"] = $DllDir
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "DllDir"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["DllDir"] = $carry }
}
if (-not [string]::IsNullOrEmpty($TestTarget)) {
    $pairs["TestTarget"] = $TestTarget
} elseif ($null -ne $preserved) {
    $carry = Get-IniValue $preserved "TestTarget"
    if (-not [string]::IsNullOrEmpty($carry)) { $pairs["TestTarget"] = $carry }
}

if ($pairs.Count -gt 0) {
    $before = $text
    $text = Set-IniKeys $text $pairs
    if ($text -ne $before) { $modified = $true }
    foreach ($k in @("PayloadName", "RuntimeName", "ExportMap", "DllDir", "TestTarget")) {
        if ($pairs.ContainsKey($k)) {
            $val = $pairs[$k]
            if ($k -eq "ExportMap") {

                $entries = $val -split ','
                Write-Host ("ProtectConfig: {0} =" -f $k.PadRight(12))
                foreach ($entry in $entries) {
                    $parts = $entry -split '='
                    if ($parts.Count -eq 2) {
                        Write-Host ("  {0} = {1}" -f $parts[0].PadRight(20), ("" + $parts[1]))
                    }
                }
            } else {
                Write-Host ("ProtectConfig: {0} = {1}" -f $k.PadRight(12), ("" + $val))
            }
        }
    }
}

if ($modified) {
    $plain = (New-Object Text.UTF8Encoding($false)).GetBytes($text)
} else {
    $plain = $existing
}

Add-Type -AssemblyName System.Security | Out-Null
try {
    $blob = [Security.Cryptography.ProtectedData]::Protect(
        $plain, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
} catch {
    Write-Host ("ProtectConfig: DPAPI Failed: " + $_.Exception.Message)
    exit 1
}

$out = New-Object byte[] ($magic.Length + $blob.Length)
[Array]::Copy($magic, 0, $out, 0, $magic.Length)
[Array]::Copy($blob, 0, $out, $magic.Length, $blob.Length)
[IO.File]::WriteAllBytes($Destination, $out)

exit 0
