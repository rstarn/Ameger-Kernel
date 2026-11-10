param(
  [switch]$NoPause
)
$ErrorActionPreference = "Stop"

function Get-FileSha256Compat([string]$Path) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $fs = [System.IO.File]::OpenRead($Path)
    try { return ([System.BitConverter]::ToString($sha.ComputeHash($fs)).Replace('-','')) }
    finally { $fs.Dispose() }
  } finally { $sha.Dispose() }
}

$releaseDir = "Assets\Release"
if (-not (Test-Path $releaseDir)) { New-Item -ItemType Directory -Path $releaseDir -Force | Out-Null }

$srcClient = "Assets\Client\Client.exe"
if (-not (Test-Path $srcClient)) { throw "Client.exe not found at $srcClient (Stage 5 should have produced it)" }
$h = Get-FileSha256Compat $srcClient
Write-Host "Client   -> $srcClient  ($h)"

$payloadPath = "Assets\DLL\Target.dll"
$payloadHash = ''
if (Test-Path $payloadPath) {
  $payloadHash = Get-FileSha256Compat $payloadPath
  Write-Host "Payload  -> $payloadPath  ($payloadHash) [read-only, untouched]"
} else {
  Write-Warning "Payload not found at $payloadPath (drop renewed Target.dll there before building)"
}

$mapperDir = "D:\Injector\Mapper\Build\Release"
if (Test-Path (Join-Path $mapperDir "Offsets.ini")) {
  Write-Host "Offsets  -> direct (not replicated): $(Join-Path $mapperDir 'Offsets.ini')"
} else {
  Write-Warning "Offsets.ini missing at $mapperDir (direct path)"
}
if (Test-Path (Join-Path $mapperDir "Mapper.exe")) {
  Write-Host "Mapper   -> direct (not replicated): $(Join-Path $mapperDir 'Mapper.exe')"
} elseif (Test-Path (Join-Path $mapperDir "Injector-Mapper.exe")) {
  Write-Host "Mapper   -> direct (not replicated): $(Join-Path $mapperDir 'Injector-Mapper.exe')"
} else {
  Write-Warning "Mapper.exe missing at $mapperDir (direct path)"
}

$logPath = "$releaseDir\Target.log"
if (-not (Test-Path $logPath)) {
  New-Item -ItemType File -Path $logPath -Force | Out-Null
  Write-Host "Log      -> $logPath (empty; client appends)"
}

powershell -NoProfile -ExecutionPolicy Bypass -File "Build\Scripts\Protection\ProtectConfig.ps1" `
  -Source "Client\Configuration.ini" `
  -Destination "$releaseDir\Target.ini" `
  -ConfigMagic 'kDDt0r3m'
if ($LASTEXITCODE -ne 0) { throw "ProtectConfig.ps1 failed ($LASTEXITCODE)" }
Write-Host "Config   -> $releaseDir\Target.ini (DPAPI)"

$sweepExts = @("*.pdb","*.lib","*.exp","*.ilk","*.obj")
foreach ($ext in $sweepExts) {
  Get-ChildItem -Path $releaseDir -Filter $ext -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force
}
Write-Host "Sweep    -> PDB/LIB/EXP/ILK/OBJ removed from $releaseDir"

$manifest = "$releaseDir\SectionManifest.txt"
$lines = @(
  "Client:   Client.exe",
  "  SHA256: $h"
)
if ($payloadHash -ne '') {
  $lines += ""
  $lines += "Payload:  Target.dll (read-only at Assets\\DLL\\Target.dll)"
  $lines += "  SHA256: $payloadHash"
}
$lines += ""
$lines += "Config:   Target.ini (DPAPI)"
$lines += "Log:      Target.log (created empty; client appends)"
$lines += ""
$lines += "Offsets.ini: direct D:\Injector\Mapper\Build\Release\Offsets.ini (not replicated)"
$lines += "Mapper.exe:  direct D:\Injector\Mapper\Build\Release\Mapper.exe (not replicated)"
[System.IO.File]::WriteAllLines($manifest, $lines, [System.Text.Encoding]::UTF8)
Write-Host "Manifest -> $manifest"

if (-not $NoPause -and $Host.Name -eq "ConsoleHost") { Read-Host "Enter" | Out-Null }
