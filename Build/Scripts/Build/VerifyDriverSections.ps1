
param(
  [string]$Path = "Assets\Driver\Driver.sys",
  [switch]$NoPause
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Path)) { throw "driver not found: $Path" }
$bytes = [System.IO.File]::ReadAllBytes($Path)
$peOff = [BitConverter]::ToInt32($bytes, 0x3C)
$magic = [BitConverter]::ToUInt16($bytes, $peOff + 0x18)
if ($magic -ne 0x20B) { throw "not PE32+: magic 0x$($magic.ToString('X'))" }
$numSec = [BitConverter]::ToUInt16($bytes, $peOff + 0x06)
$optOff = $peOff + 0x18
$secOff = $optOff + [BitConverter]::ToUInt16($bytes, $peOff + 0x14)
$hasRWX = $false
$codeFound = $false
$pdataWritable = $false
for ($i = 0; $i -lt $numSec; $i++) {
  $s = $secOff + ($i * 40)
  $name = [System.Text.Encoding]::ASCII.GetString($bytes, $s, 8).TrimEnd([char]0)
  $chars = [BitConverter]::ToUInt32($bytes, $s + 36)
  $isExec  = ($chars -band 0x20000000) -ne 0
  $isRead  = ($chars -band 0x40000000) -ne 0
  $isWrite = ($chars -band 0x80000000) -ne 0
  Write-Host "  $name  R=$isRead W=$isWrite X=$isExec"
  if ($isExec -and $isWrite) { $hasRWX = $true }
  if ($isExec) { $codeFound = $true }
  if ($name -eq ".pdata" -and $isWrite) { $pdataWritable = $true }
}
if (-not $codeFound) { throw "no executable section" }
if ($hasRWX) { throw "RWX section present" }
if ($pdataWritable) { throw ".pdata is writable" }
Write-Host "Driver section check OK"
if (-not $NoPause -and $Host.Name -eq "ConsoleHost") { Read-Host "Enter" | Out-Null }