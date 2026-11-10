param(
  [string]$Config = "Release",
  [switch]$NoPause
)
$ErrorActionPreference = "Stop"

$channelMagic = '0x1122334455667788'
$clientExe    = 'Client.exe'
$poolTag      = 'sfTN'

$vswhere = (Get-Command vswhere.exe -ErrorAction SilentlyContinue).Source
if (-not $vswhere) {
  foreach ($c in @(
      "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
      "C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"
  )) { if (Test-Path $c) { $vswhere = $c; break } }
}
if (-not $vswhere) { throw "vswhere.exe not found on PATH or standard locations" }

$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
  -find "MSBuild\**\Bin\MSBuild.exe" 2>$null | Select-Object -First 1

if (-not $msbuild) {
  foreach ($c in @(
      "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
      "C:\Program Files\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
  )) { if (Test-Path $c) { $msbuild = $c; break } }
}
if (-not $msbuild) { throw "MSBuild.exe not found via vswhere or fallback" }

Write-Host "Using MSBuild: $msbuild"

$outSys = "Assets\Driver\Driver.sys"
if (Test-Path $outSys) { Remove-Item $outSys -Force }
& $msbuild "Build\Template\Driver.vcxproj" /p:Configuration=$Config /p:Platform=x64 `
  /p:AmegerPoolTag=$poolTag `
  /p:AmegerChannelMagic=$channelMagic `
  /p:ClientName=$clientExe `
  /p:AmegerPdataRva=0x0 /p:AmegerPdataSize=0x0 `
  /p:SignMode=Off /p:EnableInf2cat=false /p:ApiValidator_Enable=false `
  /m /v:minimal
if ($LASTEXITCODE -ne 0) { throw "Driver build failed ($LASTEXITCODE)" }
if (-not (Test-Path $outSys)) { throw "Driver.sys not produced at $outSys (pass 1)" }

$b = [System.IO.File]::ReadAllBytes($outSys)
$peOff = [BitConverter]::ToInt32($b, 0x3C)
$optOff = $peOff + 0x18
$dirOff = $optOff + 0x70 + (3 * 8)
$excRva = [BitConverter]::ToUInt32($b, $dirOff)
$excSize = [BitConverter]::ToUInt32($b, $dirOff + 4)
Write-Host ("Extracted .pdata RVA=0x{0:X} SIZE=0x{1:X}" -f $excRva, $excSize)

& $msbuild "Build\Template\Driver.vcxproj" /p:Configuration=$Config /p:Platform=x64 `
  /p:AmegerPoolTag=$poolTag `
  /p:AmegerChannelMagic=$channelMagic `
  /p:ClientName=$clientExe `
  /p:AmegerPdataRva=$('0x{0:X}' -f $excRva) `
  /p:AmegerPdataSize=$('0x{0:X}' -f $excSize) `
  /p:SignMode=Off /p:EnableInf2cat=false /p:ApiValidator_Enable=false `
  /m /v:minimal
if ($LASTEXITCODE -ne 0) { throw "Driver build failed ($LASTEXITCODE)" }
if (-not (Test-Path $outSys)) { throw "Driver.sys not produced at $outSys (pass 2)" }
$finalSize = (Get-Item $outSys).Length
Write-Host "Final driver: $finalSize bytes"

Write-Host "Driver -> $outSys (CHANNEL_MAGIC=$channelMagic CLIENT=$clientExe)"

if (-not $NoPause -and $Host.Name -eq "ConsoleHost") { Read-Host "Enter" | Out-Null }
