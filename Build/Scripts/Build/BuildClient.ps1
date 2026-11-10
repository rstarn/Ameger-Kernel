param(
  [string]$Config = "Release",
  [switch]$NoPause
)
$ErrorActionPreference = "Stop"

$channelMagic = '0x1122334455667788'

$vswhere = (Get-Command vswhere.exe -ErrorAction SilentlyContinue).Source
if (-not $vswhere) {
  foreach ($c in @(
      "C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe",
      "C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"
  )) { if (Test-Path $c) { $vswhere = $c; break } }
}
if (-not $vswhere) { throw "vswhere.exe not found" }

$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild `
  -find "MSBuild\**\Bin\MSBuild.exe" 2>$null | Select-Object -First 1
if (-not $msbuild) {
  foreach ($c in @(
      "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
      "C:\Program Files\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
  )) { if (Test-Path $c) { $msbuild = $c; break } }
}
if (-not $msbuild) { throw "MSBuild.exe not found" }
Write-Host "Using MSBuild: $msbuild"

& $msbuild "Build\Template\Client.vcxproj" /p:Configuration=$Config /p:Platform=x64 `
  /p:AmegerChannelMagic=$channelMagic `
  /m /v:minimal
if ($LASTEXITCODE -ne 0) { throw "Client build failed ($LASTEXITCODE)" }

$outExe = "Assets\Client\Client.exe"
if (-not (Test-Path $outExe)) { throw "Client.exe not produced at $outExe" }
Write-Host "Client -> $outExe"

if (-not $NoPause -and $Host.Name -eq "ConsoleHost") { Read-Host "Enter" | Out-Null }
