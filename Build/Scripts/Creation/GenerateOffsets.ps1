
param(
  [string]$OutFile = "D:\Ameger\Mapper\Build\Release\Offsets.ini",
  [string]$TargetBuild = "26300",
  [switch]$NoPause
)
$ErrorActionPreference = "Stop"
$tool = "D:\Ameger\Mapper\Build\Release\SymbolTool.exe"
if (-not (Test-Path $tool)) { throw "SymbolTool.exe missing at $tool (use D:\Ameger\Mapper directly)" }
if (Test-Path $OutFile) { Remove-Item $OutFile }
& $tool --generate --output $OutFile
if ($LASTEXITCODE -ne 0) { throw "SymbolTool failed ($LASTEXITCODE)" }
if (-not (Test-Path $OutFile)) { throw "no output" }
$age = (Get-Date) - (Get-Item $OutFile).LastWriteTime
if ($age.TotalDays -gt 90) {
  Write-Warning "Offsets.ini older than 90 days; regenerate against fresh PDB"
}
Write-Host "Offsets -> $OutFile (build $TargetBuild, mtime $((Get-Item $OutFile).LastWriteTime), direct D:\Ameger\Mapper)"
if (-not $NoPause -and $Host.Name -eq "ConsoleHost") { Read-Host "Enter" | Out-Null }