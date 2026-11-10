@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "ROOT=%~dp0..\.."
pushd "%ROOT%"

set "CACHEDIR=Build\Release\Cache"
if not exist "%CACHEDIR%" mkdir "%CACHEDIR%" >nul

echo === Create.bat %DATE% %TIME% ===

call :Stage "1/6 Toolchain"

powershell -NoProfile -ExecutionPolicy Bypass -Command "$vswhere=$null; $cmd=Get-Command vswhere.exe -ErrorAction SilentlyContinue; if($cmd){$vswhere=$cmd.Source}; if(-not $vswhere){ foreach($p2 in @('C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe','C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe')){ if(Test-Path $p2){$vswhere=$p2;break}}}; if(-not $vswhere){exit 10}; $msbuild=$null; try{$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find 'MSBuild\**\Bin\MSBuild.exe' 2>$null | Select-Object -First 1}catch{}; if(-not $msbuild){ foreach($p3 in @('C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe','C:\Program Files\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe')){ if(Test-Path $p3){$msbuild=$p3;break}}}; if(-not $msbuild){exit 11}; Set-Content -Path 'Build\Release\Cache\_tc_vswhere.txt' -Value $vswhere -Encoding ASCII; Set-Content -Path 'Build\Release\Cache\_tc_msbuild.txt' -Value $msbuild -Encoding ASCII"
if errorlevel 10 (echo FAIL: vswhere not found on PATH or standard locations & goto :fail)
if errorlevel 11 (echo FAIL: MSBuild not found via vswhere or fallback path & goto :fail)
if exist "%CACHEDIR%\_tc_vswhere.txt" for /f "usebackq delims=" %%i in ("%CACHEDIR%\_tc_vswhere.txt") do set "VSWHERE=%%i"
if exist "%CACHEDIR%\_tc_msbuild.txt" for /f "usebackq delims=" %%i in ("%CACHEDIR%\_tc_msbuild.txt") do set "MSBUILD=%%i"
echo OK: VSWHERE=%VSWHERE%
echo OK: MSBUILD=%MSBUILD%

if exist "D:\Injector\Mapper\Build\Release\SymbolTool.exe" (
    echo OK: SymbolTool ^(D:\Injector\Mapper\Build\Release\SymbolTool.exe^)
) else (
    echo WARN: D:\Injector\Mapper\Build\Release\SymbolTool.exe missing ^(Offsets.ini must be provisioned^)
)
if exist "D:\Injector\Mapper\Build\Release\Mapper.exe" (
    echo OK: Mapper ^(D:\Injector\Mapper\Build\Release\Mapper.exe^)
) else (
    echo WARN: D:\Injector\Mapper\Build\Release\Mapper.exe missing
)

call :Stage "2/6 Projects"
if exist "Build\Template\Driver.vcxproj" (
    echo OK: Build\Template\Driver.vcxproj
) else (
    echo FAIL: Build\Template\Driver.vcxproj missing & goto :fail
)
if exist "Build\Template\Client.vcxproj" (
    echo OK: Build\Template\Client.vcxproj
) else (
    echo FAIL: Build\Template\Client.vcxproj missing & goto :fail
)

call :Stage "3/6 Clean"
if exist "Build\Release" rmdir /s /q "Build\Release" >nul 2>&1
if exist "Assets\Release" rmdir /s /q "Assets\Release" >nul 2>&1
if exist "Assets\Driver\Driver.sys" del /f /q "Assets\Driver\Driver.sys" >nul 2>&1
if exist "Assets\Client\Client.exe" del /f /q "Assets\Client\Client.exe" >nul 2>&1
mkdir "%CACHEDIR%" >nul
echo Clean OK

call :Stage "4/6 Offsets"
if exist "D:\Injector\Mapper\Build\Release\SymbolTool.exe" (
    if not exist "D:\Injector\Mapper\Build\Release\Offsets.ini" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "Build\Scripts\Creation\GenerateOffsets.ps1" -NoPause
        if errorlevel 1 (echo FAIL: GenerateOffsets & goto :fail)
        echo OK: Offsets.ini generated ^(direct^)
    ) else (
        echo OK: Offsets.ini exists ^(direct, not regenerated^)
    )
) else (
    echo SKIP: Offsets.ini ^(SymbolTool missing at D:\Injector\Mapper^)
)

call :Stage "5/6 Build"
powershell -NoProfile -ExecutionPolicy Bypass -File "Build\Scripts\Build\BuildDriver.ps1" -NoPause
if errorlevel 1 (echo FAIL: BuildDriver & goto :fail)
powershell -NoProfile -ExecutionPolicy Bypass -File "Build\Scripts\Build\VerifyDriverSections.ps1" -NoPause
if errorlevel 1 (echo FAIL: VerifyDriverSections & goto :fail)
echo OK: driver built and verified

powershell -NoProfile -ExecutionPolicy Bypass -File "Build\Scripts\Build\BuildClient.ps1" -NoPause
if errorlevel 1 (echo FAIL: BuildClient & goto :fail)
echo OK: client built

call :Stage "6/6 Protect/Deploy"
call Build\Executors\Protect.bat
if errorlevel 1 (echo FAIL: Protect & goto :fail)

powershell -NoProfile -ExecutionPolicy Bypass -File "Build\Scripts\Build\DeployRelease.ps1" -NoPause
if errorlevel 1 (echo FAIL: DeployRelease & goto :fail)
echo OK: release assembled

echo === Stages 1-6 complete ===
popd
echo.
echo Stages 1-6 complete. Release: Assets\Release\
exit /b 0

:Stage
echo [%~1]
goto :eof

:fail
echo === FAILED ===
popd
echo.
echo Build failed.
exit /b 1
