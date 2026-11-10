@echo off
setlocal EnableExtensions EnableDelayedExpansion
pushd "%~dp0..\.."

echo === Protect.bat %DATE% %TIME% ===

if not exist "Assets\DLL\Target.dll" (
    echo WARN: Assets\DLL\Target.dll not staged; skipping payload stage
    popd
    exit /b 0
)

echo OK: Assets\DLL\Target.dll present (not copied, moved or modified)
echo === Protect.bat complete ===
popd
exit /b 0
