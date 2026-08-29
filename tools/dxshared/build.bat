@echo off
REM Build all dxshared tools with MSVC (VS2022 or VS2026).
REM Output: .\bin\*.exe

setlocal EnableDelayedExpansion

REM ---- Locate vcvarsall.bat ----
set "VCVARS="
for %%V in ("18\Community" "17\Community" "18\Professional" "17\Professional" "18\Enterprise" "17\Enterprise") do (
    if exist "C:\Program Files\Microsoft Visual Studio\%%~V\VC\Auxiliary\Build\vcvarsall.bat" (
        set "VCVARS=C:\Program Files\Microsoft Visual Studio\%%~V\VC\Auxiliary\Build\vcvarsall.bat"
        goto :found_vs
    )
    if exist "C:\Program Files (x86)\Microsoft Visual Studio\%%~V\VC\Auxiliary\Build\vcvarsall.bat" (
        set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\%%~V\VC\Auxiliary\Build\vcvarsall.bat"
        goto :found_vs
    )
)
echo [!] vcvarsall.bat nao encontrado. Instale VS2022 ou VS2026 com C++ workload.
exit /b 1

:found_vs
echo [+] Using: !VCVARS!
call "!VCVARS!" x64 >nul
if errorlevel 1 (echo [!] vcvarsall failed & exit /b 1)

cd /d "%~dp0"
if not exist bin mkdir bin

REM ---- Compile flags ----
set "CFLAGS_17=/nologo /EHsc /std:c++17 /O2 /W3"
set "CFLAGS_20=/nologo /EHsc /std:c++20 /O2 /W3"
set "LIB_D3D=d3d11.lib dxgi.lib user32.lib gdi32.lib"
set "LIB_GUI=user32.lib gdi32.lib"
set "LIB_WGC=d3d11.lib dxgi.lib user32.lib gdi32.lib windowsapp.lib runtimeobject.lib"

echo.
echo === dxshared_probe (screenshot unico) ===
cl.exe %CFLAGS_17% dxshared_probe.cpp /link %LIB_D3D% /OUT:bin\dxshared_probe.exe
if errorlevel 1 goto :err

echo.
echo === dxshared_stream (streaming continuo) ===
cl.exe %CFLAGS_17% dxshared_stream.cpp /link %LIB_D3D% /OUT:bin\dxshared_stream.exe
if errorlevel 1 goto :err

echo.
echo === wda_holder (cobaia com WDA aplicada) ===
cl.exe %CFLAGS_17% wda_holder.cpp /link %LIB_GUI% /OUT:bin\wda_holder.exe /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :err

echo.
echo === wgc_probe (probe WGC de referencia) ===
cl.exe %CFLAGS_20% wgc_probe.cpp /link %LIB_WGC% /OUT:bin\wgc_probe.exe
if errorlevel 1 goto :err

echo.
echo === wgc_selftest (WGC contra propria janela) ===
cl.exe %CFLAGS_20% wgc_selftest.cpp /link %LIB_WGC% /OUT:bin\wgc_selftest.exe /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :err

REM cleanup .obj
del /q *.obj 2>nul

echo.
echo ============================================
echo   Build OK -^> bin\
dir /b bin\*.exe
exit /b 0

:err
echo [!] build falhou
del /q *.obj 2>nul
exit /b 1
