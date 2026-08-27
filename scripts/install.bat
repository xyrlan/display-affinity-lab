@echo off
REM install.bat - carrega o driver de teste affctl.sys.
REM Requer prompt de Administrador. Uso: install.bat [caminho\affctl.sys]
REM Se nenhum caminho for passado, usa .\affctl.sys ao lado deste script.

setlocal
set DRV=%~1
if "%DRV%"=="" set DRV=%~dp0affctl.sys

if not exist "%DRV%" (
    echo [erro] driver nao encontrado: %DRV%
    echo passe o caminho: install.bat C:\caminho\affctl.sys
    exit /b 1
)

echo === Pre-requisito: Test Signing ===
echo Drivers nao assinados so carregam com Test Signing LIGADO.
echo Para ligar (exige REBOOT):
echo     bcdedit /set testsigning on
echo Verifique com:  bcdedit /enum ^| findstr -i testsigning
echo.

echo === Criando e iniciando servico 'affctl' ===
sc create affctl type= kernel start= demand binPath= "%DRV%"
if errorlevel 1 echo [aviso] sc create falhou - servico ja existe? Tentando start mesmo assim.
sc start affctl
if errorlevel 1 (
    echo [erro] sc start falhou. Test Signing ligado? Rebootou apos ligar?
    exit /b 1
)

echo.
echo [ok] driver affctl carregado. Rode affapp.exe.
endlocal
