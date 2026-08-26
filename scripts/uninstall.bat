@echo off
REM uninstall.bat - para e remove o driver de teste affctl.
REM Requer prompt de Administrador.

setlocal
echo === Parando servico 'affctl' ===
sc stop affctl

echo === Removendo servico 'affctl' ===
sc delete affctl

echo.
echo [ok] driver affctl removido. (Test Signing continua ligado ate voce desligar:
echo      bcdedit /set testsigning off  ^&  reboot)
endlocal
