<#
.SYNOPSIS
    Prepara/desfaz ambiente RE do rubinot_dx.exe sob x64dbg via IFEO.

.DESCRIPTION
    Setup (padrao):
      1. Copia x64dbg.exe -> notepadd.exe (mesma pasta) — contramedida ao scan
         NtQuerySystemInformation do rubinot que blacklista 'x64dbg' (Sessao 4-5).
      2. Registra IFEO Debugger de rubinot_dx.exe apontando pro clone.
      3. Inicia driver EMACDRVGLTB (rubinot morre <10s sem ele — Sessao 2).
      4. (Opcional -StartAffctl) inicia driver kernel affctl deste projeto.

    Rollback (-Rollback):
      1. Restaura IFEO original (guardado em %TEMP%\rubinot-debug-backup.txt).
      2. Remove notepadd.exe.
      3. Para drivers EMACDRVGLTB e affctl.
      4. Mata rubinot_dx.exe se estiver rodando.

.PARAMETER Rollback
    Desfaz o setup. Requer que o backup do IFEO exista em %TEMP%.

.PARAMETER StartAffctl
    Alem do EMAC, inicia tambem o driver 'affctl' deste projeto. Necessario pra
    Fase B1 (IOCTL_INJECT_DLL). Sessao 6 confirmou que rubinot nao detecta affctl,
    entao ligar por default seria conservador; mantido opt-in pra reduzir surface.

.PARAMETER X64DbgPath
    Path pro x64dbg.exe original. Default: pasta do winget do usuario 'xyrlan'.

.PARAMETER CloneName
    Nome do clone (sem path). Default: 'notepadd.exe' — nao esta na blacklist.

.PARAMETER RubinotPath
    Path pro rubinot_dx.exe. Usado so como sanity check no setup.
    Default: 'C:\Program Files (x86)\RubinOT 2.0\bin\x64\rubinot_dx.exe'.

.EXAMPLE
    # Setup completo pra sessao RE:
    .\setup-rubinot-debug.ps1 -StartAffctl

.EXAMPLE
    # Setup sem affctl (so o scan de debugger):
    .\setup-rubinot-debug.ps1

.EXAMPLE
    # Desfaz tudo:
    .\setup-rubinot-debug.ps1 -Rollback

.NOTES
    Requer PowerShell elevado. Testado no Win10 22H2 host do dev (2026-08-28).
    Ver docs/reverse-engineering/rubinot-scan-detection.md pro contexto completo.
#>
[CmdletBinding()]
param(
    [switch]$Rollback,
    [switch]$StartAffctl,
    [string]$X64DbgPath = 'C:\Users\xyrlan\AppData\Local\Microsoft\WinGet\Packages\x64dbg.x64dbg_Microsoft.Winget.Source_8wekyb3d8bbwe\release\x64\x64dbg.exe',
    [string]$CloneName  = 'notepadd.exe',
    [string]$RubinotPath = 'C:\Program Files (x86)\RubinOT 2.0\bin\x64\rubinot_dx.exe'
)

$ErrorActionPreference = 'Stop'
$IfeoKey    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rubinot_dx.exe'
$BackupPath = Join-Path $env:TEMP 'rubinot-debug-backup.txt'
$ClonePath  = Join-Path (Split-Path $X64DbgPath) $CloneName

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $isAdmin) {
        throw "Este script precisa rodar em PowerShell elevado (Run as Administrator)."
    }
}

function Set-IfeoDebugger {
    param([string]$Value)
    if (-not (Test-Path $IfeoKey)) {
        New-Item -Path $IfeoKey -Force | Out-Null
    }
    Set-ItemProperty -Path $IfeoKey -Name Debugger -Value $Value
}

function Get-IfeoDebugger {
    (Get-ItemProperty -Path $IfeoKey -Name Debugger -ErrorAction SilentlyContinue).Debugger
}

function Start-DriverSafe {
    param([string]$Name)
    $state = (sc.exe query $Name 2>&1 | Select-String -Pattern 'STATE|ESTADO').ToString()
    if ($state -match 'RUNNING') {
        Write-Host "  $Name ja RUNNING."
        return
    }
    $out = sc.exe start $Name 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "  sc start $Name falhou: $out"
    } else {
        Write-Host "  $Name -> RUNNING"
    }
}

function Stop-DriverSafe {
    param([string]$Name)
    $probe = sc.exe query $Name 2>&1
    if ($probe -match '1060|no.*service|servico.*inexistente') {
        Write-Host "  $Name nao registrado, skip."
        return
    }
    $state = ($probe | Select-String -Pattern 'STATE|ESTADO').ToString()
    if ($state -notmatch 'RUNNING') {
        Write-Host "  $Name nao esta RUNNING, skip."
        return
    }
    $out = sc.exe stop $Name 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "  sc stop $Name falhou: $out"
    } else {
        Write-Host "  $Name -> STOPPED"
    }
}

Assert-Admin

if ($Rollback) {
    Write-Host "=== ROLLBACK ==="

    if (Test-Path $BackupPath) {
        $orig = (Get-Content $BackupPath -Raw).Trim()
        if ($orig) {
            Write-Host "1. Restaurando IFEO Debugger original: $orig"
            Set-IfeoDebugger -Value $orig
        } else {
            Write-Host "1. Backup vazio -> removendo IFEO Debugger."
            Remove-ItemProperty -Path $IfeoKey -Name Debugger -ErrorAction SilentlyContinue
        }
        Remove-Item $BackupPath -Force
    } else {
        Write-Warning "1. Backup $BackupPath nao encontrado -> nao mexo no IFEO."
    }

    if (Test-Path $ClonePath) {
        Write-Host "2. Removendo clone $ClonePath"
        Remove-Item $ClonePath -Force
    } else {
        Write-Host "2. Clone $ClonePath nao existe."
    }

    Write-Host "3. Matando rubinot_dx.exe (se rodando)"
    Get-Process -Name rubinot_dx -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

    Write-Host "4. Parando drivers"
    Stop-DriverSafe -Name affctl
    Stop-DriverSafe -Name EMACDRVGLTB

    Write-Host "`nROLLBACK OK."
    return
}

# --- Setup ---
Write-Host "=== SETUP ==="

if (-not (Test-Path $X64DbgPath)) {
    throw "x64dbg.exe nao encontrado em $X64DbgPath. Passe -X64DbgPath explicito."
}
if (-not (Test-Path $RubinotPath)) {
    Write-Warning "rubinot_dx.exe nao encontrado em $RubinotPath. IFEO ainda sera setado, mas confirme o path."
}

Write-Host "1. Backup IFEO atual"
$currentIfeo = Get-IfeoDebugger
if ($null -ne $currentIfeo) {
    Set-Content -Path $BackupPath -Value $currentIfeo -Encoding utf8
    Write-Host "   Backup salvo em $BackupPath : $currentIfeo"
} else {
    Set-Content -Path $BackupPath -Value '' -Encoding utf8
    Write-Host "   Sem IFEO Debugger previo, backup vazio."
}

Write-Host "2. Copiando x64dbg.exe -> $CloneName"
Copy-Item -Path $X64DbgPath -Destination $ClonePath -Force
Write-Host "   OK: $ClonePath"

Write-Host "3. Setando IFEO Debugger = $ClonePath"
Set-IfeoDebugger -Value ('"' + $ClonePath + '"')
Write-Host "   IFEO agora: $(Get-IfeoDebugger)"

Write-Host "4. Iniciando driver EMACDRVGLTB"
Start-DriverSafe -Name EMACDRVGLTB

if ($StartAffctl) {
    Write-Host "5. Iniciando driver affctl (opt-in)"
    Start-DriverSafe -Name affctl
} else {
    Write-Host "5. Skipping affctl (passe -StartAffctl pra ligar)."
}

Write-Host ""
Write-Host "SETUP OK. Proximos passos:"
Write-Host "  Start-Process '$RubinotPath'"
Write-Host "  (rubinot vai abrir sob x64dbg via IFEO)"
Write-Host ""
Write-Host "Rollback: .\setup-rubinot-debug.ps1 -Rollback"
