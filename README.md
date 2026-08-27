# display-affinity-lab

Laboratório **educacional** de internals do Windows: driver de kernel + payloads
user-mode que exploram — e efetivamente contornam — `SetWindowDisplayAffinity`
em Windows 10/11 modernos.

O projeto nasceu como um PoC clássico ("achar a flag DisplayAffinity dentro da
`tagWND` e zerar via driver") e, ao esbarrar num hardening arquitetural real da
Microsoft, pivotou para uma abordagem que **funciona hoje**: injeção de DLL 100%
kernel-mode via APC + hook inline em `user32!SetWindowDisplayAffinity`.

> **Escopo.** Só rode em **VM de teste** sua, com Test Signing. Todos os testes
> foram feitos contra janelas criadas pelo próprio `afftarget.exe`. Não é
> ferramenta pra atacar apps de terceiros. Você é responsável pelo uso.

---

## TL;DR — o que este repo demonstra

1. **Descoberta científica** (documentada com dados): em Win10 22H2 e Win11
   22H2+, o estado de `WDA_EXCLUDEFROMCAPTURE` **não vive** na `tagWND` do
   kernel — foi movido pro **DWM** (`dwm.exe`). A técnica clássica "zerar byte
   em `tagWND` via driver" não é mais aplicável. Provamos isso com controle
   (`WS_EX_LAYERED` produz diff visível na `tagWND`, WDA não).
2. **Bootstrap kernel-mode limpo**: driver assinado por cert de teste, resolução
   de símbolos via PDB da Microsoft (Symbol Server), leitura de kernel VA
   protegida por SEH, IOCTLs versionados.
3. **Injeção de DLL 100% kernel** (`IOCTL_INJECT_DLL`): `KeStackAttachProcess` +
   `ZwAllocateVirtualMemory` + `KeInitializeApc`/`KeInsertQueueApc`. Sem
   `CreateRemoteThread`, sem `WriteProcessMemory`, sem hooks user-mode.
4. **Bypass end-to-end verificado**: DLL de bypass (`affbypass.dll`) usa MinHook
   pra hookar `user32!SetWindowDisplayAffinity` no processo alvo; quando o alvo
   chama, o hook retorna `TRUE` sem repassar ao Windows/DWM — proteção
   neutralizada. Prova visual em BMP (captura mostra conteúdo, não preto).

---

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────────┐
│  USER MODE                                                          │
│                                                                     │
│  afftarget.exe                       affapp.exe (Admin)             │
│  ├─ Janela colorida                  ├─ --inject <pid> <dll>        │
│  ├─ Botao "Proteger"                 │  ├─ enum threads (Toolhelp)  │
│  └─ Loop alertable                   │  ├─ resolve LoadLibraryW     │
│     (MWMO_ALERTABLE)                 │  └─ IOCTL_INJECT_DLL         │
│         ▲                            ├─ --capture <bmp> [delay]     │
│         │ hooked                     ├─ --probe-dwm (PDB reality-   │
│         │                            │              check)          │
│  affbypass.dll (injetada)            └─ ...                         │
│  ├─ MinHook em user32!Set...            │                           │
│  └─ Hook retorna TRUE                   │ DeviceIoControl           │
│         (nao propaga p/ DWM)            ▼                           │
├─────────────────────────────────────────────────────────────────────┤
│  KERNEL MODE                                                        │
│                                                                     │
│  affctl.sys (\??\AffCtl)                                            │
│  ├─ IOCTL_INJECT_DLL                                                │
│  │  ├─ PsLookupProcessByProcessId / PsLookupThreadByThreadId        │
│  │  ├─ KeStackAttachProcess(target)                                 │
│  │  ├─ ZwAllocateVirtualMemory (buffer pro path, no espaco do alvo) │
│  │  ├─ RtlCopyMemory sob SEH                                        │
│  │  ├─ KeUnstackDetachProcess                                       │
│  │  └─ KeInitializeApc + KeInsertQueueApc                           │
│  │     (UserMode, NormalRoutine = LoadLibraryW resolvido no app)    │
│  ├─ IOCTL_AFF_DIAG (diagnostico do layout HANDLEENTRY/tagWND)       │
│  └─ [legado] IOCTL_READ_RANGE / CLEAR_AFFINITY / SET_OFFSET / ...   │
│              — mecanica classica de patch em tagWND                 │
│              (nao funciona em Win10/11 modernos — ver findings)     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Componentes

| Arquivo | Papel |
|---|---|
| `driver/driver.cpp` | `DriverEntry`, dispatch dos IOCTLs, `Unload`. |
| `driver/inject.h/.cpp` | Injeção de DLL via APC (`KeStackAttach` + `Zw*VirtualMemory` + `KeInitializeApc/InsertQueueApc`). |
| `driver/tagwnd.h/.cpp` | Resolução HWND → `tagWND` via `ValidateHwnd` (PDB) + leitura/escrita com SEH. **Legado**: útil como demo de mecânica kernel, não do bypass em si. |
| `driver/win32k_structs.h` | Layouts parciais (`SHAREDINFO`, `HANDLEENTRY`) — validados via diagnóstico para Win11 25H2. |
| `driver/affctl.vcxproj` / `.inf` | Projeto WDM x64 + INF mínimo. |
| `shared/affctl_shared.h` | Contrato IOCTL entre driver e app. |
| `app/main.cpp` | Orquestração; modos `--inject`, `--capture`, `--probe-dwm`, `--guard`, `--(default: discovery/demo)`. |
| `app/Injector.hpp/.cpp` | Enumeração de threads, `LoadLibraryW` addr, wrapper de `IOCTL_INJECT_DLL`. |
| `app/PdbResolver.hpp/.cpp` | `dbghelp` + Symbol Server. Resolve símbolos internos (`gSharedInfo`, `ValidateHwnd`) — future-proof. |
| `app/ModuleBase.cpp` | Base do módulo kernel via `EnumDeviceDrivers`. |
| `app/DriverComm.hpp/.cpp` | RAII sobre `\\.\AffCtl`; wrappers de IOCTL. |
| `app/TestWindow.hpp/.cpp` | Janela própria RAII (usada no discovery legado). |
| `app/OffsetFinder.hpp/.cpp` | Heurística de descoberta (clássica + bit-flag + diagnóstica). |
| `app/BmpCapture.hpp/.cpp` | Captura via `BitBlt` de HWND. |
| `app/affapp.vcxproj` | Console x64 C++17, runtime estático (`/MT`), toolset `v145`. |
| `afftarget/afftarget.cpp` | Cobaia visual: janela colorida com botões "Proteger" e "Ler afinidade". Loop `MsgWaitForMultipleObjectsEx(MWMO_ALERTABLE)` pra garantir APC delivery. |
| `affbypass/affbypass.cpp` | DLL de payload: MinHook em `user32!SetWindowDisplayAffinity`, retorna `TRUE` sem propagar. Status file em `%TEMP%`. |
| `hellodll/hellodll.cpp` | DLL de smoke-test da injeção (prova de que a mecânica APC executa código dentro do alvo). |
| `third_party/minhook/` | MinHook (vendored, BSD-2-Clause). Necessário para `affbypass`. |
| `scripts/install.bat` / `uninstall.bat` | `sc create` / `sc start` / `sc delete` do driver. |
| `dist/vm-payload/` | Pacote pronto pra copiar na VM: driver assinado + exes + DLLs + scripts + cert público. |

---

## Descoberta científica: WDA vive no DWM

O README original assumia que `WDA_EXCLUDEFROMCAPTURE` era um byte da `tagWND`
que um driver poderia zerar. **Isso é falso em Windows moderno.** Validamos com
snapshots controlados:

| Operação | Diffs em 8 KB da `tagWND` |
|---|---|
| `WDA_NONE → WDA_MONITOR` | 0 (ou apenas contador genérico compartilhado) |
| `WDA_NONE → WDA_EXCLUDEFROMCAPTURE` | 0 (ou o mesmo contador) |
| `WDA_MONITOR → WDA_EXCLUDEFROMCAPTURE` | **0** ← chave do argumento |
| Controle: `NONE → +WS_EX_LAYERED` | 1 bit específico em offset conhecido ← prova que a leitura kernel funciona |

`MONITOR` e `EXCLUDE` produzem valores distintos na API (`0x01` vs `0x11`) mas
`0 diffs` na `tagWND` — o modo não está armazenado ali. O estado real é
mantido pelo DWM (`dwm.exe`) em user-mode, e a Microsoft **strippou o PDB do
`dwmcore.dll`** (validado com `--probe-dwm`: 1 hit em 10 wildcards, único
export documentado). Atacar o DWM diretamente exigiria RE manual completo do
`dwmcore.dll` — fora do escopo deste PoC.

**Conclusão:** para bypass real de `WDA_EXCLUDEFROMCAPTURE` em Windows atual,
o caminho viável é interceptar a API **dentro do próprio processo alvo**
(user-mode) — mas fazer o bootstrap do hook via **kernel** (não via
`CreateRemoteThread`, que muitos EDRs/anti-debug bloqueiam). É exatamente o
que este PoC faz.

---

## Pré-requisitos

- **Windows 10/11 x64** no host + Visual Studio 2022 ou 2026 (testado com 2026
  Community 18.9.2).
- **Windows SDK 10.0.26100** e **WDK 10.0.26100.6584** (casar build numbers).
- Uma **VM de teste** (Hyper-V Gen 2 ou Gen 1) com Test Signing habilitado.
- Habilidade de assinar drivers com cert de teste (`signtool`, incluído no SDK).

### Nota sobre VS 2026 × WDK 26100

O WDK 26100.6584 é oficialmente pra VS 2022 (17). No VS 2026 (18) precisa de
três overrides no `msbuild` do driver — já embutidos nos comandos abaixo:

```
/p:VisualStudioVersion=17.0  # acha Microsoft.DriverKit.Build.Tasks.17.0.dll
/p:SignMode=Off              # signtool novo exige /fd; assinamos separado
/p:EnableInf2cat=false       # nao usamos catalogo INF neste PoC
```

O toolset dos apps user-mode foi migrado de `v143` (VS 2022) pra `v145`
(VS 2026); ver `app/affapp.vcxproj`.

---

## Setup inicial (uma vez)

### 1. MinHook (vendored)

```powershell
$dest = "C:\Users\<user>\display-affinity-lab\third_party\minhook"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$zip = "$env:TEMP\minhook.zip"
Invoke-WebRequest -Uri "https://github.com/TsudaKageyu/minhook/archive/refs/tags/v1.3.3.zip" -OutFile $zip
Expand-Archive -Force -Path $zip -DestinationPath $env:TEMP
Copy-Item -Recurse -Force "$env:TEMP\minhook-1.3.3\*" $dest
```

### 2. Cert de teste (assina driver + é o mesmo que a VM confia)

```powershell
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
  -Subject "CN=AffCtl Test Cert" -CertStoreLocation "Cert:\CurrentUser\My" `
  -KeyUsage DigitalSignature -KeyExportPolicy Exportable `
  -NotAfter (Get-Date).AddYears(5) -HashAlgorithm SHA256
$cert.Thumbprint  # anote para os comandos de sign abaixo
Export-Certificate -Cert $cert -FilePath "dist\vm-payload\AffCtlTest.cer" -Force
```

---

## Build

```powershell
$msb = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\amd64\MSBuild.exe"
$root = "C:\Users\<user>\display-affinity-lab"

# Driver
& $msb "$root\driver\affctl.vcxproj" /p:Configuration=Release /p:Platform=x64 `
  /p:VisualStudioVersion=17.0 /p:SignMode=Off /p:EnableInf2cat=false `
  /v:minimal /nologo /t:Rebuild

# Apps + DLLs
& $msb "$root\app\affapp.vcxproj"        /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo /t:Rebuild
& $msb "$root\afftarget\afftarget.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo /t:Rebuild
& $msb "$root\affbypass\affbypass.vcxproj" /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo /t:Rebuild
& $msb "$root\hellodll\hellodll.vcxproj"   /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo /t:Rebuild

# Assina o driver
$st = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
& $st sign /fd SHA256 /sha1 <THUMBPRINT_DO_CERT> "$root\driver\x64\Release\affctl.sys"

# Empacota
$out = "$root\dist\vm-payload"
Copy-Item "$root\driver\x64\Release\affctl.sys"       $out -Force
Copy-Item "$root\app\x64\Release\affapp.exe"          $out -Force
Copy-Item "$root\afftarget\x64\Release\afftarget.exe" $out -Force
Copy-Item "$root\affbypass\x64\Release\affbypass.dll" $out -Force
Copy-Item "$root\hellodll\x64\Release\hellodll.dll"   $out -Force
$zip = "$root\dist\vm-payload.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$out\*" -DestinationPath $zip
```

---

## Setup da VM (Hyper-V Gen 2)

```powershell
# Cria VM Gen 2 sem Secure Boot (Secure Boot bloqueia Test Signing)
$vm  = "Win10-AffCtl"
$iso = "C:\path\to\Windows.iso"
$vhd = "C:\HyperV\$vm\$vm.vhdx"
New-VHD -Path $vhd -SizeBytes 60GB -Dynamic | Out-Null
New-VM -Name $vm -Generation 2 -MemoryStartupBytes 4GB -VHDPath $vhd -SwitchName "Default Switch"
Add-VMDvdDrive -VMName $vm -Path $iso
Set-VMFirmware -VMName $vm -EnableSecureBoot Off -FirstBootDevice (Get-VMDvdDrive -VMName $vm)
Set-VMProcessor -VMName $vm -Count 2
Start-VM $vm ; vmconnect.exe localhost $vm
```

Instala o Windows normalmente. Depois copie o `vm-payload.zip` pra dentro da
VM (Enhanced Session copy/paste) e, num **cmd Admin**:

```
setup-vm.bat     REM importa cert e liga testsigning
REM reinicie a VM
sc query affctl  REM ainda nao existe, normal
```

Tire um **checkpoint** ("pre-driver-load") no Hyper-V Manager antes de carregar
o driver — se der BSOD, restaura em segundos.

---

## Rodando a demo end-to-end (na VM, cmd Admin)

```
install.bat
sc query affctl
REM STATE deve ser 4 RUNNING
```

### Baseline (proteção FUNCIONA sem hook)

```
afftarget.exe
REM anota o PID mostrado no titulo da janela
REM clica "Proteger" -> status vira 0x11
```

Em outro cmd:
```
affapp.exe --capture "%USERPROFILE%\Desktop\1-baseline.bmp" 5
```
Abre o BMP: a janela do afftarget aparece **preta** (ou sumida — depende da
build do Windows). Proteção funcional.

### Injeta o hook via kernel

```
taskkill /f /im afftarget.exe
del "%TEMP%\affbypass_status.txt" 2>nul
afftarget.exe
REM anota o novo PID
```

**Sem** clicar em Proteger, injeta:
```
affapp.exe --inject <PID_NOVO> affbypass.dll
```
Espera ver `[inject] OK — DLL 'affbypass.dll' aparece nos modulos do PID N`.

```
type "%TEMP%\affbypass_status.txt"
REM affbypass engajado (hook instalado)
```

Agora clica **Proteger** algumas vezes no afftarget e depois:
```
type "%TEMP%\affbypass_status.txt"
REM affbypass ativo (interceptando)
REM Chamadas ate agora: N  <- prova numerica do hook
```

Captura de novo:
```
affapp.exe --capture "%USERPROFILE%\Desktop\2-bypass.bmp" 5
```

Abre o BMP: a janela aparece **colorida** (listras + "AffCtl TARGET"), mesmo
tendo clicado em Proteger. Bypass end-to-end via kernel injection **provado**.

### Modos adicionais do `affapp.exe`

| Comando | Descrição |
|---|---|
| `affapp.exe` | Modo legado: discovery + demo clássica. Não funciona em Win10/11 modernos (documentado nos findings). |
| `affapp.exe --guard` | Modo cabo-de-guerra (legado). |
| `affapp.exe --inject <pid> <dll>` | Injeção kernel-APC de DLL arbitrária em processo alvo. |
| `affapp.exe --capture <out.bmp> [delaySec]` | Captura desktop inteiro (contorna Snipping Tool). |
| `affapp.exe --probe-dwm` | Reality-check do PDB de `dwmcore.dll`. Prova quantos símbolos internos a Microsoft strippou. |

---

## Detalhes técnicos por camada

### Driver → apesar de ~500 linhas, cobre:

- Layout parcial de `SHAREDINFO`/`HANDLEENTRY` (validado empiricamente em Win11
  25H2: entries de 32 bytes, `bType`/`wUniq` em `+0x18/+0x1A`).
- `MmIsAddressValid` + `__try/__except` em toda desreferência de ponteiro
  vindo do user-mode. **Zero BSOD** em todos os testes.
- `KeStackAttachProcess` + `ZwAllocateVirtualMemory` no espaço do alvo com
  cleanup rigoroso em cada caminho de erro.
- `KeInitializeApc`/`KeInsertQueueApc` (`UserMode`, `NormalRoutine =
  LoadLibraryW`) com `KernelRoutine` que libera a KAPC.

### App user-mode

- Resolução de símbolos internos do `win32kbase.sys` via `dbghelp` +
  `_NT_SYMBOL_PATH` apontando pro Symbol Server da Microsoft. Cache local em
  `%TEMP%\SymCache`.
- Enumeração de threads via `Toolhelp32Snapshot(TH32CS_SNAPTHREAD)`; injeção
  "shotgun" em todas as threads (tolerante a threads não-alertable).
- `GetProcAddress(kernel32!LoadLibraryW)` — mesmo VA base em todos os
  processos da sessão (ASLR per-boot).

### `afftarget` — loop alertable

Chave pra APC delivery confiável:

```cpp
for (;;) {
    DWORD r = MsgWaitForMultipleObjectsEx(0, nullptr, INFINITE,
                                          QS_ALLINPUT, MWMO_ALERTABLE);
    if (r == WAIT_IO_COMPLETION) continue;  // APC disparou
    if (r == WAIT_OBJECT_0) { /* pump */ }
}
```

`GetMessage` clássico **não** é alertable — APCs só disparam por acidente. Com
`MWMO_ALERTABLE`, a thread entra em alertable wait entre mensagens, e nossa
APC dispara em milissegundos.

### `affbypass` — hook inline via MinHook

```cpp
MH_Initialize();
FARPROC target = GetProcAddress(user32, "SetWindowDisplayAffinity");
MH_CreateHook(target, &Hook_SetWindowDisplayAffinity, (LPVOID*)&g_origSet);
MH_EnableHook(target);
```

Hook simplesmente retorna `TRUE` — o Windows/DWM nunca sabe que a proteção
foi pedida. Alternativa seria patch inline manual (~40 linhas de x64 asm);
MinHook foi escolhido por robustez.

---

## Riscos conhecidos e limitações

- **Legacy `IOCTL_CLEAR_AFFINITY`/`IOCTL_READ_RANGE`**: presentes por
  completude histórica; **não fazem nada útil em Windows moderno** (WDA foi
  pro DWM).
- **Alvo em AppContainer** (ex: novo Notepad no Win11 24H2+): injeção falha
  silenciosamente. Solução: alvos Win32 clássicos (nosso `afftarget`).
- **HVCI ligado**: pode restringir algumas operações; não testado
  exaustivamente. Recomendado desligar em ambiente de teste.
- **Assinatura de driver**: requer cert de teste + Test Signing ON. Não é
  distribuível como driver de produção sem EV cert + Microsoft Partner Center.
- **DWM**: attack real de `WDA_EXCLUDEFROMCAPTURE` em processos protegidos
  exigiria RE do `dwmcore.dll` (PDB stripped) — fora deste PoC.

---

## Referências técnicas

- [KeStackAttachProcess](https://learn.microsoft.com/windows-hardware/drivers/ddi/ntddk/nf-ntddk-kestackattachprocess)
- [KeInitializeApc / KeInsertQueueApc](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializeapc)
- [ZwAllocateVirtualMemory](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)
- [SymFromName / dbghelp](https://learn.microsoft.com/windows/win32/api/dbghelp/nf-dbghelp-symfromname)
- [MinHook](https://github.com/TsudaKageyu/minhook) — BSD-2-Clause
- Windows Internals, 7th Ed. (Yosifovich et al.) — cap. Windowing e I/O
- [Alex Ionescu, "Windows Internals"](https://www.alex-ionescu.com/) — posts sobre `_HANDLEENTRY`

---

## Licença

MIT (ver `LICENSE`). MinHook em `third_party/minhook/` mantém sua própria
licença (BSD-2-Clause).
