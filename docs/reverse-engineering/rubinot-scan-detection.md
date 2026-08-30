# Rubinot — Vetor Primário de Detecção de Debugger

> **Data:** 2026-08-28
> **Setup usado:** x64dbg + ScyllaHide (profile VMProtect) + x64dbg-MCP-Server + IFEO em `rubinot_dx.exe`, driver EMAC (`EMACDRVGLTB`) rodando.
> **Alvo:** `C:\Program Files (x86)\RubinOT 2.0\bin\x64\rubinot_dx.exe` (VMProtect-protected).
> **Escopo:** documentar o mecanismo pelo qual o cliente do jogo detecta a presença do debugger x64dbg e provocar shutdown gracioso, e a contramedida validada. Relevante pra **Fase B1** deste projeto (injeção kernel APC via `IOCTL_INJECT_DLL`) — o mesmo mecanismo é o que faz nossa injeção falhar contra esse alvo específico.

---

## TL;DR

1. O binário `rubinot_dx.exe` chama **`NtQuerySystemInformation(SystemProcessInformation, class=5)`** logo cedo na init, **antes** do `emac-client64.dll` sequer ser carregado. A chamada é feita direto no syscall stub do ntdll — **não passa por `kernelbase!EnumProcesses`** — bypassando qualquer inline hook em APIs de mais alto nível.
2. O `call` sai de **shellcode em endereço baixo (`0x1E31A0` na região `0x1E0000..0x1EA000`, mapping RWX de 40KB)**. Essa região **não é seção PE** — é código descriptografado em runtime pelo próprio VMProtect que embala o binário.
3. O kernel devolve um buffer de ~950KB com o array completo de `SYSTEM_PROCESS_INFORMATION` (todos os processos do sistema com `ImageName` UNICODE_STRING). O rubinot itera essa lista comparando com uma blacklist de nomes de debuggers/inspetores conhecidos (`x64dbg`, provavelmente também `ollydbg`, `ida`, `cheatengine`, `procmon`, `wireshark`, etc).
4. Ao encontrar `x64dbg.exe` na lista, o rubinot **não trava** — dispara `ExitThread` em cascata pelas suas threads (dezenas delas) e depois `ExitProcess`. Sem exception, sem crash. Padrão de shutdown "silenciado".
5. **Contramedida validada por reversão:** basta **renomear `x64dbg.exe` pra outro nome** (`notepadd.exe` no teste) e re-registrar IFEO com o novo path. A blacklist do rubinot não matcha `notepadd`, o scan passa, e a init termina normal. Sem custom ScyllaHide profile, sem driver bypass. Rubinot chega em runtime (tela de login/splash).

---

## Como o scan foi descoberto

### 1. Sintoma inicial

Rubinot sempre terminava graciosamente entre 5–20s depois de iniciar sob x64dbg. **Sem crash**, sem exception no event log — apenas cascata de `[Thread exited]` events e `[Process exited]`. Isso indica **decisão consciente** (chamada direta a `ExitProcess`), não crash por hook detectado.

Padrão observado em três sessões consecutivas:
- Sem driver EMAC (`EMACDRVGLTB` stopped): morria durante init do `emac-client64!DllMain` (~10s, 19 threads exiting).
- Com driver EMAC RUNNING: passava emac init, carregava NVIDIA drivers (`nvgpucomp64`, `nvmemmapstoragex`, `nvwgf2umx`, `nvppex`), entrava no `exitlag.dll` e morria em `exitlag+0x542890` (~20s, 48 threads exiting).

### 2. Hipóteses testadas e refutadas

- **Inline hook em `LdrLoadDll` / `NtProtectVirtualMemory`:** prólogos em memória lidos byte-a-byte no system BP e no EP eram **idênticos** ao `ntdll.dll` do disco (versão 10.0.19041.4842). Sem hook.
- **Scan por `NtQueryInformationProcess(ProcessImageFileName=27)` iterando handles:** vários hits capturados, todos com `rcx=-1` (self-check do próprio rubinot). Nunca foi usado pra ler nome de outros processos.

### 3. Hipótese confirmada

- **Scan por `NtQuerySystemInformation(SystemProcessInformation=5)`:** primeira chamada que capturei (BP condicional filtrado `rcx==5`), veio de endereço `0x1E31A0` — **fora dos módulos PE do processo**. Verificado no memory map: essa região é `0x1E0000 | 0xA000 | RWX`. Alocação dinâmica RWX no início do processo = clássico de VMProtect descomprimindo código de proteção.

### 4. Prova por dump + grep

Dumpei o buffer que o kernel preencheu (~950KB) em disco e greppei em UTF-16LE:

```
--- Sessão inicial (x64dbg com nome real):
Matches de 'x64dbg' (UTF-16LE): 1
  Offset 0x73AA0 (abs 0x26A3B20) — x64dbg.exe

--- Sessão após rename x64dbg → notepadd:
Matches de 'x64dbg' (UTF-16LE): 0
Matches de 'notepadd' (UTF-16LE): 1
  Offset 0x73508 — notepadd.exe
```

### 5. Prova por reversão (end-to-end)

Renomeei `x64dbg.exe` pra `notepadd.exe`, re-registrei IFEO apontando pro clone, rodei rubinot direto. Resultado:

| Métrica | x64dbg (nome real) | notepadd (renomeado) |
|---|---|---|
| Status após 3 min | `NO_TARGET` (morto ~15s) | `RUNNING` (vivo, 3+ min) |
| Threads criadas | 48 (todos exit) | 93 e crescendo |
| RAM usada | ~500 MB | **2.1 GB** |
| Módulo ativo no ponto de shutdown | `exitlag+0x542890` (morrendo) | `exitlag.dll` (ativo, rodando) |

Rubinot chegou em tela de login/splash — os 2.1 GB de RAM são assets 3D do cliente MMO carregando.

---

## Disassembly do call site do scan

Do shellcode em `0x1E31A0` (RWX region, dinâmico — offset varia entre execuções por conta de ASLR):

```asm
0x1E31A0: mov rax, rsp                         ; frame pointer
0x1E31A3: mov [rax+8], rbx                     ; save volatiles no shadow space
0x1E31A7: mov [rax+18], rbp
0x1E31AB: mov [rax+20], rsi
0x1E31AF: push rdi
0x1E31B0: sub rsp, 0x20                        ; shadow space
0x1E31B4: xor edx, edx                         ; SystemInformation = NULL (probe)
0x1E31B6: lea r9, [rax+10]                     ; &ReturnLength
0x1E31BA: mov rbp, rcx                         ; salva rcx original (arg passado ao caller)
0x1E31BD: xor r8d, r8d                         ; SystemInformationLength = 0
0x1E31C0: lea edi, [rdx+5]                     ; SystemInformationClass = 5 (SystemProcessInformation)
0x1E31C3: mov ecx, edi
0x1E31C5: call [<NtQuerySystemInformation>]    ; via IAT patchado do shellcode
0x1E31CB: cmp eax, C0000004                    ; STATUS_INFO_LENGTH_MISMATCH
0x1E31D0: jne 1E326F                           ; se ≠, salta pra tratamento de erro
                                                ; se ≡, cai adiante: aloca buffer e refaz call
```

Segunda chamada (real, com buffer alocado):
- `rcx = 5` (SystemProcessInformation)
- `rdx = <endereço alocado>` (heap; observamos `0x25F0080` e `0x2630080` em duas execuções)
- `r8 = 0xE79B0 / 0xE8170` (~950KB — length exato do buffer retornado no ReturnLength da probe)
- `r9 = 0` ou `NULL`

O kernel retorna `STATUS_SUCCESS` e preenche o buffer com array de `SYSTEM_PROCESS_INFORMATION`. Cada entrada tem no offset `0x38` um `UNICODE_STRING` `ImageName` com pointer pro nome do executável (`svchost.exe`, `notepad.exe`, ..., `x64dbg.exe`).

---

## Contramedidas ranqueadas

Aplicáveis pra Fase B1 deste projeto — nossa DLL injetada `affbypass.dll` cai no mesmo tipo de detecção se o alvo enumerar módulos com nome distintivo.

### Curto prazo (validado hoje)

**1. Renomear executáveis de dev pra nomes não-blacklistados.**

- Custo: 5 minutos.
- Efetividade: 100% validada no rubinot pra debugger.
- Como: copiar `x64dbg.exe` como `notepadd.exe` (mesma pasta, todo o resto — DLLs, plugins, config — continua com nome original; o loader hardcoda `x64dbg.dll` como target, não deriva do próprio nome do exe).
- Ajustar IFEO ou atalhos pra usar o novo nome.

**2. Renomear a DLL injetada do projeto.**

- Aplicar mesmo princípio pra `affbypass.dll`. Nomes que se camuflam bem:
  - `d3d11helper.dll`
  - `nvcuda_helper.dll`
  - `dbgcore_ext.dll`
- Nenhum código do `affbypass.dll` muda — só o filename do artefato de build (`affbypass.vcxproj` → `<OutputFile>`).
- Rubinot enumerando módulos do próprio processo (via `PEB.Ldr` walking ou `NtQuerySystemInformation(SystemModuleInformation=0x0B)`) não vai identificar como suspeita.

### Médio prazo (investigado — não é prioridade)

**3. ~~Verificar se o driver `affctl.sys` é enumerado por rubinot.~~ Investigado — rubinot não detecta.**

Veja a [Sessão 6](#sessão-6--rubinot-detecta-o-driver-affctl) abaixo. Resumo: o `affctl` aparece na enumeração user-mode de drivers kernel (`driverquery` confirma path completo `\??\C:\Users\xyrlan\display-affinity-lab\driver\x64\Debug\affctl.sys`), mas o rubinot sobreviveu 75s+ em estado saudável (108 threads, 1.9 GB RAM, `emac-client64` + `exitlag` + NVIDIA + D3D todos carregados) com `affctl` RUNNING. Rename do driver **não é necessário no momento**.

Recomendação atualizada: continuar usando o nome `affctl.sys`. Reavaliar se o rubinot receber update do módulo anti-cheat (`emac-client64.dll` versão diferente) — a blacklist pode ser expandida em novas versões.

### Longo prazo (produção)

**4. Filtro kernel próprio no output de `NtQuerySystemInformation`.**

Nosso driver `affctl` já roda em kernel-mode. Pode registrar um **PsSetLoadImageNotifyRoutine** ou **hookar `ExAllocatePoolWithTag`** pra interceptar buffers preenchidos pelo `NtQuerySystemInformation` e remover entradas cujo `ImageName` matche uma lista custom (nossa DLL, nosso driver, outras ferramentas de dev). Requisito: driver precisa estar carregado antes do alvo iniciar. **Não implementar sem revisão de segurança** — hook em kernel é vetor de instabilidade e ameaças reais.

**5. Alternativa: PPL / ETW hiding.**

Se a DLL injetada for carregada em um processo PPL (`SYSTEM_LEAST` ou acima), enumerações user-mode não conseguem enumerar seus módulos com o nível de detalhe do `SystemProcessInformation`. Requer signing especial da nossa DLL e do driver. Alto custo, altíssima robustez.

---

## Como reproduzir a análise

### Setup mínimo

1. x64dbg instalado + plugin `x64dbg-MCP-Server.dp64` + ScyllaHide profile VMProtect.
2. IFEO em `rubinot_dx.exe` apontando pro `x64dbg.exe` (ou clone renomeado).
3. Driver EMAC (`EMACDRVGLTB`) — se stopped, rubinot termina antes do scan. Rodar `sc start EMACDRVGLTB` como admin antes.
4. **Não usar** o launcher `RubinOT.exe` — ele lança rubinot com flag herdada de debug que quebra x64dbg (documentado em memory `x64dbg-mcp-setup.md`). Lançar direto: `Start-Process 'C:\Program Files (x86)\RubinOT 2.0\bin\x64\rubinot_dx.exe'`.

### Sequência x64dbg (via comandos ou MCP)

```
# 1. Sistema BP hit em ntdll — remover BPs auto pra reduzir ruído
bpc 0x1431BF5B0                                    # TLS Callback 1
bpc 0x1431BFA00                                    # TLS Callback 2
bpc 0x1431BFDC0                                    # entry breakpoint

# 2. BP condicional em NtQuerySystemInformation(rcx==5)
bp ntdll:NtQuerySystemInformation
bpcnd <address>, "rcx==5"
bpcmdcnd <address>, "rcx!=5"
bpcmd <address>, "run"

# 3. Correr
run
# → primeiro hit: probe (rdx=NULL)
run
# → segundo hit: chamada real (rdx=buffer, r8=length)

# 4. StepOut duas vezes pra sair do syscall stub e voltar ao caller
sto
sto
# → estamos no ret do shellcode caller (endereço baixo tipo 0x1E3285)

# 5. Dump do buffer pra disco
savedata <path>, <rdx da segunda call>, <r8 da segunda call>
```

### Grep no buffer (PowerShell)

```powershell
$file = '<path>'
$bytes = [System.IO.File]::ReadAllBytes($file)
$needle = [System.Text.Encoding]::Unicode.GetBytes("x64dbg")
$plen = $needle.Length
for ($i = 0; $i -le $bytes.Length - $plen; $i++) {
    $match = $true
    for ($j = 0; $j -lt $plen; $j++) {
        if ($bytes[$i+$j] -ne $needle[$j]) { $match = $false; break }
    }
    if ($match) { "Match no offset 0x$('{0:X}' -f $i)" }
}
```

Se achar match → nome está no buffer → rubinot vai detectar.

### Setup rename + IFEO (comando único)

```powershell
$src = 'C:\Users\<você>\...\x64dbg\release\x64\x64dbg.exe'
$dst = Join-Path (Split-Path $src) 'notepadd.exe'
Copy-Item $src $dst -Force
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rubinot_dx.exe' `
    -Name Debugger -Value ('"' + $dst + '"')
```

### Rollback

```powershell
Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\rubinot_dx.exe' `
    -Name Debugger -Value '"C:\Users\<você>\...\x64dbg.exe"'
Remove-Item 'C:\Users\<você>\...\notepadd.exe' -Force
sc.exe stop EMACDRVGLTB
```

---

## Endereços observados (referência rápida)

Valores **relativos ao módulo** (RVA) — resistem a ASLR entre execuções. Bases variam a cada boot.

| Símbolo | RVA | Nota |
|---|---|---|
| `rubinot_dx.exe!entry` | `+0x31BFDC0` | `mainCRTStartup` MSVC vanilla |
| `rubinot_dx.exe!TLS Callback 1` | `+0x31BF5B0` | `__dyn_tls_init` (só executa em `THREAD_ATTACH`) |
| `rubinot_dx.exe!TLS Callback 2` | `+0x31BFA00` | `__dyn_tls_dtor` |
| `.vmp0` (data) | `+0x6571000` | 100 KB, RC- |
| `.vmp0` (code) | `+0x658A000` | 4.3 MB, R-X — bytecode virtualizado do VMProtect |
| `CPADinfo` | `+0x64D4000` | 4 KB — marca característica do VMProtect |
| `.fptable` | `+0x64D5000` | 4 KB — populada em runtime com ptrs pras funções virtualizadas (Call Gate) |
| Shellcode RWX do scan | `~0x1E0000` (não é PE) | 40 KB — descriptografado pelo VMProtect no init |
| `emac-client64!DllMain` | `+0x111A34E` | Prolog obfuscado `sub rsp,A18; jmp +A; ...` |
| `emac-client64!NtSetInformationThread(HideFromDebugger)` call site | `+0x89ECD3` | Anti-debug do emac, interceptado por ScyllaHide |
| `emac-client64!NtSetInformationThread` call site (thread factory) | `+0x8D8FAD` | Segundo call site, per-thread |

---

## Sessão 6 — Rubinot detecta o driver `affctl`?

> **Data:** 2026-08-28
> **Setup:** `EMACDRVGLTB` RUNNING, `affctl` (nosso driver kernel de dev) RUNNING, rubinot rodado **sem debugger** (IFEO limpo temporariamente pra isolar variáveis).

### Motivação

A [contramedida #3](#médio-prazo-investigado--não-é-prioridade) especulava que se o rubinot chamasse `NtQuerySystemInformation(SystemModuleInformation=0x0B)`, o path do nosso driver (`C:\Users\xyrlan\display-affinity-lab\driver\x64\Debug\affctl.sys`) vazaria o nome do projeto e o driver poderia ser blacklistado. Antes de comprometer sessão RE dedicada, foi possível encaixar um experimento cirúrgico que dispensa debugger.

### Metodologia

1. **Confirmar visibilidade user-mode do driver.** `driverquery /v` (que internamente chama `NtQuerySystemInformation(0xB)`) foi executado como usuário admin comum. Resultado:

   ```
   ModuleName  : affctl
   DisplayName : affctl
   State       : Running
   Path        : \??\C:\Users\xyrlan\display-affinity-lab\driver\x64\Debug\affctl.sys
   ```

   O driver aparece no output entre 398 outros drivers do sistema. Path completo inclui `affctl` e `display-affinity-lab` — qualquer scanner que faça `wcsstr(path, L"affctl")` ou padrões heurísticos (`"lab"`, `"bypass"`, `"debug"`) bate.

2. **Isolar o vetor.** IFEO removido temporariamente (backup em scratchpad), rubinot rodado direto sem debugger anexado. Assim, se o rubinot morrer, a única variável nova é o `affctl` — o mecanismo de detecção de debugger via `SystemProcessInformation` (Sessões 4–5) não pode ser gatilho.

3. **Amostragem de sobrevivência.** Rubinot iniciado, medido a cada 15s por 60s: threads, RAM, CPU, módulos carregados.

### Resultado

| t | Threads | RAM | CPU acum | Estado |
|---|---|---|---|---|
| +15s | 109 | 2193 MB | — | Ativo, carregando assets |
| +30s | 107 | 1930 MB | 28.9s | Estável (GC de assets iniciais) |
| +45s | 108 | 1930 MB | 30.8s | Estável |
| +60s | 108 | 1930 MB | 32.6s | Estável |
| +75s | 106 | 1930 MB | 34.4s | Estável |

Módulos observados no snapshot (119 total, filtro pelos relevantes):
- `emac-client64.dll` — anti-cheat principal, carregado e ativo
- `exitlag.dll` — SDK de network overlay, carregado
- `splash.dll` — bootscreen do cliente
- `d3d11.dll`, `d3d9.dll`, `d3dcompiler_47.dll` — renderer inicializado
- `nvd3dumx.dll`, `nvgpucomp64.dll`, `nvwgf2umx.dll` — driver NVIDIA carregado

Rubinot chegou em runtime completo (tela de login/splash), mesmo padrão do estado saudável da Sessão 5.

### Conclusão

**O rubinot não detecta o `affctl` como driver hostil.** Duas explicações plausíveis:

1. **Rubinot não faz scan de módulos kernel** — o mecanismo confirmado nas Sessões 4–5 é scan de processos user-mode (`SystemProcessInformation=5`). O emac pode não fazer o equivalente de `SystemModuleInformation=0xB`.
2. **Rubinot faz o scan, mas a blacklist do emac só contém strings de debuggers/inspetores conhecidos** (`x64dbg`, `ollydbg`, `ida`, `cheatengine`, `procmon`, `wireshark`, etc), sem heurística genérica pra nomes suspeitos como `affctl` ou `lab`.

Não há evidência empírica pra separar (1) de (2) sem confirmação por RE. Mas ambos resultam em: **manter o nome `affctl.sys` do driver não bloqueia a integração com rubinot.**

### Contramedida atualizada

**Nenhuma ação imediata necessária.** Manter o build atual (`affctl.sys` com path de dev).

Reavaliar se:
- `emac-client64.dll` receber update com hash/tamanho diferente do observado (mudança de versão indica que a blacklist pode ter mudado)
- Aparecer sintoma de shutdown gracioso pós-injeção que não seja explicado pela detecção da DLL user-mode

### Verificação RE opcional (não executada — evidência empírica é suficiente)

Se em uma sessão futura for necessário confirmar categoricamente se o rubinot chama `NtQuerySystemInformation(0xB)`:

```
bp ntdll:NtQuerySystemInformation
bpcnd <address>, "rcx==0xB"
bpcmdcnd <address>, "rcx!=0xB"
bpcmd <address>, "run"
run
```

Se bater → dumpar buffer e greppar `affctl`. Se não bater durante toda init até tela de login → rubinot definitivamente não usa esse class.

---

## Sessão 7 — Fase B1 contra rubinot: injeção user-mode bloqueada em kernel

> **Data:** 2026-08-28
> **Setup inicial:** IFEO → notepadd, drivers `EMACDRVGLTB` + `affctl` RUNNING, rubinot iniciado sob x64dbg.
> **Objetivo:** confirmar por que a Fase B1 (injeção kernel APC + hook inline em `user32!SetWindowDisplayAffinity` via `affbypass.dll`) falha contra rubinot, e mapear as camadas de defesa que o anti-cheat aplica.

### TL;DR

1. `user32!SetWindowDisplayAffinity` é literalmente **6 bytes de forwarder** pra `win32u!NtUserSetWindowDisplayAffinity`. Hookar em user32 só funciona se o caller passa por `GetProcAddress(user32, "SetWindowDisplayAffinity")`.
2. A **injeção kernel APC funciona tecnicamente** contra rubinot pré-login — provamos que o trampolim shellcode + `LdrLoadDll` carrega nossa `nvdlss_helper.dll`, `DllMain` roda, e o hook MinHook é instalado (status file: `"engajado (hook instalado)"`).
3. Encontramos duas causas **colaterais** que estavam mascarando a análise:
   - **Build mismatch** — o `affapp.exe` distribuído resolvia `LoadLibraryW`, mas o trampolim do [driver/inject.cpp:112](driver/inject.cpp:112) monta args de `LdrLoadDll`. `LoadLibraryW(NULL, ...)` retorna handle do próprio módulo sem carregar nada. **Rebuild** do `affapp.vcxproj` corrigiu.
   - **Shotgun APC deadlockeia o loader** — enfileirar APCs de `LdrLoadDll("nvdlss_helper.dll")` em 100+ threads simultâneas satura o `LdrpLoaderLock`. Todas as threads acabam em `Wait` (35 `EventPairLow`, 28 `Unknown`, 27 `UserRequest`, 8 `Executive`, 3 `ExecutionDelay`), UI thread parkia no lock → `MainWindowHandle = 0`, rubinot vira "cadáver funcional".
4. **A causa REAL** de a Fase B1 não bypassar a proteção in-game é o driver kernel **`EMACDRVGLTB`** (`EMAC-Driver-GL-TB-x64.sys`). Ele registra callbacks kernel-mode que:
   - **Strippam handles de terceiros contra rubinot** — `EnumProcessModules` retorna `ACCESS_DENIED (GLE=5)` mesmo com `PROCESS_QUERY_LIMITED_INFORMATION|VM_READ` válido. Isso é `ObRegisterCallbacks(ObTypeProcess)` filtrando acesso.
   - **Bloqueiam carga de DLLs foráneas via `PsSetLoadImageNotifyRoutine`** — nosso `--global-hook` (SetWindowsHookEx WH_GETMESSAGE + WH_CBT + WH_CALLWNDPROC) instalou com sucesso do lado do affapp, mas a DLL **nunca** carregou no rubinot in-game. Sem status file, sem `%TEMP%\affbypass_status.txt`. Windows tentou, kernel vetou.
5. **Prova visual final:** com o `--global-hook` armado e o usuário logado in-game, a janela do rubinot **ficou preta** no Snipping Tool → `SetWindowDisplayAffinity(hWnd, WDA_MONITOR)` foi chamado com sucesso pelo rubinot via API real, sem intercepção nossa. Confirma que a proteção está funcional e nosso hook não engajou.

Conclusão pragmática: **rubinot é um alvo comercial protegido em kernel-mode.** A Fase B1 do projeto (desenhada como PoC educacional contra `afftarget.exe` conforme o [README](../../README.md)) não é ferramenta pra atacar anti-cheats comerciais — e não deveria ser.

---

### Achado 1 — `user32!SetWindowDisplayAffinity` é forwarder de 6 bytes

Antes de qualquer teste, lemos o prólogo de `user32!SetWindowDisplayAffinity` (base `0x7FFBEE0B0000` + `+0x359B0`) via `Disassemble`:

```asm
0x7FFBEE0E59B0: FF 25 22 E9 05 00    jmp qword ptr ds:[<NtUserSetWindowDisplayAffinity>]
0x7FFBEE0E59B6: CC CC CC CC CC       int3 padding
```

E `win32u!NtUserSetWindowDisplayAffinity` (base `0x7FFBED320000` + `+0xAF10`):

```asm
0x7FFBED32AF10: 4C 8B D1              mov r10, rcx
0x7FFBED32AF13: B8 F7 14 00 00        mov eax, 14F7            ; syscall #
0x7FFBED32AF18: F6 04 25 08 03 FE 7F 01  test byte ptr ds:[7FFE0308], 1  ; SystemCallProvider
0x7FFBED32AF20: 75 03                 jne 7FFBED32AF25
0x7FFBED32AF22: 0F 05                 syscall
0x7FFBED32AF24: C3                    ret
0x7FFBED32AF25: CD 2E                 int 2E
0x7FFBED32AF27: C3                    ret
```

Implicação pro hook do `affbypass.cpp`: MinHook substitui os primeiros 5 bytes de `user32!SetWindowDisplayAffinity` com `jmp <hook>`. **Se o caller resolve via `GetProcAddress(user32, "SetWindowDisplayAffinity")`, o hook engaja.** Se o caller resolve `GetProcAddress(win32u, "NtUserSetWindowDisplayAffinity")` direto ou emite o syscall bruto (`mov r10,rcx; mov eax,14F7; syscall`) via bytecode virtualizado (VMProtect), o hook em user32 **nunca é acionado**.

Verificar isso empiricamente ficou impossível pelo motivo do Achado 4 — nossa DLL nunca chegou a rodar no rubinot in-game.

---

### Achado 2 — Injeção APC funciona (com fixes)

Setamos BPs em `ntdll!KiUserApcDispatcher`, `kernel32!LoadLibraryW` e `ntdll!LdrLoadDll`. Rodamos `affapp --inject 7016 nvdlss_helper.dll`. Resultado da **primeira** tentativa:

- `KiUserApcDispatcher` disparou (APC dispatched — hipótese "threads não alertable" refutada, todas as 92 threads receberam APC)
- BP em `kernel32!LoadLibraryW` disparou, mas `rcx=0` (arg1 = `NULL`) → `LoadLibraryW(NULL)` retorna handle do próprio módulo sem carregar
- DLL nunca apareceu nos módulos

Análise dos registros na chegada do BP:
- `rbx = 0x2A60000` = view base (nosso `remoteView` do driver)
- `r8 = 0x2A60090` = `rbx + 0x90` = ponteiro pra nossa `UNICODE_STRING` (exatamente `kUnicodeStringOffset`)
- `r9 = 0x169F6B0` = ponteiro na stack (nosso `&out_BaseAddress` local)
- `rcx = 0, rdx = 0` = `SearchPath = NULL, DllChars = NULL` (assinatura correta de `LdrLoadDll`)

Ou seja: o trampolim shellcode montou args pra `LdrLoadDll(NULL, NULL, &UNICODE_STRING, &out)` — mas caiu em `LoadLibraryW`. Grep binário no `affapp.exe` velho:

```
ASCII 'LoadLibraryW':  3 hits (0xABE04, 0xACCD3, 0xAE7E8)
ASCII 'LdrLoadDll':    0 hits
```

O binário resolvia `GetProcAddress(kernel32, "LoadLibraryW")`, mas o [Injector.cpp:61](app/Injector.cpp:61) atual e o trampolim do [driver/inject.cpp:112](driver/inject.cpp:112) esperam `LdrLoadDll`. **Discrepância build × source** — o exe estava desatualizado. Fix:

```powershell
msbuild affapp.vcxproj /p:Configuration=Release /p:Platform=x64 /t:Rebuild
```

Novo binário, novo grep: `ASCII 'LdrLoadDll'` = 3 hits. Re-injetamos, e desta vez o BP em `LdrLoadDll` bateu com o layout correto:

```
Registros no LdrLoadDll:
  rcx = 0                     (SearchPath = NULL)
  rdx = 0                     (DllCharacteristics = NULL)
  r8  = 0x2BC0090             (&UNICODE_STRING)
  r9  = 0xE67F6B0             (&out_BaseAddress na stack)

UNICODE_STRING (16 bytes @ r8):
  Length        = 0x98 = 152 bytes (76 chars)
  MaximumLength = 0x9A = 154 bytes
  Buffer        = 0x02BC00A0

Path (@ Buffer, 152 bytes UTF-16LE):
  "C:\Users\xyrlan\display-affinity-lab\affbypass\x64\Release\nvdlss_helper.dll"
```

Deixamos o `LdrLoadDll` retornar. Status file:

```
affbypass engajado (hook instalado)
PID: 7016
Hora: 2026-08-28 14:38:07
Chamadas ate agora: 0
```

**Prova end-to-end da Fase B1 pré-login**: DLL carrega, `DllMain` roda, MinHook instala hook em `user32!SetWindowDisplayAffinity`, `hidePeb()` remove das 3 listas do PEB.Ldr (por isso `EnumProcessModules` não vê `nvdlss_helper.dll`).

---

### Achado 3 — Shotgun APC deadlockeia o loader

Após a injeção bem-sucedida (Achado 2), o rubinot ficou "vivo" (2.1 GB RAM, 102 threads, `Responding: True`) mas **`MainWindowHandle = 0`** — a janela principal nunca foi criada.

Threads agregadas por `WaitReason` (via `Get-Process | .Threads | Group-Object WaitReason`):

| Count | WaitReason | Interpretação |
|---|---|---|
| 35 | EventPairLow | Waits internos do Windows (CSRSS/LPC roundtrips) |
| 28 | Unknown | Kernel-mode waits opacos |
| 27 | UserRequest | `WaitForSingleObject/MultipleObjects` |
| 8 | Executive | `Sleep`, timer waits |
| 3 | ExecutionDelay | `Sleep()` |
| 1 | Suspended | Thread suspensa manualmente |

**102/102 threads em Wait. Zero Running. Zero Ready.** Rubinot literalmente não pode progredir.

**Diagnóstico:** o `affapp --inject` faz "shotgun APC" — enfileira uma APC em **cada** thread do PID (92 na primeira tentativa, 101 na segunda). Cada APC dispara e chama `LdrLoadDll("nvdlss_helper.dll")`. A primeira thread pega o `LdrpLoaderLock` e carrega. As outras 100 tentam pegar o mesmo lock e ficam esperando. Enquanto algum código do rubinot dentro da região crítica do loader tenta re-entrar (via callback, ou o próprio `DllMain` da nossa DLL chamando algo que toca o loader), **deadlock**. A UI thread — que ia criar a MainWindow — está numa das 100 threads paradas.

Isso é uma limitação **arquitetural** conhecida do "shotgun APC injection". A prática moderna é injetar em uma thread só (a primeira do processo, ou a thread da UI identificada por `GetWindowThreadProcessId` na MainWindow).

**Fix recomendado no projeto:** modificar [app/main.cpp:runInject](app/main.cpp) pra enfileirar APC apenas na primeira thread válida, com fallback pra segunda se `KeInsertQueueApc` retornar `FALSE`. `Injector::findFirstThreadId` já existe pra isso ([Injector.cpp:12](app/Injector.cpp:12)) — só precisa ser usado em `--inject` no lugar de `enumThreadIds`.

---

### Achado 4 — In-game, `EMACDRVGLTB` bloqueia injeção user-mode

Depois do deadlock (Achado 3), matamos rubinot, refizemos setup limpo. Tentamos passar dos system BPs sob debugger — rubinot **terminou graciosamente** (`TARGET_EXITED`) por causa da latência acumulada dos vários `erun` (rubinot tem timing check via RDTSC dentro do emac init; cada pausa nossa entre TLS callbacks adiciona 1-2s → detectado como ambiente lento).

Pivotamos pra: rodar rubinot **sem debugger**, usar `--global-hook` (não usa APC), user loga manualmente.

Sem debugger, o `rubinot_dx.exe` direto abre em modo **launcher** (título "RubinOT Launcher") — não como cliente. O binário tem lógica pra rodar como launcher OU cliente dependendo de argumentos/env; o path certo é executar `C:\Program Files (x86)\RubinOT 2.0\RubinOT.exe` (launcher genuíno), que ao clicar Play spawna `rubinot_dx.exe` com args secretos e ele roda como cliente.

Sequência que executamos:
1. `sc.exe start EMACDRVGLTB` (parou entre restarts)
2. `Start-Process 'C:\Program Files (x86)\RubinOT 2.0\RubinOT.exe'` (launcher, título "EMAC LAB Anti-Cheat")
3. `Start-Process 'C:\...\affapp.exe' --global-hook rubinot_dx.exe nvdlss_helper.dll` em background — instala SetWindowsHookEx global (3 tipos: WH_GETMESSAGE, WH_CBT, WH_CALLWNDPROC) e cria filter file `%TEMP%\affbypass_target.txt = "rubinot_dx.exe"`
4. Cliente `rubinot_dx.exe` PID 7984 subiu com título "RubinOT Client", MainWindow visível
5. Usuário logou + selecionou personagem + entrou in-game
6. **Janela do rubinot ficou preta no Snipping Tool.**

Investigação pós-fato:

| Verificação | Resultado |
|---|---|
| `%TEMP%\affbypass_status.txt` existe? | **NÃO** — DllMain nunca rodou |
| `Get-Process 7984 \| .Modules` | `Total modulos visiveis: 0` — enumeração bloqueada |
| `affapp --global-hook` PID 20224 vivo? | Sim, message pump rodando normal, log sem erros |
| Todos `Get-ProcessMitigation`? | Todas OFF (BinarySignature, ExtensionPoint, ImageLoad, DynamicCode, Payload, StrictHandle) |
| Event log `Microsoft-Windows-Security-Mitigations/UserMode` | Nenhum evento nos últimos 3 min |
| `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION\|VM_READ)` via P/Invoke | OK, handle `0xA54` |
| `EnumProcessModules(handle)` | **FALHOU — `GLE=5` (`ACCESS_DENIED`)** |

O handle abriu, mas a enumeração de módulos foi negada em kernel-mode. Como **nenhuma** mitigation policy do Windows está ativa, o veto vem de **fora do subsistema padrão** — só pode ser um driver kernel registrando callbacks:

- **`ObRegisterCallbacks(PsProcessType)`** — chamado antes de cada `OpenProcess`/`OpenThread` fora do próprio processo. Pode strippar bits de acesso (`PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION`, `PROCESS_ALL_ACCESS`) do `ACCESS_MASK` desejado.
- **`PsSetLoadImageNotifyRoutine`** — chamado pra cada `NtCreateSection`/`NtMapViewOfSection` que mapeie imagem executável. Callback pode setar `IoStatus.Status = STATUS_ACCESS_DENIED` no InitialThunk, bloqueando o load. Provavelmente isso está bloqueando o Windows de carregar `nvdlss_helper.dll` no rubinot via WH_GETMESSAGE.

Sequência exata (hipótese):

```
1. affapp registra SetWindowsHookExW(WH_GETMESSAGE, ..., 0)
2. Windows guarda hDll + procName em tabela global de hooks
3. rubinot processa mensagem (mouse move na janela, tick de UI)
4. Windows tenta carregar nvdlss_helper.dll no rubinot via LdrLoadDll interno
5. EMAC callback intercepta em NtMapViewOfSection / PsSetLoadImageNotifyRoutine
6. EMAC checa: path da DLL contém "affbypass" ou "nvdlss_helper" ou não é MS-assinada
7. EMAC seta status = STATUS_ACCESS_DENIED
8. LdrLoadDll retorna erro, DLL não é carregada, DllMain não roda
9. Windows silenciosamente falha, hook continua registrado do lado do affapp mas não faz nada no rubinot
```

Zero evento em event log porque o EMAC não é uma mitigation policy documentada — é código customizado. Zero mensagem porque a falha do `LdrLoadDll` é engolida no path do WH_* dispatcher.

---

### Contramedidas hipotéticas (fora do escopo do projeto)

Todas exigiriam trabalho substancial e/ou seriam desproporcionais ao escopo educacional deste PoC.

1. **Driver kernel próprio pra desregistrar callbacks do EMAC.** Iterar `PsProcessType->CallbackList`, achar o entry do EMAC pelo endereço da CallbackRoutine (dentro do `EMAC-Driver-GL-TB-x64.sys`), e chamar `ObUnRegisterCallbacks` no handle registrado. Semelhante pra `PsSetLoadImageNotifyRoutine` (tabela `PspLoadImageNotifyRoutine`, remover entry). **Requer PatchGuard bypass ou timing correto** — não trivial e alto risco de BSOD. Ferramenta de ataque real, não educacional.
2. **Bootar sem EMAC ativo.** `sc.exe delete EMACDRVGLTB` + reboot. Cliente detecta driver ausente e termina (memory `x64dbg-mcp-setup.md` documenta esse comportamento). Sem workaround simples.
3. **Assinar `nvdlss_helper.dll` com cert Microsoft ou EV cert legítimo.** Alto custo, potencialmente contorna se o veto for por assinatura — mas o veto pode ser por path/nome, não signature.
4. **Hookar `win32u!NtUserSetWindowDisplayAffinity` em vez de `user32!Set`.** Contorna o forwarder do Achado 1 — mas ainda precisaria da DLL carregar no processo (Achado 4 bloqueia).

Nenhuma dessas é sensata pra este projeto. O README já delimita corretamente: **PoC educacional contra `afftarget.exe`, não ferramenta ofensiva.**

---

### Fixes recomendados no código do projeto (independentes do bypass)

Achados 2 e 3 revelaram melhorias reais no PoC que valem commit:

1. **`app/Injector.cpp` / `app/main.cpp:runInject`** — usar `findFirstThreadId` (que já existe) em vez de shotgun `enumThreadIds`. Enfileirar APC em uma thread só, com fallback. Elimina o deadlock do loader observado no Achado 3. Se a primeira thread não é alertable, tentar a próxima (loop com no máx 3-5 tentativas).
2. **`app/affapp.vcxproj` build hygiene** — o CI/checklist do projeto deveria forçar `Rebuild` (não incremental) em toda mudança do `Injector.cpp` pra evitar recorrer o mismatch do Achado 2. Documento essa política num `CONTRIBUTING.md` ou nota no README na seção Build.
3. **`--global-hook` já é bem robusto** — 3 tipos de hook (WH_GETMESSAGE + WH_CBT + WH_CALLWNDPROC), filter file, DllMain rejeita fora do alvo. Nenhum ajuste necessário; falha contra rubinot é por Achado 4 (kernel-mode veto), não por bug do modo.

---

## Notas para próximo assistant / sessão

- Memory salva em `~/.claude/projects/.../memory/x64dbg-mcp-setup.md` tem timeline completo das 7 sessões.
- **Sessão 7 (essa doc) fechou a investigação da Fase B1 contra rubinot**: causa raiz da falha é kernel-mode process protection do driver `EMACDRVGLTB`, não bug nosso. Documentadas contramedidas hipotéticas (fora do escopo) e fixes REAIS do código (shotgun APC → single-thread APC; build hygiene do `affapp.vcxproj`).
- Sessão 6 reduziu prioridade da contramedida "rename `affctl.sys`" — **não é necessário**.
- Contramedida do rename `x64dbg → notepadd` virou script — [`scripts/setup-rubinot-debug.ps1`](../../scripts/setup-rubinot-debug.ps1) com flag `-Rollback` e `-StartAffctl`.
- **Fixes REAIS pra commitar** (identificados na Sessão 7):
  1. `app/main.cpp:runInject` — usar `findFirstThreadId` em vez de `enumThreadIds` (shotgun causa deadlock do loader — evidência empírica em Achado 3).
  2. Rebuildar `affapp.vcxproj` sempre que mudar `Injector.cpp` (Achado 2 do build mismatch). Considerar CONTRIBUTING.md ou pre-commit hook.
- Tasks de RE que ficam abertas (baixa prioridade — não bloqueiam nada):
  - Confirmar via BP se rubinot chama `NtQuerySystemInformation(0xB)` (só fecha hipótese (1) vs (2) da Sessão 6).
  - Mapear rotina anti-debug em `emac-client64+0x89ECD3` (VMProtect Ultra, tracing dedicado).
  - RE do driver `EMAC-Driver-GL-TB-x64.sys` pra confirmar quais callbacks kernel ele registra (`ObRegisterCallbacks` vs `PsSetLoadImageNotifyRoutine` vs ambos). Só interessante pro cenário 1 das contramedidas hipotéticas — que está fora de escopo.
- Estado do setup ao fechar Sessão 7: **não fez rollback a pedido do usuário** — IFEO ainda aponta pra `notepadd.exe`, drivers RUNNING, backup em `%TEMP%\rubinot-debug-backup.txt`. Rollback via `scripts\setup-rubinot-debug.ps1 -Rollback`.
