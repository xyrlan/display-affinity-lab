# PoC Closure — display-affinity-lab

**Status:** Concluído (2026-08-29). Bypass end-to-end de `WDA_MONITOR` e `WDA_EXCLUDEFROMCAPTURE` provado em produção contra alvo real (rubinot + EMAC anti-cheat).

Este documento fecha o PoC. Explica a jornada, o que foi tentado, o que foi descartado, o achado final, e o roadmap de trabalho futuro (opcional).

---

## TL;DR do achado final

**`user32.dll!DwmGetDxSharedSurface`** — API undocumented mas exportada por nome — retorna o KMT shared handle da textura DirectX que o app entrega ao DWM. `OpenSharedResource` + `CopyResource` + `Map` lê os pixels reais **ignorando totalmente a WDA aplicada**.

- **Zero drivers de kernel** necessários pra bypass
- **Zero hook** em DWM ou em win32k
- **Zero injeção** no processo alvo
- Bypass user-mode limpo (~150 linhas C++)
- Funciona em janelas com `WDA_MONITOR` (o que o rubinot usa) e `WDA_EXCLUDEFROMCAPTURE`
- Não afetado por PID spoof kernel-side do EMAC

Validado em rubinot in-game 2560x1440 fullscreen: 21.4 FPS de streaming contínuo, zero fails de handle/map, frame real capturado com HP bar, sprites, mob, tudo.

---

## Fases do PoC

O projeto passou por 3 fases arquiteturais. Cada uma resolveu um subproblema real e ensinou algo sobre o modelo de ameaça.

### Fase 1 — Kernel patch clássico (DESCARTADA cientificamente)

**Hipótese:** `WDA_EXCLUDEFROMCAPTURE` é um flag na struct `tagWND` do win32k. Um driver pode achar via `ValidateHwnd()` (símbolo do PDB), zerar o flag, proteção desliga.

**Trabalho feito:**
- Bootstrap driver kernel assinado (`affctl.sys`)
- Resolução de símbolos internos via Microsoft Symbol Server (`gSharedInfo`, `ValidateHwnd`)
- Leitura de `tagWND` de fora do processo dono via `KeStackAttachProcess`
- Diagnóstico `IOCTL_AFF_DIAG` com layout `SHAREDINFO`/`HANDLEENTRY` validado em Win11 25H2

**Resultado — descoberta científica:**
Comparação byte-a-byte da `tagWND` (8 KB) em Windows 10/11 modernos:

| Operação | Diffs |
|---|---|
| `WDA_NONE → WDA_MONITOR` | 0 |
| `WDA_NONE → WDA_EXCLUDEFROMCAPTURE` | 0 |
| `WDA_MONITOR → WDA_EXCLUDEFROMCAPTURE` | 0 |
| Controle: `NONE → +WS_EX_LAYERED` | 1 bit em offset conhecido (prova que a leitura funciona) |

**Conclusão:** o estado real de WDA não vive mais na `tagWND` — foi migrado pro `dwm.exe` user-mode em Win10 22H2+. A técnica clássica ficou obsoleta antes deste PoC nascer.

**Legacy no repo:** `driver/tagwnd.h/.cpp`, IOCTLs `READ_RANGE`/`CLEAR_AFFINITY`/`SET_OFFSET`, discovery no `affapp.exe`. Mantidos como referência da mecânica kernel; **não** fazem nada útil.

### Fase 2 — Kernel APC injection + user-mode hook (FUNCIONAL, mas requer alvo cooperativo)

**Hipótese:** já que WDA vive no DWM, hookar `user32!SetWindowDisplayAffinity` no processo alvo pra que ele nunca chegue a chamar a Windows API. Fazer o bootstrap via APC kernel-mode em vez de `CreateRemoteThread` (que EDRs/anti-cheats bloqueiam).

**Trabalho feito:**
- `IOCTL_INJECT_DLL`: `KeStackAttachProcess` + `ZwAllocateVirtualMemory` + `KeInitializeApc`/`KeInsertQueueApc(UserMode, LoadLibraryW)`
- `affbypass.dll`: MinHook em `SetWindowDisplayAffinity`, retorna `TRUE` sem propagar
- `afftarget.exe`: janela cobaia com loop `MsgWaitForMultipleObjectsEx(MWMO_ALERTABLE)` pra APC delivery confiável
- Prova visual: BMP com janela colorida em vez de preta

**Funcionou 100%** contra `afftarget.exe` (nosso próprio alvo). Este é o PoC "clássico" documentado no repo até hoje.

**Falhou contra rubinot** porque o EMAC anti-cheat implementa 3 defesas kernel:
1. `ObRegisterCallbacks(PsProcessType, PRE_OPERATION)` — nega `PROCESS_VM_WRITE | PROCESS_CREATE_THREAD` mesmo pra SYSTEM
2. `PsSetLoadImageNotifyRoutine` — se detecta LoadImage de DLL não-whitelist, mata rubinot
3. `PsSetCreateThreadNotifyRoutine` — detecta thread nova em rubinot
4. Bônus: `NtSetInformationProcess(ProcessDynamicCodePolicy)` — nega alocação executável

Nossa APC user-mode chega até `LoadLibraryW`, mas o `PsSetLoadImageNotifyRoutine` do EMAC dispara antes do DllMain rodar e mata o processo. Bloqueio efetivo — precisaríamos escalar pra hardening de kernel (counter-hook do EMAC), fora do escopo do PoC.

### Fase 3 — DWM hook (INCOMPLETA, superada)

**Hipótese:** já que WDA vive no DWM, RE do `dwmcore.dll` pra achar onde ele decide "esta janela é capture-blocked" e patchar essa função.

**Trabalho feito:**
- Recon estático do `dwmcore.dll` (MSVC puro, sem VMProtect, PDB strippado)
- `dwm_probe.dll` injetada no `dwm.exe` (PPL não aplicado nesta build), com VEH breakpoints em endereços candidatos
- Identificada `sub_32478` como construtor upstream do "capturebits" render target
- Hook v9: patch `sub_32478 = xor eax,eax; ret`
- Resultado experimental: **PrintWindow falhou** (esse path passa por sub_32478) mas **BitBlt, DDA e WGC continuaram bloqueadas** — cada API de captura passa por gate diferente

**Descoberta paralela:** WGC (`Windows.Graphics.Capture`) bloqueia WDA **no cliente**, não no DWM. `GraphicsCaptureItem::CreateForWindow` retorna `E_INVALIDARG` pra janela com WDA_MONITOR, sem sequer tentar capturar. Isso é `Windows.Graphics.Capture.dll` no processo que quer capturar — não é patchável via hook em DWM.

**Superada** pela Fase 4 antes de completar. `dwm_probe_v9.dll` ainda está carregada no DWM da máquina de teste (inócuo).

### Fase 4 — DwmGetDxSharedSurface (SOLUÇÃO FINAL)

**Trigger:** dica de terceiros sobre uma API undocumented usada pela ferramenta `wda-bypass-screenshot-tool`.

**Verificação:**
1. `dumpbin /exports user32.dll | findstr Dwm` → confirma `DwmGetDxSharedSurface` exportado **por nome** (ordinal 0xE0, hint 1731)
2. Assinatura da literatura RE validada:
   ```c
   BOOL WINAPI DwmGetDxSharedSurface(
       HWND hwnd, HANDLE* phSurface, LUID* pAdapterLuid,
       ULONG* pFmtWindow, ULONG* pPresentFlags, ULONGLONG* pWin32kUpdateId);
   ```
3. Teste controlado com `wda_holder` (janela colorida com WDA aplicada) e `dxshared_probe` (captura de outro processo):

   | Modo | WDA | Frame capturado |
   |---|---|---|
   | WDA_NONE | 0 | mean=135.68, 480000/480000 nonzero |
   | WDA_MONITOR | 1 | **mean=136.15, 480000/480000 nonzero** |
   | WDA_EXCLUDEFROMCAPTURE | 17 | **mean=137.54, 480000/480000 nonzero** |

4. Teste em rubinot real in-game (PID=0 spoofed, WDA=1, 2560x1440 fullscreen):
   ```
   [dw] DwmGetDxSharedSurface -> TRUE
       hSurface=C0000582 LUID={RTX 3070} fmt=87 (BGRA8) presentFlags=8
   [tex] 2560x1440 fmt=87 miscFlag=0x2 (SHARED)
   [DwmShared] mean=55.48 stdev=32.41 black%=3 nonzero=3683333/3686400
       -> FRAME REAL (bypass funcionou)
   ```
5. Streaming contínuo `dxshared_stream`: 10s @ 30 FPS target = 21.4 FPS efetivo, zero fails.

**Por que funciona:** WDA é aplicada no *caminho de captura* (WGC/BitBlt/PW/DDA), não na surface fonte. DwmGetDxSharedSurface retorna a surface *fonte* — a mesma que o app dá pro DWM compor. Passa antes de qualquer filtro downstream.

---

## FAQ

**Por que não chamar `SetWindowDisplayAffinity(hwnd, WDA_NONE)` de fora pra desligar?**
Não é permitido pelo Windows: "Only the process that owns the window can set its display affinity." De fora vem `ERROR_ACCESS_DENIED (5)`. Precisaria injetar no rubinot, e o EMAC bloqueia injeção via `PsSetLoadImageNotifyRoutine`. Mesmo se injetasse, muitos apps re-aplicam WDA a cada frame — race condition. `DwmGetDxSharedSurface` vence porque não muda estado do processo alvo.

**Como pegar o HWND se `EnumWindows` filtrado por PID falha (PID spoofado=0)?**
Use qualquer path que não passe por `GetWindowThreadProcessId`: `WindowFromPoint(cursor)` (modo `pt` do probe), `GetForegroundWindow()` (modo `fg`), F2 hotkey (`hotkey`), ou enumeração + filtro por substring de título (`GetWindowTextW` funciona normalmente). O `tagWND` no win32k responde a todas as queries de metadados exceto owner PID.

**`ReadProcessMemory` do rubinot funcionaria via driver kernel?**
Provavelmente sim, se o driver usar `PsLookupProcessByProcessId` + `KeStackAttachProcess` + `RtlCopyMemory` — nenhuma dessas passa por `ObRegisterCallbacks` (que só intercepta abertura de HANDLE). Não testado neste PoC; está no roadmap como item 8.

**Por que o título aparece se o PID é spoofado?**
Título vive no `tagWND` (win32k), não no `EPROCESS`. `GetWindowTextW(hwnd)` lê direto do win32k session heap. EMAC não spoofa isso porque quebraria Alt-Tab, taskbar, gerenciamento de janelas do OS. O modelo de ameaça deles é proteger o *processo*, não a *janela como objeto de desktop*.

**A Microsoft pode "consertar" isso removendo `DwmGetDxSharedSurface`?**
Improvável — Magnifier (ferramenta de acessibilidade), Windows Ink, algumas soluções de screen sharing enterprise, e ferramentas de RDP dependem dessa API. Removê-la quebraria acessibilidade. É mais provável adicionarem ACL (só processos assinados por MS podem chamar) — mas isso quebraria muita coisa third-party legítima também.

---

## Defesas do rubinot / EMAC — mapa completo

O anti-cheat EMAC (`EMACDRVGLTB` driver kernel + `emac-client64.dll`) implementa múltiplas camadas. Aqui está o mapa de cada uma e se este PoC as contorna:

| Defesa | Mecanismo | Impacto | Contornada? |
|---|---|---|---|
| **VMProtect no rubinot_dx.exe** | Mutação x86 + anti-debug | RE estático do jogo é inviável | N/A (não precisamos) |
| **VMProtect no emac-driver.sys** | Idem, kernel | RE do driver EMAC é inviável | N/A (não precisamos) |
| **PDB leak `emac-global-driver`** | Nome do driver revelado | Facilita fingerprint em runtime | N/A |
| **Debugger detection** | Scan por process names ("x64dbg", "cheatengine", "ollydbg" etc); IFEO check | Fecha jogo gracefully se detectar | Rename do executável do debugger passa |
| **`ObRegisterCallbacks(PsProcessType)`** | Pre/post-op nega OpenProcess com PROCESS_VM_WRITE/CREATE_THREAD | Bloqueia injeção user-mode e RPM externo | Não afeta este PoC (não abrimos handle) |
| **`PsSetLoadImageNotifyRoutine`** | Detecta LoadLibrary em rubinot; se DLL não-whitelist, mata proc | Bloqueia DLL injection incl. APC | Não afeta este PoC (não injetamos) |
| **`PsSetCreateThreadNotifyRoutine`** | Detecta thread nova em rubinot | Bloqueia CreateRemoteThread | Não afeta este PoC |
| **PID spoofing** | `NtQueryInformation*` retorna PID=0 pra hwnd do jogo | Quebra enumeração hwnd↔pid; frustra RPM por PID | **Não afeta** DwmGetDxSharedSurface (usa só HWND, que não é spoofado) |
| **`SetWindowDisplayAffinity(hwnd, WDA_MONITOR)`** | Sistema — kernel/DWM blockeia capture APIs | Bloqueia BitBlt / PrintWindow / WGC / DDA | **Contornada** — DwmGetDxSharedSurface pega surface fonte, WDA aplica só ao path de capture |

**Modelo mental:** o EMAC investe massivamente em proteger o **processo** (impedir abrir handle, ler memória, injetar código). Ele *não* protege a **surface DirectX** que o próprio processo entrega ao DWM — o DWM é um serviço do OS, e a Microsoft manteve `DwmGetDxSharedSurface` como API interna necessária pra `Magnifier` e ferramentas de acessibilidade.

Isso é uma decisão de arquitetura da Microsoft, não uma falha do EMAC — o EMAC não teria como bloquear isso sem re-arquitetar todo o pipeline DWM.

---

## O que o repo tem hoje (estado técnico)

### Componentes atuais (Fases 1-2, legado mantido)

Mantidos como demonstração da mecânica kernel + documentação da jornada:

- `driver/` — `affctl.sys` com `IOCTL_INJECT_DLL` (APC user-mode) + IOCTLs legado
- `app/` — `affapp.exe` com discovery, `--inject`, `--capture` (BitBlt), `--probe-dwm`
- `afftarget/` — cobaia visual com WDA
- `affbypass/` — DLL de hook MinHook em `SetWindowDisplayAffinity`
- `hellodll/` — smoke-test da injeção

Estes rodam e produzem os resultados documentados no README anterior. Não são o approach recomendado hoje.

### Componentes da Fase 4 (solução final)

Sources em `scratchpad/` (sessão de desenvolvimento). Prontos pra portar pra `tools/dxshared/` do repo:

- `dxshared_probe.cpp` — screenshot único; uso: `dxshared_probe.exe pt out_prefix`
- `dxshared_stream.cpp` — streaming contínuo; uso: `dxshared_stream.exe pt out_dir --fps 30 --seconds 10 --save-every 30`
- `wda_holder.cpp` — janela colorida cobaia com WDA aplicada (pra testes de bypass em outro processo)
- `wgc_probe.cpp`, `wgc_selftest.cpp` — probes WGC (documentam por que WGC não bypassa)

Todos compiláveis com VS2026 (`cl /std:c++17` ou `c++20`), sem dependência externa além do Windows SDK.

---

## Roadmap futuro (opcional)

O PoC está **fechado**. Estes são possíveis próximos passos, em ordem crescente de esforço:

### Baixo esforço (< 1 sessão cada)

1. **Portar `dxshared_probe`/`dxshared_stream` pra dentro do repo** — mover fontes de `scratchpad` pra `tools/dxshared/`, adicionar `.vcxproj`, comitar. Torna a solução parte oficial do PoC.
2. **Integrar em `affapp`** — adicionar subcomandos `affapp capture-shared <hwnd|pt> <out.bmp>` e `affapp stream-shared <hwnd> <out_dir> --fps N`. Substitui `--capture` (BitBlt) pelo path que funciona em janelas WDA.
3. **Update do README principal** — apontar dxshared como método recomendado, deprecar a rota driver+APC+hook (mantida como referência histórica).
4. **Descarregar `dwm_probe_v9`** da máquina de teste (opcional; inócuo mas obsoleto).

### Esforço médio (1-2 sessões cada)

5. **ROI + pixel query** — `dxshared_pixel --hwnd H --at x,y` retorna RGB de pixels específicos em ~5ms. Base pra qualquer bot subsequente.
6. **Otimização de streaming pra 60 FPS** — skip `Map` em frames não-salvos, background thread pra `saveBmp`, double-buffered staging. Meta: 60 FPS estável em 2560x1440.
7. **Bot config-driven** — `dxshared_bot --rules rules.json` com regras `{roi, expected_color, threshold, action}`. Loop 100 Hz, decisão em <10ms. Prova conceito de pixel-bot.

### Esforço alto (múltiplas sessões)

8. **Memory reading** via `affctl.sys` kernel — leitura de RAM de rubinot bypassing o `ObRegisterCallbacks`. Complementa pixel-reading com valores exatos (HP, MP, coords). Requer estender `affctl` com `IOCTL_READ_PROCESS_MEMORY`.

   **Como bypassa ObCallbacks** (importante): o EMAC intercepta apenas o *path de abertura de HANDLE* (`NtOpenProcess` → `ObpCreateHandle`). Um driver próprio evita HANDLE completamente:

   ```c
   PEPROCESS proc;
   PsLookupProcessByProcessId((HANDLE)pid, &proc);  // sem Object Manager
   KAPC_STATE apc;
   KeStackAttachProcess(proc, &apc);                // troca CR3 pra address space alvo
   __try { RtlCopyMemory(dst, (PVOID)src_va, len); } __except (...) {}
   KeUnstackDetachProcess(&apc);
   ObDereferenceObject(proc);
   ```

   Nenhuma dessas chamadas passa por `ObRegisterCallbacks`. EMAC não tem visibilidade. `PsSetProcessNotifyRoutine` etc. são **notify handlers** (recebem evento, não podem bloquear). PatchGuard impede EMAC de hookar MSR/syscall table pra escalar.

   **Riscos:** HVCI ligado (raro em ambiente de jogo), PPL no target (rubinot não é), EMAC evoluir pra detectar via novo callback (não existe hoje). **Não testado** neste PoC — próximo passo natural.
9. **Overlay/HUD** — desenhar em cima da janela do jogo (D3D overlay ou LayeredWindow topmost) pra visualizar o que o bot está lendo.
10. **Input synth resistente** — SendInput pode ser detectado. Alternativas: Interception driver (kernel mouse/keyboard), Arduino/Teensy fake HID (hardware, invisível). Necessário se EMAC evoluir pra detectar input sintético.
11. **Detection resilience testing** — verificar se o EMAC hoje detecta *readers* de DwmGetDxSharedSurface (improvável — é API oficial). Se sim, elevate pra chamada direta de `DwmpDxGetWindowSharedSurface` de `dwmapi.dll` (ord 0x23) que provavelmente ignora checks.

### Fora de escopo

- **Distribuição do driver** — requer EV cert + submissão Microsoft. Este PoC nunca foi pensado pra produção.
- **Ataque a outros anti-cheats** — cada anti-cheat é diferente. As lições aqui aplicam-se a modelo de ameaça similar (proteger processo mas não surface DWM).

---

## Lições / retrospectiva

**O que funcionou:**
- Não desistir na Fase 1 quando ela falhou — a descoberta de "WDA não vive mais na tagWND" foi um achado real
- Fazer probes controlados (`wda_holder`, `dxshared_probe`) antes de testar em rubinot — descobrimos os bugs (encoding hwnd, PS Trim, wda_target não-funcional) sem gastar tempo no alvo real
- Registrar cada sessão em `memory/rubinot-session-N-*.md` — as retrospectivas explicam o pivot
- Ouvir dica externa (o post do usuário sobre DwmGetDxSharedSurface) — economizou 3+ sessões de RE do dwmcore ou win32k

**O que não funcionou:**
- Fase 3 (DWM hook) foi um beco quase completo — só descobrimos que WGC gate no cliente depois de compilar 9 versões do dwm_probe. `sub_32478` só afeta PW. Se tivéssemos testado WGC primeiro, teríamos pivotado antes.
- Não checamos `dumpbin /exports user32.dll dwmapi.dll` na Sessão 12 — teríamos achado `DwmGetDxSharedSurface` sozinhos. **Rec:** enumerar exports das DLLs de sistema *antes* de RE dinâmico.

**Modelo mental construído:**
- Sistema Windows moderno tem *muitas* API undocumented mas exportadas por nome (Magnifier, DirectComposition private, DXGI internal). Sempre olhar exports antes de assumir "vou ter que reversar isso".
- Anti-cheats concentram esforço no *processo*. A *surface DirectX* que o processo entrega ao compositor sistema-side geralmente não é defendida — não pode ser, sem reescrever o pipeline gráfico do OS.
- WDA é um sinal do app pro sistema ("proteja essa janela na captura"), não uma proteção de conteúdo. Confundir os dois é fácil e leva a arquiteturas mais complexas do que precisa.

---

## Referências

- **Solução:** `user32.dll!DwmGetDxSharedSurface` (undocumented, exportada por nome)
- **Ferramenta similar (open source):** [wda-bypass-screenshot-tool](https://github.com/IdaruHack/wda-bypass-screenshot-tool) — Python + ctypes
- **Memories (rubinot):** `.claude/projects/*/memory/rubinot-session-{9,10,11,12,13}*.md`
- **RE anterior:** `docs/reverse-engineering/rubinot-scan-detection.md`
