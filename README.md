# display-affinity-lab

Laboratório **educacional** de bypass de `SetWindowDisplayAffinity` no Windows 10/11 moderno. PoC concluído.

> **Escopo.** Só rode em **VM/máquina de teste** sua. Todos os testes foram feitos contra janelas próprias (`wda_holder.exe`) e contra alvos autorizados. Você é responsável pelo uso.

---

## Solução (o que este repo prova)

Windows 10/11 protege janelas contra captura via `SetWindowDisplayAffinity(hwnd, WDA_MONITOR)` — BitBlt, PrintWindow, Windows.Graphics.Capture e Desktop Duplication API todas retornam preto/erro. **Este PoC contorna 100% dessa proteção com ~150 linhas de C++ user-mode**, usando uma API undocumented mas exportada por nome:

```c
// user32.dll — exportada por NOME, ordinal 0xE0
BOOL WINAPI DwmGetDxSharedSurface(
    HWND hwnd, HANDLE* phSurface, LUID* pAdapterLuid,
    ULONG* pFmtWindow, ULONG* pPresentFlags, ULONGLONG* pWin32kUpdateId);
```

Ela retorna o KMT shared handle da textura DirectX que o app entrega ao DWM. `OpenSharedResource + CopyResource + Map` lê os pixels **fonte**, antes de qualquer filtro de captura. **WDA é ignorada** porque WDA é aplicada no *path de captura*, não na surface fonte.

**Zero drivers. Zero hook. Zero injeção. Zero elevated. Zero risco de crash.**

## Validação em produção

Testado contra o rubinot (jogo online com anti-cheat comercial **EMAC** — driver kernel VMProtect + `emac-client64.dll` + `ObRegisterCallbacks`+`PsSetLoadImageNotifyRoutine`+PID spoofing + `WDA_MONITOR`):

```
[+] Target HWND=0x70566 PID=0 (spoofed) WDA=1 title="RubinOT Client - Fus Ro Daah" 2560x1440
[dw] DwmGetDxSharedSurface -> TRUE
    hSurface=C0000582 LUID={RTX 3070} fmt=87 (BGRA8) presentFlags=8
[tex] 2560x1440 fmt=87 miscFlag=0x2 (SHARED)
[DwmShared] mean=55.48 stdev=32.41 black%=3 nonzero=3683333/3686400 (99.92%)
    -> FRAME REAL (bypass funcionou)
```

Streaming contínuo estável em **21.4 FPS efetivo** (bottleneck é `CopyResource+Map` — não a API).

---

## Uso

### Como resolver o HWND (janela com PID spoofado)

O EMAC spoofa `GetWindowThreadProcessId(hwnd) → 0`, então **filtrar `EnumWindows` por PID falha silenciosamente**. Três formas que funcionam:

| Modo | Como funciona | Quando usar |
|---|---|---|
| `pt` | 10s countdown; usa `WindowFromPoint(cursor)` | Interativo, mais confiável |
| `fg` | 10s countdown; usa `GetForegroundWindow()` | Interativo, target já em foco |
| `hotkey` | Pressione F2 quando target focado | Sem countdown, timing preciso |
| `<needle>` | Enumera + filtra por substring do título via `GetWindowTextW` | Automação (título estável) |
| `hwnd:0x...` | HWND explícito | Você já tem o handle |
| `pid:N` | Enumera por PID | **NÃO funciona em janela spoofada** (PID=0) |

Nenhum desses passa por `GetWindowThreadProcessId` — o HWND vive no `tagWND` do win32k, que responde `GetWindowTextW`, `GetWindowRect`, `GetWindowDisplayAffinity` normalmente mesmo com PID spoofado.

### Screenshot único (textura inteira)

```bash
dxshared_probe.exe pt rubinot_capture
# 10s countdown → posiciona mouse sobre a janela alvo
# gera: rubinot_capture.shared.bmp
```

Uso completo: `dxshared_probe.exe <needle|pid:N|hwnd:H|pt|fg|hotkey> <out_prefix>`.

### Streaming contínuo

```bash
dxshared_stream.exe pt out_dir --fps 30 --seconds 10 --save-every 30
# 10s @ 30 FPS, salva 1 frame por segundo em out_dir/frame_NNNNN.bmp
```

Flags: `--fps N`, `--seconds N`, `--save-every N`, `--stats-only` (sem salvar).

### Pixel-read (ROI) para pixel-bot

*Não incluído no PoC atual — está no [roadmap](docs/POC_CLOSURE.md#roadmap-futuro-opcional).* Arquitetura sugerida usa `ID3D11DeviceContext::CopySubresourceRegion` em vez de `CopyResource` inteira:

```cpp
// Pseudo — copia só uma ROI pequena (ex: HP bar 200x20)
D3D11_BOX box = { x, y, 0, x+w, y+h, 1 };
ctx->CopySubresourceRegion(stagingSmall, 0, 0, 0, 0, srcTex, 0, &box);
ctx->Map(stagingSmall, ...);
uint32_t* pixels = (uint32_t*)mapped.pData;
// pixels[y*w + x] = 0xAARRGGBB (BGRA)
```

Latência esperada: **~2-5 ms por check** (vs ~15 ms da textura inteira). Suficiente pra bot em 100-200 Hz.

---

## Estrutura do repo

Este repo tem duas camadas — **use a Fase 4** (recomendada) e leia a Fase 1-3 como documentação da jornada:

### Fase 4 — Solução final (recomendada)

Sources em `scratchpad/` da sessão de desenvolvimento (portar pra `tools/dxshared/` é próximo passo). Compilam standalone com Windows SDK:

- `dxshared_probe.cpp` — screenshot único via `DwmGetDxSharedSurface`
- `dxshared_stream.cpp` — streaming contínuo com cache de shared resource
- `wda_holder.cpp` — cobaia (janela colorida com WDA aplicada) pra testes de bypass
- `wgc_probe.cpp` / `wgc_selftest.cpp` — probes WGC (documentam por que WGC não funciona como via)

**Build:**
```bash
cl /nologo /EHsc /std:c++17 /O2 dxshared_probe.cpp /link ^
   d3d11.lib dxgi.lib user32.lib gdi32.lib /OUT:dxshared_probe.exe
```

### Fases 1-3 — Legado (jornada de RE)

Mantidas como referência da mecânica kernel + documentação de dead-ends que ensinaram algo:

- `driver/affctl.sys` — driver kernel com `IOCTL_INJECT_DLL` (APC user-mode), IOCTLs legado (`READ_RANGE`/`CLEAR_AFFINITY`)
- `app/affapp.exe` — orquestração; discovery, `--inject`, `--capture` (BitBlt), `--probe-dwm`
- `afftarget/afftarget.exe` — cobaia visual
- `affbypass/affbypass.dll` — hook MinHook em `SetWindowDisplayAffinity` (Fase 2)
- `hellodll/hellodll.dll` — smoke-test de injeção kernel

Estes rodam e produzem os resultados documentados na Fase 2. **Não** funcionam contra rubinot (bloqueados pelas defesas do EMAC descritas em `docs/POC_CLOSURE.md`). Use a Fase 4.

---

## Por que a Fase 4 vence

O EMAC anti-cheat (e a maioria dos anti-cheats modernos) defende o **processo** exaustivamente:
- `ObRegisterCallbacks(PsProcessType)` — nega `OpenProcess(PROCESS_VM_WRITE|CREATE_THREAD)`
- `PsSetLoadImageNotifyRoutine` — mata proc se DLL não-whitelist é carregada
- `PsSetCreateThreadNotifyRoutine` — mata proc em thread nova
- PID spoofing — `GetWindowThreadProcessId(hwnd)` retorna 0
- `WDA_MONITOR` — sinal pro DWM aplicar preto em BitBlt/WGC/PW/DDA

**Não protege** a surface DirectX que o próprio processo entrega ao DWM — porque não pode, sem reescrever o pipeline do compositor do OS. `DwmGetDxSharedSurface` é uma back-door mantida pela Microsoft pra ferramentas de acessibilidade (Magnifier) que a comunidade RE mapeou. Contorna o modelo de ameaça inteiro sem tocar em nada que o anti-cheat consegue defender.

## Detalhe: título é lido mesmo com PID spoofado

O PID spoof só quebra a associação HWND↔processo. `GetWindowTextW(hwnd)` continua funcionando porque o título é armazenado no `tagWND` (win32k), independente do owner process:

| API | Rubinot | Bloqueado? |
|---|---|---|
| `EnumWindows` | HWND aparece | ✅ funciona |
| `GetWindowTextW` | `"RubinOT Client - Fus Ro Daah"` | ✅ funciona |
| `GetWindowDisplayAffinity` | `1` (WDA_MONITOR) | ✅ funciona |
| `GetWindowThreadProcessId` | `pid = 0` | ❌ spoofed |
| `OpenProcess(rubinot)` | ACCESS_DENIED | ❌ ObCallbacks |
| `ReadProcessMemory(rubinot)` | idem | ❌ ObCallbacks |

Isso confirma o modelo de ameaça: proteger *processo*, não *janela*.

---

## Documentação técnica

- **[docs/POC_CLOSURE.md](docs/POC_CLOSURE.md)** — Retrospectiva completa: fases 1-4, achados, defesas do EMAC mapeadas, roadmap opcional
- **[docs/reverse-engineering/rubinot-scan-detection.md](docs/reverse-engineering/rubinot-scan-detection.md)** — 6 sessões RE do EMAC anti-debug + contramedida
- **[scripts/setup-rubinot-debug.ps1](scripts/setup-rubinot-debug.ps1)** — Rename + IFEO + start dos drivers (com `-Rollback`)

---

## Referências

- **API core:** `user32.dll!DwmGetDxSharedSurface` (undocumented, exportada por nome; assinatura mapeada pela comunidade RE)
- **Ferramenta similar (open-source):** [wda-bypass-screenshot-tool](https://github.com/IdaruHack/wda-bypass-screenshot-tool) (Python + ctypes)
- **APIs Microsoft usadas:** `CreateDXGIFactory1`, `D3D11CreateDevice`, `ID3D11Device::OpenSharedResource`, `ID3D11DeviceContext::CopyResource/Map`
- **PDBs Microsoft** (via Symbol Server) — usados na Fase 1 pra resolver `ValidateHwnd`/`gSharedInfo`

---

## Licença

MIT (ver `LICENSE`). MinHook em `third_party/minhook/` mantém sua própria licença (BSD-2-Clause).
