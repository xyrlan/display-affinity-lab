# tools/dxshared

Bypass user-mode de `WDA_MONITOR`/`WDA_EXCLUDEFROMCAPTURE` via `user32.dll!DwmGetDxSharedSurface`. Ver [docs/POC_CLOSURE.md](../../docs/POC_CLOSURE.md) para contexto completo, histórico das fases e defesas mapeadas.

## Build

```bat
build.bat
```

Detecta VS2022/VS2026 automaticamente e compila 5 binários em `bin\`. Requer C++ workload + Windows SDK 10.0.19041+ (WGC precisa 1903+; `DwmGetDxSharedSurface` existe desde 8/8.1).

## Binários

| Binário | Propósito |
|---|---|
| `dxshared_probe.exe` | **Screenshot único** via DwmGetDxSharedSurface — bypass principal |
| `dxshared_stream.exe` | **Streaming contínuo** com cache de shared resource |
| `wda_holder.exe` | Cobaia visual: cria janela colorida + aplica WDA no mode escolhido |
| `wgc_probe.exe` | Probe Windows.Graphics.Capture (referência; **não bypassa** — CreateForWindow retorna E_INVALIDARG em WDA_MONITOR) |
| `wgc_selftest.exe` | WGC contra própria janela (documenta o mesmo gate) |

## Uso

### Screenshot único

```bat
dxshared_probe.exe pt out_prefix
```

Modos aceitos como primeiro argumento (resolvem HWND sem passar por PID lookup — importante para janelas com PID spoofado):

| Modo | Comportamento |
|---|---|
| `pt` | 10s countdown; `WindowFromPoint(cursor)` |
| `fg` | 10s countdown; `GetForegroundWindow()` |
| `hotkey` | Aguarda F2; `GetForegroundWindow()` |
| `<needle>` | Substring case-insensitive em `GetWindowTextW` |
| `pid:N` | Filtro por PID (**não** funciona em janela spoofada) |
| `hwnd:0x...` | HWND explícito |

Salva `<out_prefix>.shared.bmp` e imprime verdict (mean, black%, nonzero pixels).

### Streaming contínuo

```bat
dxshared_stream.exe pt out_dir --fps 30 --seconds 10 --save-every 30
```

Flags:
- `--fps N` — cadência de polling (default 30)
- `--seconds N` — duração (default 5)
- `--save-every N` — salva 1 BMP a cada N updates de frame (default 30)
- `--stats-only` — não salva BMPs, só mede FPS efetivo

Log por segundo: `iter`, `upd` (frames com updId novo), `saved`, `fails_h` (handle), `fails_m` (Map). Ctrl+C interrompe com cleanup.

### Teste de bypass end-to-end (janela cobaia)

Em um shell:
```bat
wda_holder.exe monitor hwnd.txt
REM cria janela colorida 800x600 com WDA_MONITOR, escreve HWND em hwnd.txt
```

Em outro:
```bat
for /f "usebackq" %H in ("hwnd.txt") do dxshared_probe.exe hwnd:%H bypass_test
REM captura via DwmGetDxSharedSurface -> gera bypass_test.shared.bmp com o padrão xadrez real
```

Compare com uma tentativa via `BitBlt`/`PrintWindow` (fica preto). Modos aceitos no `wda_holder`: `none`, `monitor`, `exclude`.

## Como funciona (resumo)

1. `GetProcAddress(user32, "DwmGetDxSharedSurface")` — exportado por nome, ordinal 0xE0
2. Chama com HWND alvo → retorna KMT shared handle + LUID do adapter
3. `CreateDXGIFactory1` + `EnumAdapters1` — resolve o adapter pelo LUID
4. `D3D11CreateDevice(adap, D3D_DRIVER_TYPE_UNKNOWN)` — device no adapter dono
5. `dev->OpenSharedResource(hSurface, IID_ID3D11Resource)` — abre a textura fonte do DWM
6. `CopyResource` → staging → `Map` → BGRA pixels
7. WDA foi ignorada porque a captura é da surface **fonte**, antes do path de captura onde a WDA se aplica

Ver `dxshared_probe.cpp` inline (código todo comentado).

## Limitações conhecidas

- Janela precisa estar **visível e composta pelo DWM** (não minimizada; borderless-fullscreen OK)
- `D3D11CreateDevice` no adapter certo é obrigatório — usar `D3D_DRIVER_TYPE_HARDWARE` sem passar `adapter` explícito falha se o LUID retornado por `DwmGetDxSharedSurface` não bater com o default adapter
- `--stats-only` do stream ainda faz `Map` a cada frame (otimização pendente — ver [roadmap](../../docs/POC_CLOSURE.md#roadmap-futuro-opcional) item 6)

## Referências

- **API:** `user32.dll!DwmGetDxSharedSurface` (undocumented; assinatura mapeada pela comunidade RE)
- **Ferramenta similar:** [wda-bypass-screenshot-tool](https://github.com/IdaruHack/wda-bypass-screenshot-tool) (Python + ctypes)
- **APIs Microsoft:** `CreateDXGIFactory1`, `D3D11CreateDevice`, `ID3D11Device::OpenSharedResource`, `ID3D11DeviceContext::CopyResource/Map`
