# DisplayAffinity Test Driver — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Driver kernel + app user-mode que, para janelas do proprio app, descobrem em runtime o offset da flag DisplayAffinity na tagWND e a zeram (WDA_NONE), restaurando captura de tela.

**Architecture:** Driver WDM (`affctl.sys`, C++ kernel-safe) expoe device `\??\AffCtl` com 4 IOCTLs, resolve HWND->tagWND via `gSharedInfo`+`aheList`. App C++17 (`affapp.exe`) cria janela propria, descobre offset por heuristica (toggle WDA + diff de bytes lidos do kernel), manda ao driver e pede clear. Toda desreferencia de ponteiro kernel sob `__try/__except`.

**Tech Stack:** Visual Studio 2022 + WDK + Windows SDK, C++17. Build/teste em Windows x64; teste em VM com Test Signing. Codigo gerado em macOS (nao compila aqui).

---

## Nota sobre "testes"

Kernel driver nao tem unit-test rodavel em macOS nem fora de VM. Portanto o codigo COMPLETO de cada componente vive nos arquivos-fonte reais deste repo (ja escritos), e o plano lista **passos + criterio de aceite** por task em vez de duplicar o codigo:
- **[BUILD]** = compilar no VS/WDK; sucesso = build limpo.
- **[VERIFY-VM]** = verificacao manual na VM, com criterio explicito (console, WinDbg, captura).
- **[EDIT]** = passo que exige preencher/ajustar algo especifico da build alvo (ex.: pattern do gSharedInfo).

Referencia de codigo: cada task aponta o arquivo. Ler o arquivo e o "codigo do passo".

---

## File Structure

| Arquivo | Responsabilidade |
|---------|------------------|
| `shared/affctl_shared.h` | IOCTLs + structs de I/O. Contrato unico driver/app. |
| `driver/win32k_structs.h` | Layout parcial SHAREDINFO/HANDLEENTRY. |
| `driver/tagwnd.h` / `.cpp` | Scan gSharedInfo, HWND->tagWND, read/write sob SEH. |
| `driver/driver.cpp` | DriverEntry, dispatch IOCTL, Unload. `extern "C"` nas entradas. |
| `driver/affctl.inf` | INF minimo. |
| `driver/affctl.vcxproj` | Projeto WDM x64. |
| `app/DriverComm.hpp` / `.cpp` | RAII sobre handle do device; metodos por IOCTL. |
| `app/TestWindow.hpp` / `.cpp` | RAII de janela + setAffinity. |
| `app/OffsetFinder.hpp` / `.cpp` | Heuristica de descoberta do offset. |
| `app/BmpCapture.hpp` / `.cpp` | BitBlt da janela -> .bmp (prova visual). |
| `app/main.cpp` | Orquestra discovery -> demo -> guard. Parse `--guard`. |
| `app/affapp.vcxproj` | Console app x64 C++17. |
| `scripts/install.bat` / `uninstall.bat` | Carga/descarga do driver. |
| `README.md` | Build, setup VM, execucao, WinDbg fallback. |

---

## Task 1: Contrato compartilhado

**Files:** Create `shared/affctl_shared.h`

- [ ] **Step 1:** Escrever header com device names, 4 IOCTLs (`CTL_CODE` 0x800-0x803, METHOD_BUFFERED), `AFFCTL_MAX_RANGE`, structs `READ_RANGE_INPUT`/`SET_OFFSET_INPUT`/`HWND_INPUT`/`READ_AFFINITY_OUTPUT` (`#pragma pack(1)`, HWND como `unsigned long long`). Guarda `#ifdef _KERNEL_MODE` para includes.
- [ ] **Step 2: [BUILD]** Aceite: compila tanto de .cpp kernel quanto user (verificado nas Tasks 4 e 6).
- [ ] **Step 3: Commit** `feat(shared): IOCTL contract header`

## Task 2: Structs win32k

**Files:** Create `driver/win32k_structs.h`

- [ ] **Step 1:** `HANDLEENTRY {phead,pOwner,bType,bFlags,wUniq}`, `TYPE_WINDOW=1`, `SHAREDINFO {psi,aheList,HeEntrySize,...}`, macro `HWND_INDEX(h) = (h & 0xFFFF)`. Comentario: offsets a validar no WinDbg (README).
- [ ] **Step 2: Commit** `feat(driver): partial win32k struct layout`

## Task 3: Resolucao HWND->tagWND + SEH

**Files:** Create `driver/tagwnd.h`, `driver/tagwnd.cpp`

- [ ] **Step 1:** Header: namespace `affctl` com `InitSharedInfo()`, `ResolveTagWnd(hwnd)`, `ReadTagWndRange(hwnd,out,count)`, `ReadFlag(hwnd,offset,*value)`, `ClearFlag(hwnd,offset)`.
- [ ] **Step 2:** Impl. `FindGSharedInfo()` isolada (pattern scan em win32kbase.sys). `ResolveTagWnd`: `InitSharedInfo` -> `idx=HWND_INDEX` -> valida `idx` -> `he=aheList[idx]` -> checa `bType==TYPE_WINDOW && phead` -> retorna `phead`. Read/write: `MmIsAddressValid` pre-check + `__try/__except(EXCEPTION_EXECUTE_HANDLER)` -> `STATUS_ACCESS_VIOLATION` no except.
- [ ] **Step 3: [EDIT]** `FindGSharedInfo()` retorna `nullptr` como stub — preencher o pattern na VM alvo (README secao "Pattern"). Aceite parcial ate VM.
- [ ] **Step 4: Commit** `feat(driver): HWND->tagWND resolution with SEH guards`

## Task 4: DriverEntry + dispatch IOCTL

**Files:** Create `driver/driver.cpp`

- [ ] **Step 1:** `extern "C" DriverEntry`: `IoCreateDevice(FILE_DEVICE_UNKNOWN)` + `IoCreateSymbolicLink(\??\AffCtl)`; set `MajorFunction[CREATE/CLOSE/DEVICE_CONTROL]` + `DriverUnload`. Global `g_offset`.
- [ ] **Step 2:** `DispatchDeviceControl` (`extern "C"`): valida tamanhos de in/out buffer por IOCTL antes de tocar ponteiro; despacha:
  - `READ_RANGE`: clamp `Count<=AFFCTL_MAX_RANGE`, `affctl::ReadTagWndRange`.
  - `SET_OFFSET`: guarda `g_offset`.
  - `CLEAR_AFFINITY`: rejeita se `g_offset` nao setado (`STATUS_INVALID_DEVICE_STATE`), senao `affctl::ClearFlag`.
  - `READ_AFFINITY`: `affctl::ReadFlag` -> `READ_AFFINITY_OUTPUT`.
  - Preenche `Irp->IoStatus.Information` corretamente. Sempre `IoCompleteRequest`.
- [ ] **Step 3:** `Unload`: `IoDeleteSymbolicLink` + `IoDeleteDevice`.
- [ ] **Step 4: [BUILD]** Aceite: `affctl.sys` linka sem erro (apos vcxproj Task 5).
- [ ] **Step 5: Commit** `feat(driver): DriverEntry, IOCTL dispatch, Unload`

## Task 5: Projeto e INF do driver

**Files:** Create `driver/affctl.vcxproj`, `driver/affctl.inf`

- [ ] **Step 1:** `affctl.vcxproj` WDM x64 (Debug/Release), inclui `../shared`, adiciona `driver.cpp`+`tagwnd.cpp`, headers. Configuration Type = Driver, TargetVersion Windows10.
- [ ] **Step 2:** `affctl.inf` minimo (Class=System, servico kernel, sem hardware ID — instala via `sc`).
- [ ] **Step 3: [BUILD]** Aceite: `msbuild affctl.vcxproj /p:Configuration=Release /p:Platform=x64` gera `affctl.sys`.
- [ ] **Step 4: Commit** `build(driver): vcxproj + inf`

## Task 6: DriverComm (app RAII)

**Files:** Create `app/DriverComm.hpp`, `app/DriverComm.cpp`

- [ ] **Step 1:** Classe `DriverComm`: ctor `CreateFileW(AFFCTL_USER_PATH)`, dtor fecha handle (RAII, no copy). Metodos: `readRange(hwnd,count)->std::vector<BYTE>`, `setOffset(u32)`, `clearAffinity(hwnd)`, `readAffinity(hwnd)->BYTE`. Cada um monta struct de input, chama `DeviceIoControl`, joga `std::system_error(GetLastError())` em falha.
- [ ] **Step 2: [BUILD]** Aceite: compila com `affctl_shared.h` (`_KERNEL_MODE` indefinido).
- [ ] **Step 3: Commit** `feat(app): DriverComm RAII wrapper`

## Task 7: TestWindow (app RAII)

**Files:** Create `app/TestWindow.hpp`, `app/TestWindow.cpp`

- [ ] **Step 1:** Classe `TestWindow`: registra classe unica, `CreateWindowExW` (oculta ou visivel via flag), pinta conteudo distintivo no `WM_PAINT`. Dtor `DestroyWindow`. Metodos `hwnd()`, `setAffinity(DWORD mode)` chamando `SetWindowDisplayAffinity`, `pump()` para drenar mensagens.
- [ ] **Step 2: [BUILD]** Aceite: compila.
- [ ] **Step 3: Commit** `feat(app): TestWindow RAII`

## Task 8: OffsetFinder (heuristica)

**Files:** Create `app/OffsetFinder.hpp`, `app/OffsetFinder.cpp`

- [ ] **Step 1:** `findOffset(DriverComm&, HWND)`: (1) `setAffinity(WDA_NONE)`, `base=readRange(N=512)`; (2) `setAffinity(WDA_EXCLUDEFROMCAPTURE)`, `mod=readRange`; (3) candidatos onde `base[i]==0 && mod[i]==0x11`; (4) desambigua com toggle `WDA_MONITOR(0x01)` se >1; (5) erro explicito se 0 ou ainda >1. Retorna offset. Restaura `WDA_NONE` no fim.
- [ ] **Step 2: [BUILD]** Aceite: compila.
- [ ] **Step 3: Commit** `feat(app): heuristic offset finder`

## Task 9: BmpCapture (prova visual)

**Files:** Create `app/BmpCapture.hpp`, `app/BmpCapture.cpp`

- [ ] **Step 1:** `captureWindow(HWND, path)`: `GetWindowRect` -> `BitBlt` para DIB -> grava `.bmp` (BITMAPFILEHEADER+INFOHEADER+bits). Usada p/ before/after.
- [ ] **Step 2: [BUILD]** Aceite: compila.
- [ ] **Step 3: Commit** `feat(app): window BitBlt to bmp`

## Task 10: main.cpp (orquestracao)

**Files:** Create `app/main.cpp`

- [ ] **Step 1:** Parse `--guard`. Discovery: `TestWindow` oculta -> `OffsetFinder::findOffset` -> `comm.setOffset`. Log offset.
- [ ] **Step 2:** Demo: `TestWindow` visivel com conteudo -> `setAffinity(EXCLUDEFROMCAPTURE)` -> `captureWindow(before.bmp)` + print `readAffinity` (0x11) -> `comm.clearAffinity` -> `captureWindow(after.bmp)` + print `readAffinity` (0x00).
- [ ] **Step 3:** Guard (se `--guard`): thread 500ms `readAffinity`; se `0x11`, `clearAffinity`. Para no Enter.
- [ ] **Step 4: [BUILD]** Aceite: `affapp.exe` linka.
- [ ] **Step 5: Commit** `feat(app): orchestration main (discovery+demo+guard)`

## Task 11: vcxproj do app

**Files:** Create `app/affapp.vcxproj`

- [ ] **Step 1:** Console x64 C++17, inclui `../shared`, todos os .cpp do app, link `user32 gdi32`.
- [ ] **Step 2: [BUILD]** Aceite: `msbuild affapp.vcxproj /p:Configuration=Release /p:Platform=x64` gera `affapp.exe`.
- [ ] **Step 3: Commit** `build(app): vcxproj`

## Task 12: Scripts + README

**Files:** Create `scripts/install.bat`, `scripts/uninstall.bat`, `README.md`

- [ ] **Step 1:** `install.bat`: aviso Test Signing (`bcdedit /set testsigning on` + reboot), `sc create affctl type= kernel binPath= <path>`, `sc start affctl`. `uninstall.bat`: `sc stop/delete`.
- [ ] **Step 2:** `README.md`: build (VS+WDK), setup VM+snapshot, WinDbg kernel-debug, execucao, e secao **"Pattern"**: como obter `gSharedInfo` via `x win32kbase!gSharedInfo` e validar structs com `dt win32kfull!tagWND` / `dt win32kbase!tagSHAREDINFO`, ajustando `FindGSharedInfo()` e offsets.
- [ ] **Step 3: Commit** `docs: scripts + README`

---

## [VERIFY-VM] Roteiro final (na VM, apos build)

1. **Smoke:** `install.bat` -> `sc query affctl` = RUNNING; `affapp.exe` abre device sem erro.
2. **Discovery:** offset impresso estavel entre runs; conferir com `dt win32kfull!tagWND` que bate com campo de DisplayAffinity.
3. **Clear:** `readAffinity` = 0x11 apos set, 0x00 apos clear (console).
4. **Visual:** captura externa (Snipping Tool) mostra preto com 0x11; conteudo apos clear.
5. **Guard:** `--guard` reverte reaplicacao.
6. **Robustez:** HWND lixo -> excecao no app, sem BSOD.

Cada teste a partir de snapshot limpo.

---

## Self-Review

- **Cobertura do spec:** todos os 3 componentes + 4 IOCTLs + heuristica + gSharedInfo + SEH + build + riscos cobertos por tasks 1-12 e roteiro VM. OK.
- **Placeholders:** `FindGSharedInfo()` stub e intencional e marcado **[EDIT]** com fallback documentado — nao e placeholder de plano, e ponto de calibracao por-build inerente ao dominio. OK.
- **Consistencia de tipos:** nomes de metodos (`setOffset`/`clearAffinity`/`readAffinity`/`readRange`), IOCTLs e structs identicos entre `affctl_shared.h`, driver e app. OK.
