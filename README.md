# DisplayAffinity Test Driver

Prova de conceito **educacional**: um driver de kernel (Ring 0) + um app user-mode
que, **para janelas do próprio app**, descobrem em runtime o offset da flag
DisplayAffinity dentro da `tagWND` e a zeram (`WDA_NONE`), restaurando a captura
de tela de uma janela que havia sido marcada com `WDA_EXCLUDEFROMCAPTURE`.

> **Escopo e uso.** O app **só** opera sobre janelas que ele mesmo cria
> (`TestWindow`). Não é uma ferramenta para remover proteção de processos de
> terceiros. Use apenas em uma **VM de teste** sua, com Test Signing, para
> aprender internals do win32k. Você é responsável pelo uso.

---

## Arquitetura

```
affapp.exe (User-mode, C++17)          affctl.sys (Kernel, C++ kernel-safe)
------------------------------          -----------------------------------
TestWindow (janela propria)             DriverEntry -> \??\AffCtl
OffsetFinder (heuristica)   ==IOCTL==>  IOCTL_READ_RANGE   -> le tagWND
DriverComm (RAII)                       IOCTL_SET_OFFSET    -> guarda offset
BmpCapture (prova visual)               IOCTL_CLEAR_AFFINITY-> zera flag
                                        IOCTL_READ_AFFINITY -> le flag
                                        tagwnd.cpp: gSharedInfo->aheList->tagWND
```

- **Descoberta de offset (heurística):** o app toggla a afinidade da própria
  janela via API oficial (`WDA_NONE` → `WDA_EXCLUDEFROMCAPTURE` → `WDA_MONITOR`)
  e observa, lendo a `tagWND` pelo driver, qual byte segue o padrão exato
  `0x00 → 0x11 → 0x01`. Sem offset hardcoded → resiliente a versões.
- **Segurança de memória:** toda desreferência de ponteiro de kernel
  (`aheList`, `tagWND`) roda sob `__try/__except` com pré-check `MmIsAddressValid`.
  Ponteiro inválido → `STATUS_ACCESS_VIOLATION`, **não BSOD**.

## Estrutura de arquivos

```
shared/affctl_shared.h      Contrato (IOCTLs + structs de I/O)
driver/win32k_structs.h     Layout parcial de SHAREDINFO/HANDLEENTRY
driver/tagwnd.h/.cpp        gSharedInfo scan, HWND->tagWND, read/write SEH
driver/driver.cpp           DriverEntry, dispatch IOCTL, Unload
driver/affctl.vcxproj/.inf  Projeto WDM + INF
app/DriverComm.hpp/.cpp     RAII sobre DeviceIoControl
app/TestWindow.hpp/.cpp     Janela propria (RAII) + setAffinity
app/OffsetFinder.hpp/.cpp   Heuristica de descoberta do offset
app/BmpCapture.hpp/.cpp     BitBlt da janela -> .bmp
app/main.cpp                Orquestracao (discovery+demo+guard)
app/affapp.vcxproj          Projeto console x64 C++17
scripts/install.bat         sc create + start (Admin)
scripts/uninstall.bat       sc stop + delete (Admin)
```

---

## Pré-requisitos de build

- Windows 10/11 x64
- Visual Studio 2022 (Desktop C++ workload)
- **Windows Driver Kit (WDK)** correspondente ao seu Visual Studio + Windows SDK
- Toolset kernel: `WindowsKernelModeDriver10.0` (vem com o WDK)

## Build

Driver:

```bat
msbuild driver\affctl.vcxproj /p:Configuration=Release /p:Platform=x64
```

App:

```bat
msbuild app\affapp.vcxproj /p:Configuration=Release /p:Platform=x64
```

Saídas em `driver\x64\Release\affctl.sys` e `app\x64\Release\affapp.exe`.

> Você também pode abrir cada `.vcxproj` no Visual Studio e compilar pela IDE.

---

## Setup da VM de teste

1. VM Windows x64 dedicada (Hyper-V, VMware ou VirtualBox).
2. Ligue Test Signing e reinicie:
   ```bat
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```
   Confirme após o reboot:
   ```bat
   bcdedit /enum | findstr /i testsigning
   ```
3. **Tire um snapshot** antes de cada carga do driver. Um bug em Ring 0 pode
   causar BSOD; o snapshot restaura em segundos.
4. (Opcional, recomendado) Kernel debugging com WinDbg via named pipe:
   - No host, WinDbg → File → Kernel Debug → COM/named pipe.
   - Na VM:
     ```bat
     bcdedit /debug on
     bcdedit /dbgsettings serial debugport:1 baudrate:115200
     ```
     (ajuste a porta conforme sua config de VM).

---

## Resolução de `gSharedInfo` — automática via PDB (multi-build)

**Zero calibração manual.** O app resolve `gSharedInfo` em runtime em três passos:

1. **Base do módulo kernel** (`app/ModuleBase.cpp`): `EnumDeviceDrivers` +
   `GetDeviceDriverBaseNameW` retornam a base virtual de `win32kbase.sys` no
   kernel (exige processo Admin — que já temos).
2. **RVA via PDB** (`app/PdbResolver.cpp`): `dbghelp` extrai `GUID+Age` do
   `IMAGE_DEBUG_DIRECTORY` do `win32kbase.sys` local, baixa o PDB correto do
   Microsoft Symbol Server (`https://msdl.microsoft.com/download/symbols`) e
   chama `SymFromName("gSharedInfo")` → RVA exato.
3. **Injeta no driver** via `IOCTL_SET_GSHAREDINFO_ADDR`: driver recebe
   `base + RVA` e usa direto, sem pattern scan ou hardcoded.

### Vantagens

- **Preciso**: PDB é a fonte primária da Microsoft. Sem heurística/AOB.
- **Future-proof**: Windows lança nova build → PDB novo publicado no Symbol
  Server → app baixa automaticamente. Sem release teu.
- **Kernel enxuto**: driver só recebe endereço. Zero disassembly em Ring 0.

### Cache e requisitos

- 1ª execução: precisa internet. PDB baixa uma vez (~poucos MB) em
  `%TEMP%\SymCache`.
- Execuções seguintes: totalmente offline; PDB serve do cache.
- Symbol Server e caminho de cache configuráveis via variável de ambiente
  `_NT_SYMBOL_PATH` (se já estiver definida, o app respeita).
- Requer Admin (mesmo requisito de `sc start` + carga do driver).

### Validação (opcional, WinDbg)

Se quiser conferir se o endereço resolvido pelo app bate com o real:

```
kd> x win32kbase!gSharedInfo
```

Deve casar com a linha `[pdb] endereco absoluto = 0x...` que `affapp.exe` imprime.

O layout de `HANDLEENTRY`/`SHAREDINFO` em `driver/win32k_structs.h` é estável há
muitas versões de Windows 10/11. Se algum dia mudar, valide com:

```
kd> dt win32kbase!tagSHAREDINFO
kd> dt win32kbase!_HANDLEENTRY
```

---

## Executar (na VM, prompt Admin)

```bat
scripts\install.bat driver\x64\Release\affctl.sys
app\x64\Release\affapp.exe
```

Saída esperada (aproximada):

```
[discovery] descobrindo offset da flag DisplayAffinity...
[discovery] offset encontrado = <N> (0x..)
[demo] affinity antes do clear = 0x11 (esperado 0x11)
[demo] captura salva: before.bmp
[demo] affinity apos clear  = 0x00 (esperado 0x00)
[demo] captura salva: after.bmp
[demo] OK — flag removida no kernel.
```

- **`before.bmp` / `after.bmp`** são capturas via BitBlt da própria janela.
- Para a prova externa: com a janela protegida (`0x11`), abra o **Recortar
  (Snipping Tool)** — a janela aparece **preta**. Após o clear, o conteúdo
  reaparece.

Modo cabo-de-guerra (o app reaplica e o driver reverte):

```bat
app\x64\Release\affapp.exe --guard
```

Remover o driver:

```bat
scripts\uninstall.bat
```

---

## Roteiro de verificação (checklist)

1. `sc query affctl` = `RUNNING`; `affapp.exe` abre o device sem erro.
2. Offset descoberto é estável entre execuções na mesma build.
3. `readAffinity` = `0x11` após set, `0x00` após clear.
4. Captura externa mostra preto com `0x11`, conteúdo após clear.
5. `--guard` reverte reaplicação periódica.
6. HWND inválido → app trata exceção, **sem BSOD**.

Rode cada passo a partir de um snapshot limpo.

---

## Riscos conhecidos

- **Layout de `HANDLEENTRY`/`SHAREDINFO`**: não-documentado. Estável há muitas
  versões, mas se a Microsoft mudar (ordem de `phead`/`bType`), edite
  `driver/win32k_structs.h`. Todo o resto (endereço de `gSharedInfo`, offset da
  flag na `tagWND`) já é dinâmico.
- **Symbol Server (1ª execução)**: precisa internet pro download do PDB. Depois
  serve do cache. Se estiver offline no 1º run, o app lança erro claro.
- **Driver não assinado**: exige Test Signing (marca d'água). Assinatura formal
  = EV cert + Microsoft Partner Center (fora do escopo do PoC).
- **Entrega**: código-fonte; build e teste são responsabilidade sua na VM.
