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

## Calibração obrigatória: `FindGSharedInfo()` e structs

O ponto que **precisa** de ajuste por-build é a localização de `gSharedInfo`.
Em `driver/tagwnd.cpp`, a função `FindGSharedInfo()` é um **stub que retorna
`nullptr`**. Enquanto ela retornar `nullptr`, `IOCTL_*` responde
`STATUS_NOT_FOUND`/`STATUS_INVALID_PARAMETER` e o app imprime erro de discovery.

### 1. Obter o endereço de `gSharedInfo` (WinDbg, na VM)

```
kd> x win32kbase!gSharedInfo
```

Isso dá o endereço do símbolo. `gSharedInfo` é uma `SHAREDINFO` (às vezes exposta
como `tagSHAREDINFO`). Inspecione:

```
kd> dt win32kbase!tagSHAREDINFO <endereco>
```

Confirme o campo `aheList` (ponteiro para o array de handle entries) e o
deslocamento dele dentro da struct — deve bater com `driver/win32k_structs.h`.

### 2. Validar o layout de `HANDLEENTRY` e da `tagWND`

```
kd> dt win32kfull!tagWND
kd> dt win32kbase!_HANDLEENTRY
```

- Confirme que `HANDLEENTRY` começa com `phead` (ponteiro para objeto) e tem
  `bType` (janela = `TYPE_WINDOW` = 1). Ajuste `win32k_structs.h` se divergir.
- A flag DisplayAffinity fica dentro da `tagWND` (campos internos como
  `bDisplayAffinity`/`dwExStyle` conforme a build). **Não precisa** cravar esse
  offset à mão: a heurística do app descobre em runtime. O `dt win32kfull!tagWND`
  serve só para **conferir** que o offset descoberto bate com o campo certo.

### 3. Implementar `FindGSharedInfo()`

Duas abordagens (escolha uma):

- **Endereço derivado / símbolo:** se você tem símbolos carregados no ambiente,
  resolva o endereço de `gSharedInfo` no módulo `win32kbase.sys` a partir da base
  do módulo + RVA do símbolo (obtenha a base com `MmGetSystemRoutineAddress` de
  uma export vizinha ou enumerando módulos carregados; some o RVA do símbolo
  visto no WinDbg/PDB).
- **Pattern scan (AOB):** localize, na seção de dados de `win32kbase.sys`, o
  padrão de bytes que referencia `gSharedInfo` (por exemplo o `lea` que carrega
  seu endereço dentro de uma função exportada que você inspeciona no WinDbg com
  `u`), e extraia o endereço do deslocamento relativo. Mantenha o pattern isolado
  nesta função.

Substitua o `return nullptr;` pelo endereço resolvido (`PSHAREDINFO`).

> Como `gSharedInfo` fica em `win32kbase.sys` (sessão), garanta que o acesso
> ocorre no contexto de uma sessão de GUI válida. Para este PoC, as chamadas
> partem do app (que tem GUI), então o IRP chega em contexto adequado.

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

- `gSharedInfo`/`HANDLEENTRY`/`tagWND` **não são documentados** e variam por
  versão. A heurística cobre o offset da flag; `FindGSharedInfo()` e o layout de
  `HANDLEENTRY` precisam de validação WinDbg por build.
- Driver não assinado exige Test Signing (marca d'água na área de trabalho).
- Entrega é **código-fonte**; build e teste são responsabilidade sua na VM.
