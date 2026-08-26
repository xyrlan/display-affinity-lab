# DisplayAffinity Test Driver — Design

**Data:** 2026-08-26
**Escopo:** Prova de conceito. Driver kernel + app user-mode que removem a flag
DisplayAffinity (`WDA_EXCLUDEFROMCAPTURE` / `WDA_MONITOR`) da estrutura `tagWND`
de **janelas de propriedade do próprio app**. Sem bypass de processos de terceiros.

---

## 1. Objetivo e não-objetivos

**Objetivo:** demonstrar, de forma controlada e educacional, o mecanismo Ring 0:
um app user-mode cria uma janela própria, aplica
`SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` (janela some em captura de
tela), e um driver de kernel sobrescreve a flag na `tagWND` de volta para
`WDA_NONE`, restaurando a captura — sem injeção de DLL no alvo.

**Não-objetivos:**
- Não remover proteção de processos de terceiros. O app só passa HWNDs que ele
  mesmo criou (validação abaixo).
- Não distribuir driver assinado para produção. Entrega = código-fonte + build
  files + instruções. Uso restrito a VM de teste com Test Signing.
- Não usar offsets hardcoded (quebram em atualização do Windows). Offset é
  descoberto em runtime por heurística.

---

## 2. Ambiente

- **Geração do código:** macOS. Não compila nem testa aqui.
- **Build:** Windows 10/11 x64 + Visual Studio 2022 + Windows Driver Kit (WDK)
  correspondente + Windows SDK.
- **Teste:** VM Windows x64 dedicada com:
  - `bcdedit /set testsigning on` + reboot
  - Snapshot antes de cada carga do driver
  - WinDbg em kernel-debug (named pipe host↔VM) para inspecionar `tagWND` e
    diagnosticar eventual BSOD

---

## 3. Componentes

Três componentes, cada um com responsabilidade única e interface bem definida.

### 3.1 Kernel Driver — `affctl.sys` (C++ kernel-safe, WDM)

**Linguagem:** projeto C++. `extern "C"` apenas em `DriverEntry` e nos dispatch
handlers (ABI exigida pelo kernel). Lógica interna (scan da `tagWND`, resolução
gSharedInfo, manipulação) em C++ idiomático dentro do subset kernel-safe:
**sem STL, sem exceptions C++, sem RTTI**; SEH `__try/__except` para guarda de
memória; alocação via `ExAllocatePool2`.

**Device:** `\Device\AffCtl` (`IoCreateDevice`, `FILE_DEVICE_UNKNOWN`) + symlink
`\??\AffCtl` (`IoCreateSymbolicLink`) para o app abrir via `CreateFile`.

**Dispatch:** `IRP_MJ_CREATE`, `IRP_MJ_CLOSE` (sucesso trivial),
`IRP_MJ_DEVICE_CONTROL` (todos os IOCTLs), `Unload` (deleta symlink + device).

**IOCTLs (METHOD_BUFFERED):**

| IOCTL | Input | Output | Ação |
|-------|-------|--------|------|
| `IOCTL_READ_RANGE` | `{ HWND hwnd; ULONG count; }` | `BYTE[count]` | Resolve tagWND, copia `count` bytes do início da struct para o buffer de saída. Só para a fase de discovery. |
| `IOCTL_SET_OFFSET` | `{ ULONG offset; }` | — | Guarda o offset da flag DisplayAffinity (descoberto pela heurística) numa global do driver. |
| `IOCTL_CLEAR_AFFINITY` | `{ HWND hwnd; }` | — | Resolve tagWND, escreve `0x00` (WDA_NONE) no offset guardado. |
| `IOCTL_READ_AFFINITY` | `{ HWND hwnd; }` | `{ BYTE value; }` | Resolve tagWND, lê o byte no offset guardado (usado pelo polling tug-of-war). |

Códigos IOCTL definidos em header compartilhado `affctl_shared.h`
(incluído pelo driver e pelo app) via `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800..0x803,
METHOD_BUFFERED, FILE_ANY_ACCESS)`.

**Resolução HWND → tagWND (gSharedInfo + aheList):**

1. Localizar `gSharedInfo` no `win32kbase.sys` (ou `win32k.sys` conforme build) via
   **pattern scan** feito uma vez na inicialização/primeira chamada. `gSharedInfo`
   é do tipo `SHAREDINFO`, cujo campo `aheList` aponta para o array de
   `HANDLEENTRY`.
2. Índice = `LOWORD(hwnd)` (12–16 bits baixos do HWND são o índice na tabela).
   Validar contra `psi->cHandleEntries`.
3. `HANDLEENTRY he = aheList[index];` — checar `he.bType == TYPE_WINDOW (1)` e
   `he.pOwner`/`he.phead != NULL`.
4. `pTagWnd = he.phead;` — ponteiro para a `tagWND` no kernel.

Structs `SHAREDINFO`/`HANDLEENTRY` declaradas no driver conforme layout público
conhecido (documentado em `references/`), com o mínimo de campos necessários.
gSharedInfo/aheList residem em endereço de sessão/kernel acessível de Ring 0.

**Guarda de memória:** toda leitura/escrita em `tagWND`, `aheList` e ponteiros
derivados é envolvida em `__try/__except (EXCEPTION_EXECUTE_HANDLER)`. Falha →
retorna `STATUS_ACCESS_VIOLATION` ou `STATUS_INVALID_PARAMETER`, nunca BSOD.
Valida buffers de IRP (tamanho de input/output) antes de tocar ponteiros.

**Nota sobre validação de endereço kernel:** os endereços resolvidos (`aheList`,
`phead`/tagWND) são endereços de **kernel**, não user-mode. Portanto:
- **Não** usar `ProbeForRead`/`ProbeForWrite` sobre eles — essas rotinas exigem
  endereço user-mode e lançam se receberem endereço kernel.
- Pré-checar com `MmIsAddressValid(addr)` (best-effort; não é garantia sozinho).
- A rede de segurança real é o `__try/__except` em torno da desreferência.
- O buffer de saída do IRP é METHOD_BUFFERED (`SystemBuffer`), já mapeado e
  seguro; a cópia final para ele fica igualmente dentro do `__try`.

Esqueleto do handler `IOCTL_READ_RANGE`:
```c
__try {
    PVOID pTagWnd = ResolveTagWnd(input->Hwnd);      // gSharedInfo→aheList→phead
    if (!pTagWnd || !MmIsAddressValid(pTagWnd)) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        RtlCopyMemory(outBuf, pTagWnd, count);        // outBuf = SystemBuffer
        status = STATUS_SUCCESS;
    }
} __except (EXCEPTION_EXECUTE_HANDLER) {
    status = STATUS_ACCESS_VIOLATION;                 // sem BSOD
}
```
Mesmo padrão em `IOCTL_CLEAR_AFFINITY` (escrita) e `IOCTL_READ_AFFINITY`.

### 3.2 User-mode App — `affapp.exe` (C++17)

**Linguagem:** C++ completo — classes, RAII, STL.

**Classe `DriverComm`** (RAII sobre `HANDLE`): abre `\\.\AffCtl` no ctor, fecha no
dtor. Métodos tipados que embrulham `DeviceIoControl`:
`readRange(hwnd, count) -> std::vector<BYTE>`, `setOffset(offset)`,
`clearAffinity(hwnd)`, `readAffinity(hwnd) -> BYTE`. Erros viram exceção C++
(`std::system_error` com `GetLastError`).

**Classe `TestWindow`** (RAII): registra classe, cria janela, `DestroyWindow` no
dtor. Wrapper `setAffinity(mode)` sobre `SetWindowDisplayAffinity`.

**Fase de discovery do offset (heurística):**
1. Cria janela oculta de teste `W`.
2. `W.setAffinity(WDA_NONE)`; `base = comm.readRange(W.hwnd, N)` (ex. N=512).
3. `W.setAffinity(WDA_EXCLUDEFROMCAPTURE)`; `mod = comm.readRange(W.hwnd, N)`.
4. Varre `base` vs `mod`: acha índice `i` onde `base[i]==0x00 && mod[i]==0x11`
   (ou `0x01` para WDA_MONITOR). Esse `i` = offset da flag DisplayAffinity.
5. Se múltiplos candidatos: repete com toggle WDA_MONITOR (0x01) para desambiguar.
6. `comm.setOffset(i)`. Log do offset descoberto.

**Fase de demonstração:**
1. Cria janela visível `D` com conteúdo distintivo.
2. `D.setAffinity(WDA_EXCLUDEFROMCAPTURE)` — captura da tela mostra a região preta.
3. Captura "antes" via BitBlt da própria janela → salva `before.bmp`.
4. `comm.clearAffinity(D.hwnd)` — driver zera a flag.
5. Captura "depois" via BitBlt → salva `after.bmp`. Conteúdo agora visível.
6. Imprime no console o valor lido por `readAffinity` antes/depois (0x11 → 0x00).

**Tug-of-war (opcional, flag `--guard`):** thread de background que a cada ~500ms
chama `readAffinity`; se voltou a `0x11` (app reaplicou), chama `clearAffinity`
de novo. Demonstra o "cabo de guerra" no kernel. Encerra com sinal de parada.

**Segurança de escopo:** o app só opera sobre HWNDs que ele próprio criou
(`TestWindow`), nunca aceita HWND externo por argumento. O driver, sendo genérico,
depende dessa disciplina do app — documentado como restrição de uso.

### 3.3 Build & Deploy

- `driver/affctl.vcxproj` — projeto WDM KMDF-free (WDM puro) x64 Release/Debug.
- `driver/affctl.inf` — INF mínimo para `sc`/instalação.
- `app/affapp.vcxproj` — console app x64 C++17.
- `shared/affctl_shared.h` — IOCTLs + structs de I/O compartilhados.
- `scripts/install.bat` — `bcdedit /set testsigning on` (avisa reboot),
  `sc create affctl type= kernel binPath= <path>`, `sc start affctl`.
- `scripts/uninstall.bat` — `sc stop affctl`, `sc delete affctl`.
- `README.md` — passos de build (VS+WDK), setup da VM, execução, e como
  re-descobrir o pattern do gSharedInfo via WinDbg se o scan falhar.

---

## 4. Fluxo de dados

```
affapp.exe                         affctl.sys (Ring 0)
----------                         -------------------
TestWindow cria HWND próprio
SetWindowDisplayAffinity(0x11)
  └─ Windows grava 0x11 na tagWND no kernel
DriverComm.readRange(hwnd,N) ──IOCTL──► resolve tagWND (gSharedInfo→aheList→phead)
                             ◄──bytes── copia N bytes
[heurística acha offset i]
DriverComm.setOffset(i) ─────IOCTL──► guarda offset global
DriverComm.clearAffinity(hwnd) ─IOCTL─► resolve tagWND; escreve 0x00 no offset i
                             ◄──status─ NTSTATUS
BitBlt before/after prova visual
```

---

## 5. Tratamento de erros

| Situação | Driver | App |
|----------|--------|-----|
| HWND inválido / índice fora do range | `STATUS_INVALID_PARAMETER` | exceção → log, aborta fase |
| gSharedInfo não encontrado (pattern falhou) | `STATUS_NOT_FOUND` na 1ª chamada | mensagem clara + aponta seção WinDbg do README |
| tagWND ponteiro nulo/inacessível | `__except` → `STATUS_ACCESS_VIOLATION` | exceção → log |
| Offset não setado antes de clear | `STATUS_INVALID_DEVICE_STATE` | garante ordem discovery→clear |
| Buffer IRP com tamanho errado | valida e rejeita antes de tocar ponteiro | — |
| Heurística acha 0 ou >1 candidato | — | tenta toggle alternativo; se ainda ambíguo, erro explícito |

Princípio: **driver nunca confia em input sem validar tamanho e range; toda
desreferência de ponteiro kernel sob SEH.** Objetivo é falhar limpo, não BSOD.

---

## 6. Testes

Sem harness automatizado de kernel nesta PoC (exige VM). Validação manual em VM:

1. **Smoke:** driver carrega (`sc start` OK), device abre no app.
2. **Discovery:** offset descoberto é estável entre execuções na mesma build.
   Confirmar com `dt win32kfull!tagWND` no WinDbg que o offset bate com o campo
   de DisplayAffinity.
3. **Clear:** `readAffinity` retorna 0x11 após set, 0x00 após clear.
4. **Visual:** `before.bmp` mostra janela; captura externa (ex. Snipping Tool)
   mostra preto com 0x11 e conteúdo após clear.
5. **Guard:** com `--guard`, reaplicar afinidade e ver o driver revertê-la.
6. **Robustez:** passar HWND lixo → app trata exceção, sem crash/BSOD.

Cada teste roda a partir de snapshot limpo.

---

## 7. Riscos assumidos e sinalizados

- **Pattern do gSharedInfo pode mudar entre builds** do Windows. Mitigação:
  documentar no README como re-obter o endereço via WinDbg
  (`x win32kbase!gSharedInfo`) e como ajustar/derivar o pattern.
- **Layout de `SHAREDINFO`/`HANDLEENTRY`/`tagWND` não é documentado oficialmente**
  e varia por versão. A heurística cobre o offset da flag; os offsets de
  `aheList`/`phead` são declarados por versão conhecida e checados no WinDbg.
- **Entrega é código, não binário assinado.** Teste é responsabilidade do usuário
  em VM. Sem eu compilar/rodar (host macOS).
- **Escopo trava em janelas próprias** por disciplina do app; o driver é genérico
  e não deve ser usado contra processos de terceiros.

---

## 8. Estrutura de arquivos

```
DisplayAffinityTool/
├── README.md
├── shared/
│   └── affctl_shared.h
├── driver/
│   ├── affctl.vcxproj
│   ├── affctl.inf
│   ├── driver.cpp          (DriverEntry, dispatch, Unload — extern "C" nas entradas)
│   ├── tagwnd.cpp/.h        (gSharedInfo scan, HWND→tagWND, read/write flag)
│   └── win32k_structs.h     (SHAREDINFO, HANDLEENTRY, tagWND parcial)
├── app/
│   ├── affapp.vcxproj
│   ├── main.cpp             (orquestra discovery + demo + guard)
│   ├── DriverComm.hpp/.cpp  (RAII sobre DeviceIoControl)
│   └── TestWindow.hpp/.cpp  (RAII de janela + setAffinity)
├── scripts/
│   ├── install.bat
│   └── uninstall.bat
└── docs/
    └── superpowers/specs/2026-08-26-display-affinity-driver-design.md
```
