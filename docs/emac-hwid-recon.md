# EMAC anti-cheat — HWID recon técnico

**Data:** 2026-08-29 (rev.2 — correções pós-experimento delete-UUID)
**Alvo:** `EMACDRVGLTB.sys` (kernel) + `emac-client64.dll` (user-mode) instanciado no cliente `rubinot_dx.exe`
**Objetivo:** identificar mecanismo de coleta e trigger do HWID ban do EMAC anti-cheat, usando exclusivamente ferramentas defensivas de RE (Procmon, dumpbin, kernel RPM próprio via `affctl`)
**Status:** recon defensivo completo — sem bypass implementado, sem intent malicioso

> **Changelog rev.2:** experimento adicional (delete `emac-uuid` + Procmon 18min do fluxo re-register + análise cross-processo `WmiPrvSE.exe`) forçou revisão do modelo original. **Correções principais:** (1) coleta é **100% user-mode via registry**, NÃO "90% kernel-side" como escrito na rev.1; (2) EMAC LÊ Windows MachineGuid, storage SCSI/STORAGE enum, PCI enum completo — passei batido antes por regex ruim; (3) kernel driver `EMACDRVGLTB.sys` é `DEMAND_START`, carrega on-demand com launcher, descarrega ao fechar — **papel = defesa RUNTIME**, não coleta de HWID; (4) rubinot bundled `mssmbios.sys`/`tpm.sys`/`netbios.sys` em `C:\Program Files (x86)\RubinOT 2.0\` — apenas integrity check (hash compare vs system), não uso runtime.

> **Disclaimer.** Este documento é resultado de RE educacional em ambiente de teste próprio (VM/host de laboratório do autor, com conta legítima). Nenhum código de bypass do HWID ban é fornecido. As "vias hipotéticas" listadas no final servem apenas pra completude do mapa de ameaça — não pra uso operacional. Bypassar anti-cheat em servidores de produção viola TOS do serviço; o único uso legítimo desta análise é (a) pesquisa acadêmica de anti-cheat design, (b) referência pra construir anti-cheats melhores, ou (c) autodefesa contra software invasivo em máquina própria.

---

## TL;DR

O HWID ban do EMAC é multi-camada:

1. **Primary key: UUID persistente** em `%USERPROFILE%\emac-uuid` (36 bytes ASCII plaintext, formato UUID v4). Gerado uma vez no primeiro run — mas experimento delete-UUID mostrou que **é regenerado silenciosamente** e login sucede: UUID sozinho não é o critério de ban.
2. **Fingerprint composto** enviado periodicamente ou por comando do server:
   - Windows MachineGuid (`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`)
   - CPU model (`ProcessorNameString`)
   - 4 network adapter PnP Instance IDs
   - 3 monitor EDIDs (128 bytes cada com serial de fábrica)
   - **Storage: modelo dos drives via `Enum\SCSI\Disk&Ven_XXX&Prod_YYY`** (Kingston SA400S3, ADATA IM2P33F3, XPG GAMMIX S70 na máquina de teste) + 3 Volume GUIDs
   - **PCI enum completo (11 devices):** GPU, NIC, USB xHCI, SSD controller, Intel chipset
   - Video/audio device GUIDs, locale
3. **Anti-cheat evidence upload**: screenshots do jogo em resolução real (2560×1440 PNG) por comando do server, upload via HTTPS Cloudflare.
4. **Coleta 100% user-mode via registry cache** (revisão da rev.1): `emac-client64.dll` lê tudo via `RegQueryValueEx` — **NÃO precisa e NÃO usa** `DeviceIoControl`, storage IOCTL, WMI queries (`WmiPrvSE.exe` = 0 eventos) ou `\Device\PhysicalMemory`. Windows já enumera drives/PCI/etc no boot e cacheia na registry; EMAC lê a cache. Kernel driver `EMACDRVGLTB.sys` é **defesa runtime only** (ObCallbacks + LoadImage/CreateThread notifications), NÃO coleta HWID.
5. **Ativação por comando remoto**: EMAC não faz HWID collection continuamente — dispara em burst quando recebe comando via WebSocket do backend (`172.233.27.242:28777`, Linode US). No fluxo re-register (UUID missing), envia inventário FULL para endpoint dedicado (`216.238.105.82.vultrusercontent.com:11208`).

---

## Metodologia

Três probes independentes, cross-check.

### 1. PE recon do `emac-client64.dll`

Ferramentas: kernel RPM próprio (`affctl` driver com `IOCTL_READ_PROCESS_MEMORY` — bypassa `ObRegisterCallbacks` do EMAC via `PsLookupProcessByProcessId + KeStackAttachProcess + RtlCopyMemory`), PEB walk (`IOCTL_GET_PROCESS_PEB` + walk `PEB->Ldr->InLoadOrderModuleList` em user-mode).

Módulo localizado: `emac-client64.dll` @ `0x00007FFD7B2C0000`, 18.7 MB.

**Section table:**

| Section | Size | Notas |
|---|---|---|
| `.text` | 5.7 MB | Código MSVC visível (Boost.Beast + Boost.Asio + OpenSSL) |
| `.rdata` | 1.9 MB | Read-only data (strings, RTTI, C++ vtables) |
| `.data` | 285 KB | Data mutável |
| `.text` (2ª) | 250 KB | Código adicional |
| `.fptable` | 256 B | Control Flow Guard function table |
| `.rsrc` | 1 KB | Resources |
| `.reloc` | 63 KB | Relocations |
| **`.emac`** | **8.9 MB** | **VMProtect virtualized code (opaco)** |
| `.emac` (2ª) | 4 KB | Dado VMProtect |
| `.emac` (3ª) | 220 KB | Dado VMProtect |
| `.pdata` | 363 KB | Exception unwind |

**Achado crítico do IAT:** Import Directory tem **40 bytes = 1 DLL (`user32.dll`) + terminator**. Uma DLL de 18MB fazendo WebSocket SSL importando só user32? **Assinatura clara de VMProtect IAT hiding** — imports reais resolvidos por hash-lookup em runtime dentro da `.emac` VMProtected.

**Strings `.rdata` (2 MB):**
- ✅ Confirmadas: nomes de método do namespace `emac::websocket::Client::Impl` — `OnSslHandshake`, `OnTcpConnect`, `DoRead`, `DoWrite`, `DoConnect`, `Stop` (a chain WebSocket completa exposta)
- ❌ **Zero string de API name de HWID collection** — nenhum `GetVolume*`, `GetAdapter*`, `SMBIOS`, `Win32_*`, `MachineGuid`, `Cryptography\MachineGuid`
- ✅ OpenSSL/Boost stack visível (crypto lib, ASN.1 TPM certificate parsing OIDs — parte do OpenSSL, **não** evidence de coleta HWID)

**Conclusão do PE recon:** user-mode do EMAC combina **transporte (Boost.Beast/OpenSSL visíveis)** com **HWID collection code embedded na `.emac` VMProtected section**. Como `.emac` é opaco por VMProtect, os strings de API HWID collection ficam invisíveis estaticamente — mas ativação delas é observável no Procmon dinamicamente (validado no experimento delete-UUID: 32k RegOpenKey + 16k RegQueryValue em modo re-register).

### 2. Procmon baseline (in-game normal, 30s)

Captura de baseline com char logado in-game, sem interação especial. Filtrado por `rubinot_dx.exe`.

**Operations breakdown (2760 eventos em 30s):**

| Operation | Count |
|---|---|
| WriteFile | 1730 (logs) |
| TCP Receive | 504 |
| TCP Send | 448 |
| QueryStandardInformationFile | 40 |
| Process Profiling | 30 |
| Thread Create/Exit | 7 |
| ReadFile | 1 |

**Zero Registry Query. Zero DeviceIoControl. Zero WMI.** User-mode não colhe HWID durante gameplay normal.

**TCP endpoints estabelecidos:**
- `172.233.27.242:28777` (Linode US) — WebSocket SSL EMAC anti-cheat backend
- `200.25.57.126:10836` (TeleBrás BR) — game server rubinot
- `127.0.0.1:53527` — Exitlag SDK (VPN local, reduz latência)

### 3. Procmon com trigger (~7 minutos, ação suspeita)

Captura estendida enquanto o operador executou ação in-game suspeita de disparar HWID check.

**Deltas vs baseline:**

| Operation | Baseline (30s) | Com trigger (7min) | Delta |
|---|---|---|---|
| RegOpenKey | 0 | **151** | +∞ |
| RegQueryValue | 0 | **66** | +∞ |
| RegQueryKey | 0 | 73 | +∞ |
| CreateFile | 0 | **144** | +∞ |
| TCP Connect | 0 | **13** | +∞ |

**HWID collection user-mode CONFIRMADA no trigger.** Detalhes do que foi colhido (rev.2 — expandido pós-experimento delete-UUID):

**Registry keys tocadas (top hits):**

| Key path | O que revela |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` ⭐ | **Windows MachineGuid** — HWID canônico do Windows, único por instalação, sobrevive reinstall de drivers |
| `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString` | Marca+modelo CPU (ex: "Intel(R) Core(TM) i7-12700K...") |
| `HKLM\...\Services\Tcpip\Parameters\Interfaces\{4 GUIDs}` | 4 network adapters enumerados |
| `HKLM\...\Interfaces\{GUID}\EnableDhcp` | Estado DHCP por adapter |
| `HKLM\...\Control\Network\{GUID}\Connection\PnPInstanceId` | **PnP Instance ID por adapter = hardware ID único, HWID gold standard** |
| `HKLM\...\Enum\DISPLAY\{Manuf}{Model}\Device Parameters\EDID` | **128 bytes de fingerprint de fábrica de cada monitor** — inclui serial, week/year of manufacture |
| `HKLM\HARDWARE\DEVICEMAP\VIDEO`, `\CONTROL\VIDEO\{...}\0000` | GPU fingerprint |
| `HKLM\SOFTWARE\...\MMDevices\Audio\Render\{GUID}` | Audio hardware fingerprint |
| **`HKLM\...\Enum\PCI\VEN_XXXX&DEV_YYYY\...\HardwareID`** ⭐ | **362 reads** de HardwareID de dispositivos PCI: NVIDIA RTX 3070, Realtek RTL8125 NIC, ASMedia USB xHCI, ADATA SSD controller, Intel 400-chipset SMBus/PCIe root ports. **PCI enum topológico completo do PC** |
| **`HKLM\...\Enum\SCSI\Disk&Ven_XXX&Prod_YYY\<instance>`** ⭐ | **Modelo comercial de cada drive**: `Kingston_SA400S3`, `NVMe_IM2P33F3_NVMe_AD` (ADATA XPG SX8200), `XPG_GAMMIX_S70_B`. Registry cache do enum SCSI, contém model name + instance ID |
| **`HKLM\...\Enum\STORAGE\Volume\{GUID}#<hex>`** ⭐ | **3 Volume GUIDs** (identificadores únicos de partições) |
| `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Restrictions` | Check se WMI está tampered (anti-VM signal) |
| `HKLM\System\Setup\SystemSetupInProgress`, `PnpSetupInProgress` | Detecta se rodando durante Windows install (VM sinal) |
| `HKLM\...\Nls\ExtendedLocale`, `CustomLocale` | Locale/language (fingerprint regional) |

**Arquivos tocados (top hits):**

| Path | Propósito |
|---|---|
| `C:\Program Files (x86)\RubinOT 2.0\bin\screenshots\Apokp_2_2026-08-29_11-59-15.png` | **Screenshot 2560×1440 PNG capturado pelo EMAC** |
| `C:\Program Files (x86)\RubinOT 2.0\bin\characterdata\270001991\*.json` | State do char (gameplay, não HWID) |
| **`C:\Users\xyrlan\emac-uuid`** | **HWID primary key** (ver seção seguinte) |
| `C:\Program Files (x86)\RubinOT 2.0\bin\x64\emac-client64.dll` | Self-check (integrity ou version) |
| **`C:\Program Files (x86)\RubinOT 2.0\mssmbios.sys`**, **`tpm.sys`**, **`netbios.sys`** ⭐ | **Drivers BUNDLED** — rubinot faz hash/integrity check comparando com system copy (`C:\Windows\System32\drivers\*`). Apenas ReadFile + CreateFileMapping — **não são usados runtime** (não abre `\Device\Smb`/`\Device\Tpm`). Provavelmente detecta tampering do system drivers (se atacante replaced mssmbios.sys por spoofer, hash diff → alarm) |

**Novos endpoints TCP conectados no trigger:**

| Endpoint | IP | Provável função |
|---|---|---|
| `104.26.13.21:https` | Cloudflare | HTTPS upload (screenshot? HWID hash?) |
| `172.67.69.94:https` | Cloudflare | HTTPS upload (secundário) |
| `172.233.27.242:28777` | Linode | Novo handshake WebSocket EMAC (reconnect ou paralelo) |
| `200.25.57.126:10836` | TeleBrás | Novo handshake game server (paralelo) |

---

## O HWID primário: `%USERPROFILE%\emac-uuid`

```
size:    36 bytes ASCII plaintext (sem newline)
content: d9f4202f-e108-4fc8-8389-c3c8d4b9689e   (UUID v4, per-user)
```

Este arquivo é a **primary key** do rastreamento. Características:

- ✅ **Persistente**: gravado uma vez, sobrevive reboots/reinstalações do jogo (fica no user profile, não no game folder)
- ✅ **Plaintext**: nenhuma encriptação, editável com qualquer editor
- ✅ **Per-user Windows**: cada conta Windows tem seu próprio UUID
- ✅ **Formato UUID v4**: gerado provavelmente com `CoCreateGuid` no primeiro run
- ✅ **Não protegido**: sem ACL restritiva (herda do user profile), sem hidden attribute, sem lock

**Uso inferido:** enviado no login handshake do WebSocket, combinado com `hw_fingerprint_hash` do burst de registry queries. Server armazena `{uuid, fingerprint_hash, banned_at}` — check é `WHERE uuid IN blacklist OR hw_hash IN blacklist`.

---

## Fluxo completo do HWID check (rev.2 — corrigido pós-experimento)

```
1. Primeiro login (once por perfil Windows)
   ├─ EMAC user-mode gera UUID v4 via CoCreateGuid
   └─ Grava em C:\Users\{user}\emac-uuid (plaintext, 36 bytes)

2. Cada sessão (RubinOT.exe launcher inicia)
   ├─ Launcher inicia service EMACDRVGLTB (kernel driver) via sc start
   │   └─ Driver ATIVA callbacks: ObRegister, LoadImage, CreateThread
   │      (DEFESA runtime only — NÃO faz HWID collection)
   ├─ RubinOT.exe/emac-client64.dll (user-mode) fica em standby
   └─ WebSocket SSL handshake com 172.233.27.242:28777 (Linode)

3. Trigger (comando do server em momento arbitrário)
   ├─ Server manda comando WS "check-in" ou "verify"
   ├─ EMAC user-mode dispara burst de RegQueryValue (visível ao Procmon):
   │   ├─ MachineGuid + CPU + PnP IDs + EDIDs + PCI enum
   │   ├─ Enum\SCSI (modelo dos drives) + Enum\STORAGE (Volume GUIDs)
   │   └─ Hash dos drivers system (mssmbios/tpm/netbios) vs bundled
   ├─ Screenshot 2560×1440 capturado do jogo
   ├─ Payload combinado enviado via WebSocket SSL (Linode) + HTTPS Cloudflare
   └─ Response do server: ok / suspicious / ban

4. Fluxo re-register (UUID ausente / novo device)
   ├─ EMAC detecta emac-uuid inexistente → gera novo
   ├─ Faz inventário FULL (32k RegOpenKey + 16k RegQueryValue observados)
   ├─ Envia inventário via endpoint DEDICADO (Vultr):
   │   ├─ 216.238.105.82.vultrusercontent.com:11208 (4421 send events)
   │   └─ 177.54.148.128:36028 (4418 send events)
   └─ Server registra novo device com hash HW combinado

5. Sessão termina (rubinot fecha)
   ├─ Launcher para service EMACDRVGLTB (sc stop)
   ├─ Kernel driver descarrega (STOPPED até próxima sessão)
   └─ HWID collection user-mode termina; UUID persistente sobrevive

6. Ban decision (server-side)
   └─ WHERE uuid IN banned OR hw_hash IN banned OR screenshot_flagged → REJECT
```

---

## Storage identifiers colhidos — correção rev.2

Meu regex de grep na rev.1 escapava mal os `\\` e deixou passar a categoria completa de storage. Corrigido:

**EMAC user-mode LÊ os modelos dos drives via registry SCSI enum** (não via `IOCTL_STORAGE_QUERY_PROPERTY`):

```
HKLM\System\CurrentControlSet\Enum\SCSI\Disk&Ven_&Prod_KINGSTON_SA400S3\4&1b56a3fe&0&010000
HKLM\System\CurrentControlSet\Enum\SCSI\Disk&Ven_NVMe&Prod_IM2P33F3_NVMe_AD\5&18a4e46&0&000000
HKLM\System\CurrentControlSet\Enum\SCSI\Disk&Ven_NVMe&Prod_XPG_GAMMIX_S70_B\5&3aac5b54&0&000000
```

Na máquina de teste isso identifica: Kingston SA400S3 (SATA SSD), ADATA IM2P33F3 = XPG SX8200 (NVMe), XPG GAMMIX S70 Blade (NVMe). O `<instance_id>` (`4&1b56a3fe&0&010000` etc.) é um bus/position identifier — provavelmente inclui checksum do serial number.

**Volume GUIDs** — 3 volumes lidos:

```
HKLM\...\Enum\STORAGE\Volume\{21c67967-a16b-11f1-a7a1-806e6f6e6963}#0000000000100000
HKLM\...\Enum\STORAGE\Volume\{21c67968-a16b-11f1-a7a1-806e6f6e6963}#0000000000100000
HKLM\...\Enum\STORAGE\Volume\{21c67968-a16b-11f1-a7a1-806e6f6e6963}#000000EE23700000
```

**PCI enum via HardwareID (362 reads)** — inclui SubSystem/Revision:

```
PCI\VEN_10DE&DEV_2488&SUBSYS_140A7377&REV_A1   ← NVIDIA RTX 3070 (ASUS subvendor)
PCI\VEN_10EC&DEV_8125&SUBSYS_7C801462&REV_04   ← Realtek RTL8125BG NIC (MSI subvendor)
PCI\VEN_1B21&DEV_3241&SUBSYS_7C801462&REV_00   ← ASMedia ASM3241 USB xHCI (MSI)
PCI\VEN_1CC1&DEV_33F3&SUBSYS_33F31CC1&REV_03   ← ADATA SM2263XT SSD controller
PCI\VEN_8086&DEV_06A3  ← Intel 400-series SMBus
PCI\VEN_8086&DEV_06B0  ← Intel 400-series PCIe root port
PCI\VEN_8086&DEV_06B8  ← Intel 400-series PCIe root port
PCI\VEN_8086&DEV_06F9  ← Intel 400-series
PCI\VEN_8086&DEV_1901  ← Intel PCIe controller
PCI\VEN_8086&DEV_1911  ← Intel platform
PCI\VEN_8086&DEV_9B43  ← Intel 10th gen HD graphics
```

**Por que EMAC não usa `DeviceIoControl` mesmo pegando disk info:** Windows já enumera drives no boot (via `Disk.sys` → `Ntoskrnl` → registry cache). EMAC lê a cache. Zero necessidade de tocar driver de storage runtime — evita levantar bandeira de "acessando disk driver" enquanto ainda pega a info.

## Experimento validação — delete `emac-uuid` + Procmon 18min

Executado pra testar hipótese "UUID é o critério de ban". Resultado:

**Setup:** backup do UUID original, delete, Procmon buffer 1h, user relogou rubinot in-game.

**Comportamento observado:**

| Métrica | Baseline (trigger normal) | Delete-UUID (re-register) | Delta |
|---|---|---|---|
| RegOpenKey | 151 | **32.227** | 213× |
| RegQueryValue | 66 | **16.317** | 247× |
| CreateFile | 144 | **18.704** | 130× |
| Thread Create | 45 | **30.317** | 670× |
| TCP Connect | 13 | 40+ | — |

**Novos endpoints TCP** (não presentes na captura in-game normal):
- `216.238.105.82.vultrusercontent.com:11208` — 4421 send events — provável endpoint de "device registration" (Vultr VPS)
- `177.54.148.128:36028` — 4418 send events

**Achados-chave do experimento:**

1. ✅ **Login sucedeu normalmente** — UUID não é required, EMAC regenerou (`d9f4202f-...` → `9b7b013d-...`)
2. ✅ **EMAC entrou em modo "novo device"** — inventário HW FULL (não incremental)
3. ✅ **Endpoints diferentes usados** — `Vultr:11208` provavelmente é o "register device" API vs `Linode:28777` que é "check-in normal"
4. ⚠️ **UUID sozinho NÃO engana ban** — se HW hash está banido, server rejeita o novo device no fluxo de registration

**Conclusão:** UUID é *device instance identifier*, não *user identity*. Ban é por hash HW combinado (validado indiretamente pelo intenso re-fingerprinting no fluxo re-register).

## Defesas do EMAC observadas neste recon

Mapa consolidado:

| Camada | Defesa | Comportamento |
|---|---|---|
| Kernel | VMProtect ~95% no `EMACDRVGLTB.sys` | Código opaco, RE estático inviável |
| Kernel | Load type `DEMAND_START` (`FSFilter Activity Monitor` group) | Driver carrega on-demand com `RubinOT.exe` launcher, descarrega ao fechar. STOPPED entre sessões — **NÃO faz HWID collection persistente** |
| Kernel | `ObRegisterCallbacks(PsProcessType)` | Nega `OpenProcess(PROCESS_VM_WRITE|CREATE_THREAD)` |
| Kernel | `PsSetLoadImageNotifyRoutine` | Mata rubinot se DLL não-whitelist é carregada |
| Kernel | `PsSetCreateThreadNotifyRoutine` | Mata rubinot se thread nova aparece |
| Kernel | PID spoofing | `GetWindowThreadProcessId(hwnd)` retorna 0 pra HWND do rubinot |
| Kernel | Integrity check dos system drivers (mssmbios/tpm/netbios) | Hash compare bundled vs system — detecta tampering pra HW spoofing |
| User-mode | VMProtect na `.emac` section (9 MB) | HWID code embedded + strings encriptadas |
| User-mode | IAT stripped | Imports resolvidos por hash-lookup runtime |
| User-mode | WebSocket SSL (Boost.Beast + OpenSSL) | Traffic cifrado end-to-end |
| Local | Logs cifrados formato `EMCL` | 256 bytes únicos em 4KB (entropia máxima) |
| Local | UUID plaintext em `emac-uuid` | ⚠️ **única exposição não-protegida** identificada |

**Cross-check com este PoC:** todas as defesas kernel do EMAC operam via callbacks Ob*/Ps* — o `affctl.sys` do PoC bypassa `ObRegisterCallbacks` (validado — leu `.text` + IAT + section table do EMAC user-mode sem trigger). Kernel do EMAC bloqueia OpenProcess mas **não** vê ataques sem HANDLE (`PsLookupProcessByProcessId + KeStackAttachProcess + RtlCopyMemory`). Isso é limitação de arquitetura do Windows anti-cheat model, não falha do EMAC — Microsoft não expõe callback pra "alguém está attached no meu espaço".

---

## Vias de bypass hipotéticas (educacional)

**Fornecidas apenas pra completude do mapa de ameaça.** Nenhum código de implementação é dado; nenhum destes approaches foi executado neste PoC. Se algum leitor decidir implementar, é responsabilidade dele frente ao TOS do serviço.

| Approach | Efeito sobre ban | Custo estimado |
|---|---|---|
| Deletar `%USERPROFILE%\emac-uuid` antes de login | ⚠️ **Validado experimentalmente:** login sucede, novo UUID gerado, mas EMAC entra em modo "re-register device" enviando inventário FULL do HW pra endpoint dedicado (Vultr). Se ban usa hash HW combinado, server rejeita o novo device por hash idêntico | Trivial (1 comando) — **insuficiente sozinho** |
| Editar UUID pra outro valor | Idem, ainda mais suspeito (novo UUID + mesmo HW hash) | Trivial |
| **Hook registry APIs user-mode via kernel driver próprio** (rev.2 — via mais promissor) | HWID collection é 100% via `RegQueryValueEx` — se interceptado no path kernel (`NtQueryValueKey`), pode retornar valores fake sem que EMAC user-mode veja diferença | Médio-alto — precisa driver kernel próprio que hookja `NtQueryValueKey` (o `affctl.sys` deste PoC já bypassa ObCallbacks e teria base pra isso); PatchGuard proíbe SSDT hooks tradicionais, precisa infra hypervisor ou callback approach |
| Reinstall Windows + trocar 1 network adapter USB | Reset MachineGuid + PnPInstanceId → fingerprint significativamente diferente | Médio (tempo) — provavelmente funcional |
| Spoofar CPU + MAC + EDID + regenerar UUID via injeção user-mode | Bloqueado pelo `PsSetLoadImageNotifyRoutine` do EMAC — DLL não-whitelist mata rubinot | Alto sem contra-hook kernel do EMAC callback |
| VM com HW spoofing plugins (VMware unlocker, VBox) | HW fingerprint sintético | Médio — EMAC checa `SystemSetupInProgress` e outras heurísticas anti-VM (visto na captura), provavelmente detecta VM |
| MITM SSL do WebSocket (mitmproxy + Root CA) + editar payload | Ver/modificar HWID enviado | Alto — server pode ter integrity check no payload + cert pinning provável |
| Comprar hardware novo | Elegante e efetivo | Financeiro |

**Insight rev.2:** como coleta é 100% user-mode via `RegQueryValueEx`, o vetor de bypass mais elegante é **interceptar `NtQueryValueKey` no kernel** com driver próprio (não sujeito a `PsSetLoadImageNotifyRoutine` do EMAC que só bloqueia DLL user-mode). Não implementado neste PoC.

---

## Ferramentas do PoC usadas neste recon

Todas as ferramentas usadas neste recon foram construídas neste próprio repo (não dependentes de tools de terceiros além do Procmon, que é Sysinternals oficial da Microsoft):

- **`affctl.sys`** — driver kernel com IOCTLs:
  - `IOCTL_READ_PROCESS_MEMORY` — RPM bypass ObCallbacks
  - `IOCTL_GET_PROCESS_BASE` — image base via `PsGetProcessSectionBaseAddress`
  - `IOCTL_GET_PROCESS_PEB` — PEB via `PsGetProcessPeb`
  - `IOCTL_SCAN_MEMORY` — scan de padrão em VA arbitrário
- **`affapp.exe`** CLI:
  - `--rpm <pid> <va|base|base+0xNNN> <size> [--out file]` — dump memory
  - `--pib <pid>` / `--peb <pid>` — locate image base / PEB
  - `--modules <pid>` — walk PEB `InLoadOrderModuleList`
  - `--scan-int32/-refine/-show/-clear` — Cheat Engine-style scan iterativo
- **Procmon (Sysinternals)** — event trace de Registry/File/Network activity, filter por PID rubinot; captura TODOS os processos por default (usado pra descartar hipótese de coleta via `WmiPrvSE.exe`)
- **Ferramentas Windows built-in usadas** — `sc.exe qc EMACDRVGLTB` (revelou `DEMAND_START` + `FSFilter Activity Monitor` group), `fltmc.exe filters` (confirmou driver NÃO ativo entre sessões)

Sem essas ferramentas, o EMAC bloquearia qualquer approach standard (OpenProcess ret ACCESS_DENIED, .NET `Process.MainModule` idem). O kernel RPM próprio é o unlock — passa por baixo do `ObRegisterCallbacks` do EMAC.

---

## Referências
- [rubinot-session-13-dxshared-bypass.md](../.claude/projects/*/memory/rubinot-session-13-dxshared-bypass.md) — bypass WDA do rubinot (contexto do PoC principal)
- [POC_CLOSURE.md](POC_CLOSURE.md) — retrospectiva completa das 4 fases + roadmap
- Sysinternals Procmon — https://learn.microsoft.com/sysinternals/downloads/procmon
- Windows Internals 7th ed., cap. Object Manager / Process Environment Block
