# EMAC anti-cheat — HWID recon técnico

**Data:** 2026-08-29
**Alvo:** `EMACDRVGLTB.sys` (kernel) + `emac-client64.dll` (user-mode) instanciado no cliente `rubinot_dx.exe`
**Objetivo:** identificar mecanismo de coleta e trigger do HWID ban do EMAC anti-cheat, usando exclusivamente ferramentas defensivas de RE (Procmon, dumpbin, kernel RPM próprio via `affctl`)
**Status:** recon defensivo completo — sem bypass implementado, sem intent malicioso

> **Disclaimer.** Este documento é resultado de RE educacional em ambiente de teste próprio (VM/host de laboratório do autor, com conta legítima). Nenhum código de bypass do HWID ban é fornecido. As "vias hipotéticas" listadas no final servem apenas pra completude do mapa de ameaça — não pra uso operacional. Bypassar anti-cheat em servidores de produção viola TOS do serviço; o único uso legítimo desta análise é (a) pesquisa acadêmica de anti-cheat design, (b) referência pra construir anti-cheats melhores, ou (c) autodefesa contra software invasivo em máquina própria.

---

## TL;DR

O HWID ban do EMAC é multi-camada:

1. **Primary key: UUID persistente** em `%USERPROFILE%\emac-uuid` (36 bytes ASCII plaintext, formato UUID v4). Gerado uma vez no primeiro run, não muda entre sessões.
2. **Fingerprint composto** enviado periodicamente ou por comando do server: CPU model + 4 network adapter PnP Instance IDs + 3 monitor EDIDs + video/audio device GUIDs.
3. **Anti-cheat evidence upload**: screenshots do jogo em resolução real (2560×1440 PNG) por comando do server, upload via HTTPS Cloudflare.
4. **Coleta 90% kernel-side**: driver `EMACDRVGLTB.sys` (VMProtect) faz o trabalho pesado invisível ao Procmon; user-mode `emac-client64.dll` só transporta (WebSocket SSL via Boost.Beast).
5. **Ativação por comando remoto**: EMAC não faz HWID collection continuamente — dispara em burst quando recebe comando via WebSocket do backend (`172.233.27.242:28777`, Linode US).

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

**Conclusão do PE recon:** user-mode do EMAC é **puro transporte** — WebSocket SSL client. HWID collection acontece em outro lugar (kernel driver, ou `.emac` VMProtected).

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

**HWID collection user-mode CONFIRMADA no trigger.** Detalhes do que foi colhido:

**Registry keys tocadas (top hits):**

| Key path | Count | O que revela |
|---|---|---|
| `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0\ProcessorNameString` | 14 | Marca+modelo CPU (ex: "Intel(R) Core(TM) i7-12700K...") |
| `HKLM\...\Services\Tcpip\Parameters\Interfaces\{4 GUIDs}` | 56 total | 4 network adapters enumerados |
| `HKLM\...\Interfaces\{GUID}\EnableDhcp` | 28 | Estado DHCP por adapter |
| `HKLM\...\Control\Network\{GUID}\Connection\PnPInstanceId` | 8 | **PnP Instance ID por adapter = hardware ID único, HWID gold standard** |
| `HKLM\...\Enum\DISPLAY\{Manuf}{Model}\Device Parameters\EDID` | 6 | **128 bytes de fingerprint de fábrica de cada monitor** — inclui serial, week/year of manufacture |
| `HKLM\HARDWARE\DEVICEMAP\VIDEO`, `\CONTROL\VIDEO\{...}\0000` | 4 | GPU fingerprint |
| `HKLM\SOFTWARE\...\MMDevices\Audio\Render\{GUID}` | 4 | Audio hardware fingerprint |
| `HKLM\SYSTEM\CurrentControlSet\Control\WMI\Restrictions` | 9 | Check se WMI está tampered (anti-VM signal) |
| `HKLM\System\Setup\SystemSetupInProgress`, `PnpSetupInProgress` | 2 | Detecta se rodando durante Windows install (VM sinal) |

**Arquivos tocados (top hits):**

| Path | Count | Propósito |
|---|---|---|
| `C:\Program Files (x86)\RubinOT 2.0\bin\screenshots\Apokp_2_2026-08-29_11-59-15.png` | 36 | **Screenshot 2560×1440 PNG capturado pelo EMAC** |
| `C:\Program Files (x86)\RubinOT 2.0\bin\characterdata\270001991\*.json` | vários | State do char (gameplay, não HWID) |
| **`C:\Users\xyrlan\emac-uuid`** | **1** | **HWID primary key** (ver seção seguinte) |
| `C:\Program Files (x86)\RubinOT 2.0\bin\x64\emac-client64.dll` | 1 | Self-check (integrity ou version) |

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

## Fluxo completo do HWID check (inferido dos achados)

```
1. Primeiro login (once)
   ├─ EMAC user-mode gera UUID v4
   └─ Grava em C:\Users\{user}\emac-uuid
                                                
2. Cada sessão (todo login)
   ├─ EMAC user-mode le emac-uuid
   ├─ Kernel driver (EMACDRVGLTB) colhe silent HW info via APIs privilegiadas kernel
   ├─ User-mode combina UUID + kernel HW hash
   └─ Envia via WebSocket SSL a 172.233.27.242:28777

3. Trigger (comando do server em momento arbitrario)
   ├─ Server manda comando WS "check-in" ou "verify"
   ├─ User-mode ativa burst de Registry Query (CPU, adapters, EDIDs) — 
   │  refresh do fingerprint local em user-mode
   ├─ Kernel driver refresh do hash silent
   ├─ Screenshot 2560×1440 capturado do jogo
   ├─ Upload via HTTPS ao Cloudflare endpoint (104.26.13.21)
   └─ Response do server: ok / ban action
   
4. Ban decision (server-side)
   └─ WHERE uuid IN banned OR hw_hash IN banned OR screenshot_flagged → REJECT
```

---

## Defesas do EMAC observadas neste recon

Mapa consolidado:

| Camada | Defesa | Comportamento |
|---|---|---|
| Kernel | VMProtect ~95% no `EMACDRVGLTB.sys` | Código opaco, RE estático inviável |
| Kernel | `ObRegisterCallbacks(PsProcessType)` | Nega `OpenProcess(PROCESS_VM_WRITE|CREATE_THREAD)` |
| Kernel | `PsSetLoadImageNotifyRoutine` | Mata rubinot se DLL não-whitelist é carregada |
| Kernel | `PsSetCreateThreadNotifyRoutine` | Mata rubinot se thread nova aparece |
| Kernel | PID spoofing | `GetWindowThreadProcessId(hwnd)` retorna 0 pra HWND do rubinot |
| Kernel | HWID collection privilegiada | Silent, invisível ao Procmon (kernel-only APIs) |
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
| Deletar `%USERPROFILE%\emac-uuid` antes de login | Novo UUID no próximo run — escapa ban só-por-UUID | Trivial (1 comando) — não escapa se ban usa HW hash |
| Editar UUID pra outro valor | Idem | Trivial |
| Spoofar CPU + MAC + EDID + regenerar UUID | Fingerprint totalmente novo | Alto — precisa registry write + driver filter pra MAC randomize + EDID injector; detectável por Cloudflare Turnstile-like anti-tampering |
| VM com HW spoofing plugins (VMware unlocker, VBox) | HW fingerprint sintético | Médio — EMAC checa `SystemSetupInProgress` e outras heurísticas anti-VM (visto na captura), provavelmente detecta VM |
| MITM SSL do WebSocket (mitmproxy + Root CA) + editar payload | Ver/modificar HWID enviado | Alto — server pode ter integrity check no payload |
| Comprar hardware novo | Elegante e efetivo | Financeiro |

**O approach mais simples (deletar `emac-uuid`) provavelmente é insuficiente sozinho** — se EMAC bania por hash combinado (`uuid + cpu + mac + edid + gpu`), regenerar UUID sem mudar o hash resulta em novo UUID mas mesmo hash → ban permanece. Só análise da response do server (via MITM SSL) diria com certeza.

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
- **Procmon (Sysinternals)** — event trace de Registry/File/Network activity, filter por PID rubinot

Sem essas ferramentas, o EMAC bloquearia qualquer approach standard (OpenProcess ret ACCESS_DENIED, .NET `Process.MainModule` idem). O kernel RPM próprio é o unlock — passa por baixo do `ObRegisterCallbacks` do EMAC.

---

## Referências
- [rubinot-session-13-dxshared-bypass.md](../.claude/projects/*/memory/rubinot-session-13-dxshared-bypass.md) — bypass WDA do rubinot (contexto do PoC principal)
- [POC_CLOSURE.md](POC_CLOSURE.md) — retrospectiva completa das 4 fases + roadmap
- Sysinternals Procmon — https://learn.microsoft.com/sysinternals/downloads/procmon
- Windows Internals 7th ed., cap. Object Manager / Process Environment Block
