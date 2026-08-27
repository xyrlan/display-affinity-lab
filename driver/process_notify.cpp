// process_notify.cpp
// Implementacao: tabela circular pequena + callback + resolver por nome.
//
// Cuidados de kernel:
//   - Callback roda em PASSIVE_LEVEL (docs: process notify sempre PASSIVE).
//   - Toda escrita/leitura da tabela esta sob FAST_MUTEX (compativel com PASSIVE).
//   - Comparacao de nomes: implementacao ASCII case-insensitive (basenames de
//     PE sao ASCII na pratica). Evita depender de _wcsicmp cross-runtime.
//   - Callback protegido por __try/__except — nunca causa BSOD, mesmo se o
//     ImageFileName do CreateInfo vier malformado.
//   - Cada helper adquire/libera seu proprio mutex dentro de um __try/__except
//     independente. Isso elimina a armadilha de "release-sem-acquire" que
//     existia quando um unico bloco fazia release(A) -> acquire(B) ...
//     release(B) -> re-acquire(A): uma excecao entre as duas fases deixava o
//     handler tentando liberar A sem tê-lo. Agora cada mutex tem escopo linear
//     e o padrao acquire -> __try -> release nunca solta um lock nao-adquirido.
//
// Anti-PPID-spoofing (herança por creator real):
//   PS_CREATE_NOTIFY_INFO->ParentProcessId reflete o pai declarado — que pode
//   ser spoofado via UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_
//   PROCESS). Um alvo malicioso poderia sair da arvore de watched aparentando
//   ter outro pai. Contra isso, o callback captura PsGetCurrentProcessId()
//   ANTES de qualquer trabalho — este e o PID real da thread que fez a
//   syscall NtCreateUserProcess, vem do kernel e nao pode ser spoofado por
//   user-mode. UpdateWatchedListForCreate faz match tanto por parentPid
//   quanto por creatingPid: para escapar da watchlist o attacker teria que
//   spoofar ambos, o que a API do Windows nao permite.
//
// Anti-image-spoofing (cross-check do basename via dupla fonte kernel):
//   Um rootkit ring 0 poderia manipular EPROCESS.ImageFileName ou o
//   ImageFileName do CreateInfo para se passar por outro processo. Contra
//   isso, ResolveTrustedBasename cross-checa duas fontes independentes:
//     (A) CreateInfo->ImageFileName — path passado pelo kernel init flow
//     (B) SeLocateProcessImageName(Process) — path via EPROCESS/SeAudit info
//   Se divergem, DKOM detectado (log em DBG) e a decisao de watch usa a
//   fonte (B), historicamente mais dificil de spoofar sem tocar em varias
//   estruturas EPROCESS + SectionObject. Nao e defesa perfeita contra
//   rootkit sofisticado que altere ambas — mas eleva o custo do ataque.
#include <ntifs.h>
#include "process_notify.h"
#include "inject.h"

namespace {

constexpr int kMaxTargets = 64;

struct TargetEntry {
    WCHAR   ImageName[128]; // basename (ex: "afftarget.exe")
    HANDLE  ProcessId;
    ULONG64 Sequence;       // ordem de criacao, pra escolher "mais recente"
    BOOLEAN Active;
};

TargetEntry     g_table[kMaxTargets];
FAST_MUTEX      g_mutex;
volatile LONG64 g_sequence  = 0;
bool            g_registered = false;

// ---------- Watch list (feature 1: tree injection + auto-inject) ----------
constexpr int kMaxWatches = 8;
constexpr int kMaxWatchedProcs = 128;

struct WatchEntry {
    WCHAR   ImageName[128];
    WCHAR   DllPath[520];
    ULONG   DllPathBytes;
    PVOID   LdrLoadDllAddr; // ntdll!LdrLoadDll no alvo (mesmo VA em toda sessao)
    BOOLEAN Active;
};

// Um processo "watched" e um alvo ja marcado (por match direto de nome ou por
// heranca de pai marcado). Guardamos o buffer remoto alocado com o path da DLL
// pra reusar em cada nova thread do processo (bug: LoadLibraryW so precisa 1x,
// mas nao ha custo).
struct WatchedProc {
    HANDLE      Pid;
    WatchEntry* Watch;
    PVOID       RemoteBuf; // buffer no espaco do processo alvo com o path
    BOOLEAN     Active;
};

WatchEntry  g_watches[kMaxWatches];
WatchedProc g_watched[kMaxWatchedProcs];
FAST_MUTEX  g_watchMutex;
bool        g_threadCbRegistered = false;

// Comparacao ASCII case-insensitive (basenames de EXE sao ASCII na pratica).
// Evita dependencia de _wcsicmp que nao esta garantida no runtime kernel.
bool wcsIEqualAscii(PCWSTR a, PCWSTR b) {
    for (;;) {
        WCHAR ca = *a, cb = *b;
        if (ca >= L'A' && ca <= L'Z') ca = (WCHAR)(ca + 32);
        if (cb >= L'A' && cb <= L'Z') cb = (WCHAR)(cb + 32);
        if (ca != cb) return false;
        if (ca == 0)  return true;
        ++a; ++b;
    }
}

// Extrai basename do NT path (ex: "\Device\HarddiskVolume2\...\foo.exe" -> "foo.exe").
void extractBasename(const UNICODE_STRING* full, WCHAR* out, size_t outCharCount) {
    USHORT chars = (USHORT)(full->Length / sizeof(WCHAR));
    USHORT lastSlash = 0;
    for (USHORT i = 0; i < chars; ++i) {
        if (full->Buffer[i] == L'\\') lastSlash = (USHORT)(i + 1);
    }
    USHORT copyChars = (USHORT)(chars - lastSlash);
    if (copyChars >= outCharCount) copyChars = (USHORT)(outCharCount - 1);
    RtlCopyMemory(out, &full->Buffer[lastSlash], copyChars * sizeof(WCHAR));
    out[copyChars] = L'\0';
}

// Cross-check kernel de duas fontes independentes para o basename real do
// processo em criacao. Ver "anti-image-spoofing" no cabecalho do arquivo.
//
// Fonte A (barata): CreateInfo->ImageFileName — path passado no init.
// Fonte B (independente): SeLocateProcessImageName(Process) — path via
//   EPROCESS.SeAuditProcessCreationInfo. Buffer alocado pelo Windows, deve ser
//   liberado com ExFreePool.
//
// Retorna true se conseguiu ao menos uma fonte; grava no `outName`. Prefere
// a fonte B (SectionObject-based) por ser mais dificil de spoofar isoladamente.
// Se as fontes A e B divergem no basename, loga em DBG — sinal de que algo
// ring-0 alterou uma das duas.
static bool ResolveTrustedBasename(
    PEPROCESS              Process,
    PPS_CREATE_NOTIFY_INFO CreateInfo,
    WCHAR                  (*outName)[128])
{
    WCHAR fromInfo[128]   = {0};
    WCHAR fromKernel[128] = {0};
    bool  haveInfo   = false;
    bool  haveKernel = false;

    // Fonte A: CreateInfo->ImageFileName.
    if (CreateInfo && CreateInfo->ImageFileName &&
        CreateInfo->ImageFileName->Length > 0) {
        extractBasename(CreateInfo->ImageFileName,
                        fromInfo, RTL_NUMBER_OF(fromInfo));
        haveInfo = true;
    }

    // Fonte B: SeLocateProcessImageName. Vai a EPROCESS.SeAudit... — path que
    // o attacker precisaria alterar independentemente da estrutura consultada
    // pela fonte A.
    PUNICODE_STRING kernelImg = nullptr;
    __try {
        NTSTATUS s = SeLocateProcessImageName(Process, &kernelImg);
        if (NT_SUCCESS(s) && kernelImg &&
            kernelImg->Buffer && kernelImg->Length > 0) {
            extractBasename(kernelImg,
                            fromKernel, RTL_NUMBER_OF(fromKernel));
            haveKernel = true;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Nao deveria lancar em PASSIVE, mas garantia extra.
    }
    if (kernelImg) {
        ExFreePool(kernelImg);
    }

    // Cross-check: divergencia = suspeita de DKOM.
    if (haveInfo && haveKernel && !wcsIEqualAscii(fromInfo, fromKernel)) {
#if DBG
        DbgPrint(
            "[affctl] IMAGE spoof detected: CreateInfo='%wS' kernel='%wS' "
            "— trusting kernel source\n",
            fromInfo, fromKernel);
#endif
    }

    // Preferencia: kernel > info (kernel e mais dificil de spoofar isoladamente).
    if (haveKernel) {
        RtlCopyMemory(*outName, fromKernel, sizeof(*outName));
        return true;
    }
    if (haveInfo) {
        RtlCopyMemory(*outName, fromInfo, sizeof(*outName));
        return true;
    }
    return false;
}

// Retorna o watch matching por nome (chamada com g_watchMutex ADQUIRIDO).
WatchEntry* findWatchByName(PCWSTR name) {
    for (int i = 0; i < kMaxWatches; ++i) {
        if (g_watches[i].Active && wcsIEqualAscii(g_watches[i].ImageName, name)) {
            return &g_watches[i];
        }
    }
    return nullptr;
}

// Retorna o WatchedProc de um PID (com g_watchMutex ADQUIRIDO).
WatchedProc* findWatchedByPid(HANDLE pid) {
    for (int i = 0; i < kMaxWatchedProcs; ++i) {
        if (g_watched[i].Active && g_watched[i].Pid == pid) return &g_watched[i];
    }
    return nullptr;
}

// Marca um processo como watched — constroi section com trampolim+path no VA
// dele. Retorna true se marcou com sucesso. remoteBase e reusado por todas as
// APCs criadas em ThreadNotifyCb (uma por thread nova do alvo).
bool markProcessWatched(HANDLE pid, PEPROCESS process, WatchEntry* watch) {
    PVOID remoteBase = nullptr;
    NTSTATUS s = affctl::AllocRemotePathBuffer(
        process, watch->DllPath, watch->DllPathBytes,
        watch->LdrLoadDllAddr, &remoteBase);
    if (!NT_SUCCESS(s) || remoteBase == nullptr) return false;

    // Encontra slot livre (nao precisa de LRU aqui — se cheio, desistimos).
    for (int i = 0; i < kMaxWatchedProcs; ++i) {
        if (!g_watched[i].Active) {
            g_watched[i].Pid       = pid;
            g_watched[i].Watch     = watch;
            g_watched[i].RemoteBuf = remoteBase;
            g_watched[i].Active    = TRUE;
            return true;
        }
    }
    return false; // tabela cheia
}

// Callback de thread create — enfileira APC toda vez que uma thread nasce em
// processo watched. Isso e o coracao da "early injection": a APC dispara nos
// primeiros waits alertable do ntdll, ANTES do EntryPoint do EXE rodar.
VOID ThreadNotifyCb(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (!Create) return;

    // Snapshot rapido do remoteBase (tira dependencia do mutex por thread).
    PVOID remoteBase = nullptr;
    ExAcquireFastMutex(&g_watchMutex);
    WatchedProc* wp = findWatchedByPid(ProcessId);
    if (wp && wp->Watch) {
        remoteBase = wp->RemoteBuf;
    }
    ExReleaseFastMutex(&g_watchMutex);

    if (!remoteBase) return;

    PETHREAD thread = nullptr;
    if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &thread))) return;
    // ownerProcess = nullptr: `remoteBase` e COMPARTILHADO entre todas as APCs
    // criadas para este processo (uma por thread nova). Se uma APC individual
    // desmapeasse a view, quebraria as proximas. A cleanup fica implicita:
    // view some com o VA do processo alvo quando ele morre, e o slot em
    // g_watched e limpo em UpdateWatchedListForExit.
    affctl::QueueLoadLibraryApc(thread, remoteBase, /*ownerProcess=*/nullptr);
    ObDereferenceObject(thread);
}

// --- Helpers de atualizacao ---
// Cada um pega um unico mutex, roda sob __try/__except e libera. Nunca cruza
// mutexes. Isso torna impossivel um "release-sem-acquire" numa saida por
// excecao — o corpo do try roda entre acquire e release, e o handler nao toca
// no mutex.

// Registra o novo processo em g_table usando o basename ja resolvido pelo
// caller (via ResolveTrustedBasename). Nao extrai basename aqui — mantendo
// a fonte-de-verdade unica no orquestrador.
static void UpdateTargetTableForCreate(
    HANDLE ProcessId,
    PCWSTR trustedName)
{
    if (!trustedName || !*trustedName) return;

    ExAcquireFastMutex(&g_mutex);
    __try {
        // Busca slot livre; se nao houver, sobrescreve o mais antigo.
        int slot = -1;
        for (int i = 0; i < kMaxTargets; ++i) {
            if (!g_table[i].Active) { slot = i; break; }
        }
        if (slot < 0) {
            ULONG64 oldest = (ULONG64)-1;
            slot = 0;
            for (int i = 0; i < kMaxTargets; ++i) {
                if (g_table[i].Sequence < oldest) {
                    oldest = g_table[i].Sequence;
                    slot   = i;
                }
            }
        }

        RtlZeroMemory(&g_table[slot], sizeof(TargetEntry));
        // Copia trustedName com clamp no tamanho do buffer.
        SIZE_T maxChars = RTL_NUMBER_OF(g_table[slot].ImageName) - 1;
        SIZE_T chars = 0;
        while (trustedName[chars] && chars < maxChars) ++chars;
        RtlCopyMemory(g_table[slot].ImageName, trustedName, chars * sizeof(WCHAR));
        g_table[slot].ImageName[chars] = L'\0';

        g_table[slot].ProcessId = ProcessId;
        g_table[slot].Sequence  = InterlockedIncrement64(&g_sequence);
        g_table[slot].Active    = TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Silencioso — nao deixa uma tabela intermediaria assinar BSOD.
    }
    ExReleaseFastMutex(&g_mutex);
}

// Marca o processo em g_table como inativo (libera slot).
static void UpdateTargetTableForExit(HANDLE ProcessId)
{
    ExAcquireFastMutex(&g_mutex);
    __try {
        for (int i = 0; i < kMaxTargets; ++i) {
            if (g_table[i].Active && g_table[i].ProcessId == ProcessId) {
                g_table[i].Active = FALSE;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    ExReleaseFastMutex(&g_mutex);
}

// Consulta watch list: match direto por nome ou por heranca (pai declarado ou
// creator real). Se casar, aloca remoteBuf no espaco do alvo e insere em
// g_watched.
//
// Anti-PPID-spoofing:
//   Um processo user-mode pode mentir o pai declarado via
//   UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS). Isso
//   burla acompanhamento baseado em CreateInfo->ParentProcessId. Contra isso
//   olhamos TAMBEM `creatingPid` = PsGetCurrentProcessId() capturado no
//   callback, que e o PID real do processo que fez a syscall
//   NtCreateUserProcess — informacao vinda do kernel, nao do user, imune a
//   spoofing. Bastando qualquer um dos dois (parentPid OU creatingPid) bater
//   com a watchlist, o filho e marcado — o attacker so escaparia se AMBOS
//   fossem spoofados, o que a API do Windows nao permite.
static void UpdateWatchedListForCreate(
    HANDLE     ProcessId,
    PEPROCESS  Process,
    PCWSTR     nameCopy,
    HANDLE     parentPid,
    HANDLE     creatingPid)
{
    ExAcquireFastMutex(&g_watchMutex);
    __try {
        WatchEntry* w = findWatchByName(nameCopy);

        // Heranca por pai DECLARADO.
        WatchedProc* parentWp = (!w && parentPid)
            ? findWatchedByPid(parentPid) : nullptr;
        if (parentWp) w = parentWp->Watch;

        // Heranca por CREATOR REAL (PsGetCurrentProcessId no callback).
        // Se creatingPid != parentPid e este bate na watchlist, e sinal de
        // que o processo esta tentando esconder o pai real via
        // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
        WatchedProc* creatorWp = nullptr;
        if (!w && creatingPid && creatingPid != parentPid) {
            creatorWp = findWatchedByPid(creatingPid);
            if (creatorWp) w = creatorWp->Watch;
        }

#if DBG
        if (creatingPid != parentPid && (parentWp || creatorWp)) {
            DbgPrint(
                "[affctl] PPID spoof detected: declared=%p real-creator=%p "
                "child=%p (%wS) — injecting anyway via real-creator match\n",
                parentPid, creatingPid, ProcessId, nameCopy);
        }
#endif

        if (w) {
            markProcessWatched(ProcessId, Process, w);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    ExReleaseFastMutex(&g_watchMutex);
}

// Libera slot em g_watched (remoteBuf ja foi limpo com o VA space do processo).
static void UpdateWatchedListForExit(HANDLE ProcessId)
{
    ExAcquireFastMutex(&g_watchMutex);
    __try {
        for (int i = 0; i < kMaxWatchedProcs; ++i) {
            if (g_watched[i].Active && g_watched[i].Pid == ProcessId) {
                g_watched[i].Active = FALSE;
                break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    ExReleaseFastMutex(&g_watchMutex);
}

VOID ProcessNotifyCb(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    // [TEMP DEBUG] Print incondicional pra diagnosticar visibility do DebugView.
    // Se este NAO aparece, DbgPrint esta silenciado / DebugView nao esta
    // capturando. Se aparece mas os DbgPrint dentro de #if DBG nao aparecem,
    // a macro DBG nao esta sendo definida pelo WDK em Debug config. REMOVER
    // apos diagnostico.
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[affctl] ProcessNotifyCb: pid=%p create=%d\n",
        ProcessId, (CreateInfo != nullptr) ? 1 : 0);

    // CAPTURA IMEDIATA do creator real via PsGetCurrentProcessId(). Este
    // callback roda sincronamente no contexto da thread que fez a syscall
    // NtCreateUserProcess, entao PsGetCurrentProcessId() retorna o PID do
    // criador de verdade — o valor vem do kernel, nao do user, e nao pode ser
    // spoofado via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS (que so afeta o campo
    // CreateInfo->ParentProcessId reportado). Comparar os dois abaixo permite
    // (a) detectar PPID spoofing e (b) ainda injetar via heranca real quando
    // o attacker tenta esconder o pai.
    HANDLE creatingPid = PsGetCurrentProcessId();

    // Orquestracao pura: cada helper adquire seu proprio mutex.
    // Ordem: sempre g_mutex antes de g_watchMutex (evita deadlock cruzado).
    if (CreateInfo != nullptr) {
        // Cross-check kernel do basename: aumenta o custo de ataque tipo
        // "rootkit muda EPROCESS.ImageFileName para se passar por outro".
        WCHAR trustedName[128] = {0};
        if (!ResolveTrustedBasename(Process, CreateInfo, &trustedName)) {
            // Ambas as fontes falharam — nao ha nome confiavel, skip.
            return;
        }
        HANDLE parentPid = CreateInfo->ParentProcessId;

        UpdateTargetTableForCreate(ProcessId, trustedName);
        UpdateWatchedListForCreate(ProcessId, Process, trustedName, parentPid, creatingPid);
    } else {
        UNREFERENCED_PARAMETER(Process);
        UpdateTargetTableForExit(ProcessId);
        UpdateWatchedListForExit(ProcessId);
    }
}

} // namespace

namespace affctl {

NTSTATUS ProcessNotifyInit() {
    ExInitializeFastMutex(&g_mutex);
    ExInitializeFastMutex(&g_watchMutex);
    RtlZeroMemory(g_table,  sizeof(g_table));
    RtlZeroMemory(g_watches, sizeof(g_watches));
    RtlZeroMemory(g_watched, sizeof(g_watched));

    NTSTATUS s = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCb, FALSE);
    if (!NT_SUCCESS(s)) return s;
    g_registered = true;

    s = PsSetCreateThreadNotifyRoutine(ThreadNotifyCb);
    if (!NT_SUCCESS(s)) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCb, TRUE);
        g_registered = false;
        return s;
    }
    g_threadCbRegistered = true;
    return STATUS_SUCCESS;
}

void ProcessNotifyCleanup() {
    if (g_threadCbRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotifyCb);
        g_threadCbRegistered = false;
    }
    if (g_registered) {
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCb, TRUE);
        g_registered = false;
    }
}

NTSTATUS AddWatch(PCWSTR imageName, PCWSTR dllPath, ULONG dllPathBytes, PVOID ldrLoadDllAddr) {
    if (!imageName || !*imageName || !dllPath || !dllPathBytes || !ldrLoadDllAddr) {
        return STATUS_INVALID_PARAMETER;
    }
    if (dllPathBytes > sizeof(WatchEntry{}.DllPath) - sizeof(WCHAR)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    ExAcquireFastMutex(&g_watchMutex);
    NTSTATUS status = STATUS_INSUFFICIENT_RESOURCES;

    // Reusa slot se ja existe pra esse nome; senao pega o primeiro livre.
    int slot = -1;
    for (int i = 0; i < kMaxWatches; ++i) {
        if (g_watches[i].Active && wcsIEqualAscii(g_watches[i].ImageName, imageName)) {
            slot = i; break;
        }
    }
    if (slot < 0) {
        for (int i = 0; i < kMaxWatches; ++i) {
            if (!g_watches[i].Active) { slot = i; break; }
        }
    }
    if (slot >= 0) {
        RtlZeroMemory(&g_watches[slot], sizeof(WatchEntry));
        // Copia nome + termina NUL
        SIZE_T nameChars = 0;
        while (imageName[nameChars] && nameChars < RTL_NUMBER_OF(g_watches[slot].ImageName) - 1) ++nameChars;
        RtlCopyMemory(g_watches[slot].ImageName, imageName, nameChars * sizeof(WCHAR));
        g_watches[slot].ImageName[nameChars] = L'\0';
        // Copia path
        RtlCopyMemory(g_watches[slot].DllPath, dllPath, dllPathBytes);
        g_watches[slot].DllPath[dllPathBytes / sizeof(WCHAR)] = L'\0';
        g_watches[slot].DllPathBytes   = dllPathBytes;
        g_watches[slot].LdrLoadDllAddr = ldrLoadDllAddr;
        g_watches[slot].Active          = TRUE;
        status = STATUS_SUCCESS;
    }

    ExReleaseFastMutex(&g_watchMutex);
    return status;
}

NTSTATUS RemoveWatch(PCWSTR imageName) {
    if (!imageName || !*imageName) return STATUS_INVALID_PARAMETER;

    ExAcquireFastMutex(&g_watchMutex);
    NTSTATUS status = STATUS_NOT_FOUND;
    for (int i = 0; i < kMaxWatches; ++i) {
        if (g_watches[i].Active && wcsIEqualAscii(g_watches[i].ImageName, imageName)) {
            g_watches[i].Active = FALSE;
            status = STATUS_SUCCESS;
            break;
        }
    }
    // Nao removemos entries em g_watched — processos ja injetados continuam
    // seguindo o hook ate morrerem naturalmente.
    ExReleaseFastMutex(&g_watchMutex);
    return status;
}

HANDLE ResolvePidByName(PCWSTR imageName) {
    if (imageName == nullptr || *imageName == 0) return nullptr;

    HANDLE  result   = nullptr;
    ULONG64 bestSeq  = 0;

    ExAcquireFastMutex(&g_mutex);
    for (int i = 0; i < kMaxTargets; ++i) {
        if (!g_table[i].Active) continue;
        if (wcsIEqualAscii(g_table[i].ImageName, imageName)) {
            if (g_table[i].Sequence > bestSeq) {
                bestSeq = g_table[i].Sequence;
                result  = g_table[i].ProcessId;
            }
        }
    }
    ExReleaseFastMutex(&g_mutex);
    return result;
}

} // namespace affctl
