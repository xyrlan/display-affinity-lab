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
    PVOID   LoadLibraryAddr;
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

// Marca um processo como watched — aloca buffer no espaco dele com o path da
// DLL do `watch`. Retorna true se marcou com sucesso.
bool markProcessWatched(HANDLE pid, PEPROCESS process, WatchEntry* watch) {
    PVOID remoteBuf = nullptr;
    NTSTATUS s = affctl::AllocRemotePathBuffer(
        process, watch->DllPath, watch->DllPathBytes, &remoteBuf);
    if (!NT_SUCCESS(s) || remoteBuf == nullptr) return false;

    // Encontra slot livre (nao precisa de LRU aqui — se cheio, desistimos).
    for (int i = 0; i < kMaxWatchedProcs; ++i) {
        if (!g_watched[i].Active) {
            g_watched[i].Pid       = pid;
            g_watched[i].Watch     = watch;
            g_watched[i].RemoteBuf = remoteBuf;
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

    // Snapshot rapido do watch (tira dependencia do mutex por thread).
    PVOID loadLib  = nullptr;
    PVOID remote   = nullptr;
    ExAcquireFastMutex(&g_watchMutex);
    WatchedProc* wp = findWatchedByPid(ProcessId);
    if (wp && wp->Watch) {
        loadLib = wp->Watch->LoadLibraryAddr;
        remote  = wp->RemoteBuf;
    }
    ExReleaseFastMutex(&g_watchMutex);

    if (!loadLib || !remote) return;

    PETHREAD thread = nullptr;
    if (!NT_SUCCESS(PsLookupThreadByThreadId(ThreadId, &thread))) return;
    // ownerProcess = nullptr: o buffer `remote` e COMPARTILHADO entre todas as
    // APCs criadas para este processo (uma por thread nova). Se uma APC individual
    // liberasse o buffer, quebraria as proximas. A cleanup fica implicita:
    // buffer some com o VA space do processo alvo quando ele morre, e o slot
    // em g_watched e limpo em UpdateWatchedListForExit.
    affctl::QueueLoadLibraryApc(thread, loadLib, remote, /*ownerProcess=*/nullptr);
    ObDereferenceObject(thread);
}

// --- Helpers de atualizacao ---
// Cada um pega um unico mutex, roda sob __try/__except e libera. Nunca cruza
// mutexes. Isso torna impossivel um "release-sem-acquire" numa saida por
// excecao — o corpo do try roda entre acquire e release, e o handler nao toca
// no mutex.

// Registra o novo processo em g_table e copia o basename + parentPid para o
// caller consumir no proximo passo (g_watchMutex). Retorna true se ha match a
// fazer na watch list.
static bool UpdateTargetTableForCreate(
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo,
    WCHAR (*outNameCopy)[128],
    HANDLE* outParentPid)
{
    bool wantsWatchLookup = false;
    ExAcquireFastMutex(&g_mutex);
    __try {
        if (CreateInfo->ImageFileName == nullptr ||
            CreateInfo->ImageFileName->Length == 0) {
            __leave;
        }

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
        extractBasename(CreateInfo->ImageFileName,
                        g_table[slot].ImageName,
                        RTL_NUMBER_OF(g_table[slot].ImageName));
        g_table[slot].ProcessId = ProcessId;
        g_table[slot].Sequence  = InterlockedIncrement64(&g_sequence);
        g_table[slot].Active    = TRUE;

        // Snapshot pra passar sem lock pro helper do watchMutex.
        RtlCopyMemory(*outNameCopy, g_table[slot].ImageName, sizeof(*outNameCopy));
        *outParentPid    = CreateInfo->ParentProcessId;
        wantsWatchLookup = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Silencioso — nao deixa uma tabela intermediaria assinar BSOD.
    }
    ExReleaseFastMutex(&g_mutex);
    return wantsWatchLookup;
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

// Consulta watch list: match direto por nome ou heranca (pai ja marcado).
// Se casar, aloca remoteBuf no espaco do alvo e insere em g_watched.
static void UpdateWatchedListForCreate(
    HANDLE     ProcessId,
    PEPROCESS  Process,
    PCWSTR     nameCopy,
    HANDLE     parentPid)
{
    ExAcquireFastMutex(&g_watchMutex);
    __try {
        WatchEntry* w = findWatchByName(nameCopy);
        if (!w && parentPid) {
            // Match por heranca: pai esta na watched list?
            WatchedProc* parentWp = findWatchedByPid(parentPid);
            if (parentWp) w = parentWp->Watch;
        }
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
    // Orquestracao pura: cada helper adquire seu proprio mutex.
    // Ordem: sempre g_mutex antes de g_watchMutex (evita deadlock cruzado).
    if (CreateInfo != nullptr) {
        WCHAR  nameCopy[128] = {0};
        HANDLE parentPid     = nullptr;
        if (UpdateTargetTableForCreate(ProcessId, CreateInfo, &nameCopy, &parentPid)) {
            UpdateWatchedListForCreate(ProcessId, Process, nameCopy, parentPid);
        }
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

NTSTATUS AddWatch(PCWSTR imageName, PCWSTR dllPath, ULONG dllPathBytes, PVOID loadLibraryAddr) {
    if (!imageName || !*imageName || !dllPath || !dllPathBytes || !loadLibraryAddr) {
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
        g_watches[slot].DllPathBytes    = dllPathBytes;
        g_watches[slot].LoadLibraryAddr = loadLibraryAddr;
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
