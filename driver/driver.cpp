// driver.cpp
// affctl.sys — DriverEntry, dispatch de IOCTL e Unload.
// As rotinas de entrada exigidas pelo kernel usam extern "C" (ABI C);
// a logica interna (tagwnd.cpp) e C++.
//
// Hardening de acesso:
//   - Device criado via IoCreateDeviceSecure com SDDL_DEVOBJ_SYS_ALL_ADM_ALL.
//     Somente processos rodando como SYSTEM ou Administrator podem abrir
//     handle para \\.\AffCtl. Usuarios comuns recebem ACCESS_DENIED no
//     CreateFileW — o driver NAO pode ser abusado por processos de baixo
//     privilegio (mitigacao BYOVD).
//   - IOCTLs de diagnostico (READ_RANGE, AFF_DIAG) so existem em builds
//     Debug (definida AFFCTL_DIAG_IOCTLS pelo vcxproj). Em Release, o
//     dispatch retorna STATUS_INVALID_DEVICE_REQUEST — remove info-leak
//     de estruturas kernel adjacentes.
#include <initguid.h>   // permite alocar storage do GUID de classe abaixo
#include <ntddk.h>
#include <wdmsec.h>     // IoCreateDeviceSecure, SDDL_DEVOBJ_*
#include "tagwnd.h"
#include "inject.h"
#include "process_notify.h"
#include "rpm.h"
#include "scan.h"
#include "../shared/affctl_shared.h"

// GUID de classe do device (privado deste driver). Nao esta associado a nenhum
// setup class publico da MSFT — e apenas o argumento DeviceClassGuid exigido
// por IoCreateDeviceSecure para agrupar objetos criados por este driver.
DEFINE_GUID(GUID_DEVCLASS_AFFCTL,
    0xA1B2C3D5, 0x0002, 0x4A11, 0x9E, 0x22, 0xAF, 0xF0, 0xDA, 0x77, 0x10, 0x02);

// Offset da flag DisplayAffinity na tagWND, descoberto pelo app (heuristica) e
// enviado via IOCTL_SET_OFFSET. 0xFFFFFFFF = ainda nao configurado.
static ULONG g_offset = 0xFFFFFFFF;
// Mascara dos bits, dentro do byte em g_offset, que representam a afinidade.
// 0xFF = byte inteiro (Win10 e mais antigos); 0x01 e outras em Win11 25H2+.
static UCHAR g_clearMask = 0xFF;

static PDEVICE_OBJECT g_deviceObject = nullptr;

extern "C" {

DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD AffCtlUnload;
static DRIVER_DISPATCH AffCtlCreateClose;
static DRIVER_DISPATCH AffCtlDeviceControl;

// CREATE/CLOSE: sucesso trivial (o app abre/fecha o device).
static NTSTATUS AffCtlCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Helpers de validacao de tamanho de buffer no dispatch METHOD_BUFFERED.
static bool InputAtLeast(PIO_STACK_LOCATION s, ULONG n) {
    return s->Parameters.DeviceIoControl.InputBufferLength >= n;
}
static bool OutputAtLeast(PIO_STACK_LOCATION s, ULONG n) {
    return s->Parameters.DeviceIoControl.OutputBufferLength >= n;
}

// Le HKLM\SYSTEM\CurrentControlSet\Services\<service>\Parameters\{Offset,ClearMask}
// (DWORDs) e popula g_offset/g_clearMask. Silencioso se a subkey ou os valores
// nao existirem — o app pode enviar IOCTL_SET_OFFSET a qualquer momento pra
// setar manualmente. Isso permite ao affapp Release pular o discovery: uma vez
// que a build Debug persistiu o offset via Registry, todo boot subsequente ja
// carrega o driver pronto pra IOCTL_CLEAR_AFFINITY / IOCTL_READ_AFFINITY.
static void LoadPersistedOffset(PUNICODE_STRING servicePath) {
    // Constroi "<servicePath>\Parameters" num buffer local.
    WCHAR paramsBuf[512];
    UNICODE_STRING paramsPath;
    paramsPath.Buffer        = paramsBuf;
    paramsPath.Length        = 0;
    paramsPath.MaximumLength = sizeof(paramsBuf);
    if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&paramsPath, servicePath))) {
        return;
    }
    UNICODE_STRING suffix;
    RtlInitUnicodeString(&suffix, L"\\Parameters");
    if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&paramsPath, &suffix))) {
        return;
    }

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(
        &oa, &paramsPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        nullptr, nullptr);
    HANDLE hKey = nullptr;
    NTSTATUS s = ZwOpenKey(&hKey, KEY_READ, &oa);
    if (!NT_SUCCESS(s)) {
        // Subkey ausente = primeiro boot pos-instalacao, sem discovery previo.
        return;
    }

    // Buffer estatico para KeyValuePartialInformation + 1 DWORD de payload.
    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];

    auto readDword = [&](PCWSTR valueName, ULONG* outValue) -> bool {
        UNICODE_STRING vname;
        RtlInitUnicodeString(&vname, valueName);
        ULONG needed = 0;
        NTSTATUS r = ZwQueryValueKey(
            hKey, &vname, KeyValuePartialInformation,
            buf, sizeof(buf), &needed);
        if (!NT_SUCCESS(r)) return false;
        auto* kvp = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buf);
        if (kvp->Type != REG_DWORD || kvp->DataLength != sizeof(ULONG)) return false;
        *outValue = *reinterpret_cast<PULONG>(kvp->Data);
        return true;
    };

    ULONG offset = 0, mask = 0;
    bool haveOffset = readDword(L"Offset",    &offset);
    bool haveMask   = readDword(L"ClearMask", &mask);
    ZwClose(hKey);

    if (haveOffset && offset < AFFCTL_MAX_RANGE) {
        g_offset    = offset;
        // ClearMask e opcional — mask=0 (byte inteiro) equivale a 0xFF.
        g_clearMask = (haveMask && mask) ? static_cast<UCHAR>(mask) : 0xFF;
    }
}

static NTSTATUS AffCtlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    // METHOD_BUFFERED: input e output compartilham SystemBuffer.
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0; // bytes escritos no output

    switch (code) {

#ifdef AFFCTL_DIAG_IOCTLS
    // DIAG (Debug-only): dump cru da tagWND pro user descobrir offset da flag
    // DisplayAffinity. Compilado fora em Release — nao serve como primitiva
    // de info-leak de estruturas kernel adjacentes.
    case IOCTL_READ_RANGE: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(READ_RANGE_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        READ_RANGE_INPUT in = *reinterpret_cast<PREAD_RANGE_INPUT>(buffer);
        ULONG count = in.Count;
        if (count == 0 || count > AFFCTL_MAX_RANGE) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!OutputAtLeast(stack, count)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        // Output vai para o proprio SystemBuffer.
        status = affctl::ReadTagWndRange((ULONG_PTR)in.Hwnd, buffer, count);
        if (NT_SUCCESS(status)) {
            info = count;
        }
        break;
    }
#endif // AFFCTL_DIAG_IOCTLS

    case IOCTL_RESOLVE_PID_BY_NAME: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(RESOLVE_PID_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!OutputAtLeast(stack, sizeof(RESOLVE_PID_OUTPUT))) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        auto rin = reinterpret_cast<PRESOLVE_PID_INPUT>(buffer);
        const ULONG maxBytes =
            (ULONG)(sizeof(rin->ImageName) - sizeof(wchar_t));
        if (rin->ImageNameLen == 0 || rin->ImageNameLen > maxBytes ||
            (rin->ImageNameLen % sizeof(wchar_t)) != 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        // Copia local + NUL termina (input user pode nao vir terminado).
        wchar_t nameLocal[AFFCTL_MAX_IMAGE_NAME];
        ULONG chars = rin->ImageNameLen / sizeof(wchar_t);
        RtlCopyMemory(nameLocal, rin->ImageName, chars * sizeof(wchar_t));
        nameLocal[chars] = L'\0';

        HANDLE pid = affctl::ResolvePidByName(nameLocal);
        auto out = reinterpret_cast<PRESOLVE_PID_OUTPUT>(buffer);
        out->Pid = (unsigned long long)(ULONG_PTR)pid;
        info = sizeof(RESOLVE_PID_OUTPUT);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_WATCH_NAME: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(WATCH_NAME_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        auto win = reinterpret_cast<PWATCH_NAME_INPUT>(buffer);
        const ULONG maxNameBytes = (ULONG)(sizeof(win->ImageName) - sizeof(wchar_t));
        const ULONG maxPathBytes = (ULONG)(sizeof(win->DllPath)   - sizeof(wchar_t));
        if (win->ImageNameLen == 0 || win->ImageNameLen > maxNameBytes ||
            (win->ImageNameLen % sizeof(wchar_t)) != 0 ||
            win->DllPathLen == 0   || win->DllPathLen   > maxPathBytes ||
            (win->DllPathLen % sizeof(wchar_t)) != 0 ||
            win->LdrLoadDllAddr == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        wchar_t name[AFFCTL_MAX_IMAGE_NAME];
        ULONG nameChars = win->ImageNameLen / sizeof(wchar_t);
        RtlCopyMemory(name, win->ImageName, nameChars * sizeof(wchar_t));
        name[nameChars] = L'\0';
        win->DllPath[win->DllPathLen / sizeof(wchar_t)] = L'\0';
        status = affctl::AddWatch(
            name, win->DllPath, win->DllPathLen,
            (PVOID)(ULONG_PTR)win->LdrLoadDllAddr);
        break;
    }

    case IOCTL_UNWATCH_NAME: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(UNWATCH_NAME_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        auto uin = reinterpret_cast<PUNWATCH_NAME_INPUT>(buffer);
        const ULONG maxNameBytes = (ULONG)(sizeof(uin->ImageName) - sizeof(wchar_t));
        if (uin->ImageNameLen == 0 || uin->ImageNameLen > maxNameBytes ||
            (uin->ImageNameLen % sizeof(wchar_t)) != 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        wchar_t name[AFFCTL_MAX_IMAGE_NAME];
        ULONG nameChars = uin->ImageNameLen / sizeof(wchar_t);
        RtlCopyMemory(name, uin->ImageName, nameChars * sizeof(wchar_t));
        name[nameChars] = L'\0';
        status = affctl::RemoveWatch(name);
        break;
    }

    case IOCTL_INJECT_DLL: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(INJECT_DLL_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        auto in = reinterpret_cast<PINJECT_DLL_INPUT>(buffer);
        // Valida path length dentro dos limites do buffer estatico.
        const ULONG maxBytes =
            (ULONG)(sizeof(in->DllPath) - sizeof(wchar_t)); // deixa espaco pro NUL
        if (in->DllPathLen == 0 || in->DllPathLen > maxBytes) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = affctl::InjectDll(
            (HANDLE)(ULONG_PTR)in->TargetPid,
            (HANDLE)(ULONG_PTR)in->TargetTid,
            (PVOID)(ULONG_PTR)in->LdrLoadDllAddr,
            in->DllPath,
            (SIZE_T)in->DllPathLen);
        break;
    }

    case IOCTL_SCAN_MEMORY: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(SCAN_MEMORY_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!OutputAtLeast(stack, sizeof(SCAN_MEMORY_OUTPUT))) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        // Copia local do input pra nao ler do SystemBuffer enquanto o driver
        // sobrescreve com output (METHOD_BUFFERED: input e output compartilham buffer).
        SCAN_MEMORY_INPUT in = *reinterpret_cast<PSCAN_MEMORY_INPUT>(buffer);
        if (in.Pid == 0 || in.Size == 0 || in.PatternLen == 0 ||
            in.PatternLen > AFFCTL_SCAN_MAX_PATTERN ||
            in.MaxHits == 0 || in.MaxHits > AFFCTL_SCAN_MAX_HITS ||
            in.Size > AFFCTL_SCAN_MAX_CHUNK) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        // Zerar output no SystemBuffer antes de passar pro scan (que preenche).
        auto out = reinterpret_cast<PSCAN_MEMORY_OUTPUT>(buffer);
        RtlZeroMemory(out, sizeof(SCAN_MEMORY_OUTPUT));
        status = affctl::ScanMemoryKernel(
            Irp,                                        // pra cancellation check
            (HANDLE)(ULONG_PTR)in.Pid,
            (ULONG_PTR)in.StartVa,
            (ULONG_PTR)in.Size,
            in.Pattern, in.Mask, in.PatternLen,
            in.MaxHits,
            out);
        if (NT_SUCCESS(status)) {
            info = sizeof(SCAN_MEMORY_OUTPUT);
        }
        // STATUS_CANCELLED e reportado pro caller — nao e erro do IOCTL, e
        // sinal que user pediu pra parar. Info=0 (sem output valido).
        break;
    }

    case IOCTL_GET_PROCESS_PEB: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(GET_PEB_INPUT))) {
            status = STATUS_INVALID_PARAMETER; break;
        }
        if (!OutputAtLeast(stack, sizeof(GET_PEB_OUTPUT))) {
            status = STATUS_BUFFER_TOO_SMALL; break;
        }
        GET_PEB_INPUT in = *reinterpret_cast<PGET_PEB_INPUT>(buffer);
        if (in.Pid == 0) { status = STATUS_INVALID_PARAMETER; break; }
        ULONG_PTR peb = 0;
        status = affctl::GetProcessPeb((HANDLE)(ULONG_PTR)in.Pid, &peb);
        if (NT_SUCCESS(status)) {
            auto out = reinterpret_cast<PGET_PEB_OUTPUT>(buffer);
            out->Peb = (unsigned long long)peb;
            info = sizeof(GET_PEB_OUTPUT);
        }
        break;
    }

    case IOCTL_GET_PROCESS_BASE: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(GET_PROCESS_BASE_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!OutputAtLeast(stack, sizeof(GET_PROCESS_BASE_OUTPUT))) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        GET_PROCESS_BASE_INPUT in = *reinterpret_cast<PGET_PROCESS_BASE_INPUT>(buffer);
        if (in.Pid == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        ULONG_PTR imageBase = 0;
        status = affctl::GetProcessImageBase((HANDLE)(ULONG_PTR)in.Pid, &imageBase);
        if (NT_SUCCESS(status)) {
            auto out = reinterpret_cast<PGET_PROCESS_BASE_OUTPUT>(buffer);
            out->ImageBase = (unsigned long long)imageBase;
            info = sizeof(GET_PROCESS_BASE_OUTPUT);
        }
        break;
    }

    case IOCTL_READ_PROCESS_MEMORY: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(RPM_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        RPM_INPUT in = *reinterpret_cast<PRPM_INPUT>(buffer); // copia antes de sobrescrever
        if (in.Pid == 0 || in.Size == 0 || in.Size > AFFCTL_RPM_MAX) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!OutputAtLeast(stack, in.Size)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        // METHOD_BUFFERED: SystemBuffer serve tanto pra input quanto output.
        // Copia local do input ja feita acima; podemos escrever direto no buffer.
        status = affctl::ReadProcessMemoryKernel(
            (HANDLE)(ULONG_PTR)in.Pid,
            (ULONG_PTR)in.Address,
            in.Size,
            buffer);
        if (NT_SUCCESS(status)) {
            info = in.Size;
        }
        break;
    }

    case IOCTL_SET_VALIDATE_HWND: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(SET_VALIDATE_HWND_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        SET_VALIDATE_HWND_INPUT in = *reinterpret_cast<PSET_VALIDATE_HWND_INPUT>(buffer);
        status = affctl::SetValidateHwndAddress(reinterpret_cast<PVOID>(in.Address));
        break;
    }

#ifdef AFFCTL_DIAG_IOCTLS
    // DIAG (Debug-only): dumpa gSharedInfo/HANDLEENTRY/phead-candidates.
    // Compilado fora em Release para nao vazar layout de estruturas internas.
    case IOCTL_AFF_DIAG: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(HWND_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!OutputAtLeast(stack, sizeof(AFF_DIAG_OUTPUT))) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        HWND_INPUT in = *reinterpret_cast<PHWND_INPUT>(buffer); // copia antes de sobrescrever
        status = affctl::Diag((ULONG_PTR)in.Hwnd, buffer);
        if (NT_SUCCESS(status)) {
            info = sizeof(AFF_DIAG_OUTPUT);
        }
        break;
    }
#endif // AFFCTL_DIAG_IOCTLS

    case IOCTL_SET_GSHAREDINFO_ADDR: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(SET_GSHAREDINFO_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        SET_GSHAREDINFO_INPUT in = *reinterpret_cast<PSET_GSHAREDINFO_INPUT>(buffer);
        status = affctl::SetSharedInfoAddress(reinterpret_cast<PVOID>(in.Address));
        break;
    }

    case IOCTL_SET_OFFSET: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(SET_OFFSET_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        SET_OFFSET_INPUT in = *reinterpret_cast<PSET_OFFSET_INPUT>(buffer);
        if (in.Offset >= AFFCTL_MAX_RANGE) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        g_offset    = in.Offset;
        g_clearMask = in.ClearMask ? in.ClearMask : 0xFF; // seguranca contra 0
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_CLEAR_AFFINITY: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(HWND_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (g_offset == 0xFFFFFFFF) {
            status = STATUS_INVALID_DEVICE_STATE; // offset nao configurado ainda
            break;
        }
        HWND_INPUT in = *reinterpret_cast<PHWND_INPUT>(buffer);
        status = affctl::ClearFlag((ULONG_PTR)in.Hwnd, g_offset, g_clearMask);
        break;
    }

    case IOCTL_READ_AFFINITY: {
        if (buffer == nullptr || !InputAtLeast(stack, sizeof(HWND_INPUT))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (!OutputAtLeast(stack, sizeof(READ_AFFINITY_OUTPUT))) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (g_offset == 0xFFFFFFFF) {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }
        HWND_INPUT in = *reinterpret_cast<PHWND_INPUT>(buffer);
        unsigned char value = 0;
        status = affctl::ReadFlag((ULONG_PTR)in.Hwnd, g_offset, &value);
        if (NT_SUCCESS(status)) {
            auto out = reinterpret_cast<PREAD_AFFINITY_OUTPUT>(buffer);
            // Retorna somente os bits da afinidade — app le "0 = sem afinidade,
            // != 0 = ativa" independente do encoding (byte inteiro ou bit-flag).
            out->Value = value & g_clearMask;
            info = sizeof(READ_AFFINITY_OUTPUT);
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static void AffCtlUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    // Desregistra callback ANTES de deletar device — evita callback pending
    // ficar apontando pra codigo que ja saiu (BSOD garantido).
    affctl::ProcessNotifyCleanup();

    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, AFFCTL_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);
    if (g_deviceObject != nullptr) {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = nullptr;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, AFFCTL_DEVICE_NAME);

    // SDDL_DEVOBJ_SYS_ALL_ADM_ALL:
    //   SYSTEM = GENERIC_ALL, Administrators = GENERIC_ALL,
    //   todos os demais = negado (a SDDL nao lista ninguem mais). Bloqueia a
    //   superficie de abuso BYOVD: usuarios comuns nao conseguem abrir handle
    //   pra enviar IOCTL_INJECT_DLL ou ler memoria kernel.
    //
    // Nota: as constantes SDDL_DEVOBJ_* em wdmsec.h sao declaradas via
    // DECLARE_CONST_UNICODE_STRING — ja sao UNICODE_STRING prontas, passa-se
    // o endereco direto (nao precisa de RtlInitUnicodeString).
    NTSTATUS status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
        (LPCGUID)&GUID_DEVCLASS_AFFCTL,
        &g_deviceObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, AFFCTL_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlink, &devName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = nullptr;
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = AffCtlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = AffCtlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AffCtlDeviceControl;
    DriverObject->DriverUnload                         = AffCtlUnload;

    // Registra callback de criacao/finalizacao de processos. Popula a tabela
    // consultada por IOCTL_RESOLVE_PID_BY_NAME. Exige /INTEGRITYCHECK linkado.
    NTSTATUS pnStatus = affctl::ProcessNotifyInit();
    if (!NT_SUCCESS(pnStatus)) {
        IoDeleteSymbolicLink(&symlink);
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = nullptr;
        return pnStatus;
    }

    // gSharedInfo e configurada pelo app via IOCTL_SET_GSHAREDINFO_ADDR
    // (endereco resolvido no user-mode pelo PDB). Aqui apenas carregamos.

    // Carrega offset/mask persistidos pelo affapp (Debug) na descoberta
    // anterior. Silencioso se ausentes — o app pode chamar IOCTL_SET_OFFSET.
    LoadPersistedOffset(RegistryPath);

    return STATUS_SUCCESS;
}

} // extern "C"
