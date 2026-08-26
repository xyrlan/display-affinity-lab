// driver.cpp
// affctl.sys — DriverEntry, dispatch de IOCTL e Unload.
// As rotinas de entrada exigidas pelo kernel usam extern "C" (ABI C);
// a logica interna (tagwnd.cpp) e C++.
#include <ntddk.h>
#include "tagwnd.h"
#include "../shared/affctl_shared.h"

// Offset da flag DisplayAffinity na tagWND, descoberto pelo app (heuristica) e
// enviado via IOCTL_SET_OFFSET. 0xFFFFFFFF = ainda nao configurado.
static ULONG g_offset = 0xFFFFFFFF;

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

static NTSTATUS AffCtlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    const ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;

    // METHOD_BUFFERED: input e output compartilham SystemBuffer.
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0; // bytes escritos no output

    switch (code) {

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
        g_offset = in.Offset;
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
        status = affctl::ClearFlag((ULONG_PTR)in.Hwnd, g_offset);
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
            out->Value = value;
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
    UNICODE_STRING symlink;
    RtlInitUnicodeString(&symlink, AFFCTL_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlink);
    if (g_deviceObject != nullptr) {
        IoDeleteDevice(g_deviceObject);
        g_deviceObject = nullptr;
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName;
    RtlInitUnicodeString(&devName, AFFCTL_DEVICE_NAME);

    NTSTATUS status = IoCreateDevice(
        DriverObject,
        0,
        &devName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
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

    // gSharedInfo e configurada pelo app via IOCTL_SET_GSHAREDINFO_ADDR
    // (endereco resolvido no user-mode pelo PDB). Aqui apenas carregamos.

    return STATUS_SUCCESS;
}

} // extern "C"
