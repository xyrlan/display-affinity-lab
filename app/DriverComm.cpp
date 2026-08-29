// DriverComm.cpp
#include "DriverComm.hpp"
#include "../shared/affctl_shared.h"
#include <system_error>
#include <stdexcept>

namespace {
[[noreturn]] void throwLastError(const char* what) {
    throw std::system_error(
        static_cast<int>(GetLastError()), std::system_category(), what);
}
} // namespace

DriverComm::DriverComm() {
    m_handle = CreateFileW(
        AFFCTL_USER_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (m_handle == INVALID_HANDLE_VALUE) {
        throwLastError("CreateFileW(\\\\.\\AffCtl) - driver carregado?");
    }
}

DriverComm::~DriverComm() {
    if (m_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_handle);
    }
}

void DriverComm::ioctl(DWORD code,
                       void* in, DWORD inLen,
                       void* out, DWORD outLen,
                       DWORD* bytesReturned) {
    DWORD returned = 0;
    BOOL ok = DeviceIoControl(
        m_handle, code, in, inLen, out, outLen, &returned, nullptr);
    if (!ok) {
        throwLastError("DeviceIoControl");
    }
    if (bytesReturned) {
        *bytesReturned = returned;
    }
}

std::vector<uint8_t> DriverComm::readRange(HWND hwnd, uint32_t count) {
    if (count == 0 || count > AFFCTL_MAX_RANGE) {
        throw std::invalid_argument("readRange: count fora do limite");
    }
    READ_RANGE_INPUT in{};
    in.Hwnd = reinterpret_cast<unsigned long long>(hwnd);
    in.Count = count;

    std::vector<uint8_t> out(count);
    DWORD returned = 0;
    ioctl(IOCTL_READ_RANGE,
          &in, sizeof(in),
          out.data(), static_cast<DWORD>(out.size()),
          &returned);
    out.resize(returned);
    return out;
}

void DriverComm::injectDll(const INJECT_DLL_INPUT& in) {
    // Copia local para tirar o const p/ a assinatura non-const de DeviceIoControl.
    INJECT_DLL_INPUT local = in;
    ioctl(IOCTL_INJECT_DLL, &local, sizeof(local), nullptr, 0, nullptr);
}

void DriverComm::watchName(const wchar_t* imageName,
                           const wchar_t* dllPath,
                           uint64_t       ldrLoadDllAddr) {
    WATCH_NAME_INPUT in{};
    size_t nameChars = wcslen(imageName);
    size_t pathChars = wcslen(dllPath);
    if (nameChars >= AFFCTL_MAX_IMAGE_NAME) {
        throw std::runtime_error("imageName excede AFFCTL_MAX_IMAGE_NAME");
    }
    if (pathChars * sizeof(wchar_t) > sizeof(in.DllPath) - sizeof(wchar_t)) {
        throw std::runtime_error("dllPath excede buffer do IOCTL");
    }
    memcpy(in.ImageName, imageName, nameChars * sizeof(wchar_t));
    memcpy(in.DllPath,   dllPath,   pathChars * sizeof(wchar_t));
    in.ImageNameLen   = static_cast<unsigned long>(nameChars * sizeof(wchar_t));
    in.DllPathLen     = static_cast<unsigned long>(pathChars * sizeof(wchar_t));
    in.LdrLoadDllAddr = ldrLoadDllAddr;
    ioctl(IOCTL_WATCH_NAME, &in, sizeof(in), nullptr, 0, nullptr);
}

void DriverComm::unwatchName(const wchar_t* imageName) {
    UNWATCH_NAME_INPUT in{};
    size_t chars = wcslen(imageName);
    if (chars >= AFFCTL_MAX_IMAGE_NAME) {
        throw std::runtime_error("imageName excede AFFCTL_MAX_IMAGE_NAME");
    }
    memcpy(in.ImageName, imageName, chars * sizeof(wchar_t));
    in.ImageNameLen = static_cast<unsigned long>(chars * sizeof(wchar_t));
    ioctl(IOCTL_UNWATCH_NAME, &in, sizeof(in), nullptr, 0, nullptr);
}

uint32_t DriverComm::resolvePidByName(const wchar_t* imageName) {
    RESOLVE_PID_INPUT  in{};
    RESOLVE_PID_OUTPUT out{};
    size_t chars = wcslen(imageName);
    if (chars >= AFFCTL_MAX_IMAGE_NAME) {
        throw std::runtime_error("imageName excede AFFCTL_MAX_IMAGE_NAME");
    }
    memcpy(in.ImageName, imageName, chars * sizeof(wchar_t));
    in.ImageNameLen = static_cast<unsigned long>(chars * sizeof(wchar_t));
    ioctl(IOCTL_RESOLVE_PID_BY_NAME,
          &in, sizeof(in), &out, sizeof(out), nullptr);
    // PID fits em 32 bits em qualquer Windows atual.
    return static_cast<uint32_t>(out.Pid & 0xFFFFFFFFu);
}

AFF_DIAG_OUTPUT DriverComm::diag(HWND hwnd) {
    HWND_INPUT in{};
    in.Hwnd = reinterpret_cast<unsigned long long>(hwnd);
    AFF_DIAG_OUTPUT out{};
    ioctl(IOCTL_AFF_DIAG,
          &in, sizeof(in),
          &out, sizeof(out),
          nullptr);
    return out;
}

void DriverComm::setSharedInfoAddr(uint64_t addr) {
    SET_GSHAREDINFO_INPUT in{};
    in.Address = addr;
    ioctl(IOCTL_SET_GSHAREDINFO_ADDR, &in, sizeof(in), nullptr, 0, nullptr);
}

void DriverComm::setValidateHwndAddr(uint64_t addr) {
    SET_VALIDATE_HWND_INPUT in{};
    in.Address = addr;
    ioctl(IOCTL_SET_VALIDATE_HWND, &in, sizeof(in), nullptr, 0, nullptr);
}

void DriverComm::setOffset(uint32_t offset, uint8_t clearMask) {
    SET_OFFSET_INPUT in{};
    in.Offset    = offset;
    in.ClearMask = clearMask;
    ioctl(IOCTL_SET_OFFSET, &in, sizeof(in), nullptr, 0, nullptr);
}

void DriverComm::clearAffinity(HWND hwnd) {
    HWND_INPUT in{};
    in.Hwnd = reinterpret_cast<unsigned long long>(hwnd);
    ioctl(IOCTL_CLEAR_AFFINITY, &in, sizeof(in), nullptr, 0, nullptr);
}

uint64_t DriverComm::getProcessImageBase(uint32_t pid) {
    if (pid == 0) throw std::invalid_argument("getProcessImageBase: pid=0");
    GET_PROCESS_BASE_INPUT in{};
    in.Pid = pid;
    GET_PROCESS_BASE_OUTPUT out{};
    ioctl(IOCTL_GET_PROCESS_BASE,
          &in, sizeof(in), &out, sizeof(out), nullptr);
    return out.ImageBase;
}

uint64_t DriverComm::getProcessPeb(uint32_t pid) {
    if (pid == 0) throw std::invalid_argument("getProcessPeb: pid=0");
    GET_PEB_INPUT in{}; in.Pid = pid;
    GET_PEB_OUTPUT out{};
    ioctl(IOCTL_GET_PROCESS_PEB, &in, sizeof(in), &out, sizeof(out), nullptr);
    return out.Peb;
}

SCAN_MEMORY_OUTPUT DriverComm::scanMemory(
    uint32_t pid, uint64_t startVa, uint64_t size,
    const uint8_t* pattern, const uint8_t* mask, uint32_t patternLen,
    uint32_t maxHits)
{
    if (pid == 0 || size == 0 || size > AFFCTL_SCAN_MAX_CHUNK ||
        patternLen == 0 || patternLen > AFFCTL_SCAN_MAX_PATTERN ||
        maxHits == 0 || maxHits > AFFCTL_SCAN_MAX_HITS) {
        throw std::invalid_argument("scanMemory: parametros invalidos");
    }
    SCAN_MEMORY_INPUT in{};
    in.Pid = pid;
    in.StartVa = startVa;
    in.Size = size;
    in.PatternLen = patternLen;
    in.MaxHits = maxHits;
    memcpy(in.Pattern, pattern, patternLen);
    memcpy(in.Mask, mask, patternLen);
    SCAN_MEMORY_OUTPUT out{};
    ioctl(IOCTL_SCAN_MEMORY,
          &in, sizeof(in),
          &out, sizeof(out), nullptr);
    return out;
}

std::vector<uint8_t> DriverComm::readProcessMemory(uint32_t pid, uint64_t address, uint32_t size) {
    if (pid == 0 || size == 0 || size > AFFCTL_RPM_MAX) {
        throw std::invalid_argument("readProcessMemory: parametros invalidos");
    }
    RPM_INPUT in{};
    in.Pid = pid;
    in.Address = address;
    in.Size = size;
    std::vector<uint8_t> out(size);
    DWORD returned = 0;
    ioctl(IOCTL_READ_PROCESS_MEMORY,
          &in, sizeof(in),
          out.data(), static_cast<DWORD>(out.size()),
          &returned);
    out.resize(returned);
    return out;
}

uint8_t DriverComm::readAffinity(HWND hwnd) {
    HWND_INPUT in{};
    in.Hwnd = reinterpret_cast<unsigned long long>(hwnd);
    READ_AFFINITY_OUTPUT out{};
    ioctl(IOCTL_READ_AFFINITY,
          &in, sizeof(in),
          &out, sizeof(out),
          nullptr);
    return out.Value;
}
