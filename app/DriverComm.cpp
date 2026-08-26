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

void DriverComm::setSharedInfoAddr(uint64_t addr) {
    SET_GSHAREDINFO_INPUT in{};
    in.Address = addr;
    ioctl(IOCTL_SET_GSHAREDINFO_ADDR, &in, sizeof(in), nullptr, 0, nullptr);
}

void DriverComm::setOffset(uint32_t offset) {
    SET_OFFSET_INPUT in{};
    in.Offset = offset;
    ioctl(IOCTL_SET_OFFSET, &in, sizeof(in), nullptr, 0, nullptr);
}

void DriverComm::clearAffinity(HWND hwnd) {
    HWND_INPUT in{};
    in.Hwnd = reinterpret_cast<unsigned long long>(hwnd);
    ioctl(IOCTL_CLEAR_AFFINITY, &in, sizeof(in), nullptr, 0, nullptr);
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
