// Injector.cpp
#include "Injector.hpp"
#include "DriverComm.hpp"
#include "../shared/affctl_shared.h"

#include <windows.h>
#include <tlhelp32.h>
#include <stdexcept>
#include <system_error>
#include <cstring>

uint32_t Injector::findFirstThreadId(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        throw std::system_error((int)GetLastError(), std::system_category(),
                                "CreateToolhelp32Snapshot(SNAPTHREAD)");
    }
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    uint32_t chosen = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                chosen = te.th32ThreadID;
                break; // primeira thread do alvo — suficiente pra GUI
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (chosen == 0) {
        throw std::runtime_error(
            "nenhuma thread encontrada para PID " + std::to_string(pid) +
            " (processo existe? permissao?)");
    }
    return chosen;
}

std::vector<uint32_t> Injector::enumThreadIds(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        throw std::system_error((int)GetLastError(), std::system_category(),
                                "CreateToolhelp32Snapshot(SNAPTHREAD)");
    }
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    std::vector<uint32_t> tids;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tids.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}

uint64_t Injector::loadLibraryWAddr() {
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    if (!k) throw std::runtime_error("kernel32.dll nao carregado no processo atual");
    FARPROC p = GetProcAddress(k, "LoadLibraryW");
    if (!p) throw std::runtime_error("LoadLibraryW nao exportada");
    return reinterpret_cast<uint64_t>(p);
}

void Injector::inject(DriverComm& comm,
                      uint32_t pid,
                      uint32_t tid,
                      uint64_t loadLibraryAddr,
                      const std::wstring& dllPath) {
    // Normaliza para caminho absoluto — LoadLibraryW aceita relativo, mas evita
    // ambiguidade de SearchPath dentro do alvo (que pode ter cwd diferente).
    wchar_t full[MAX_PATH];
    DWORD n = GetFullPathNameW(dllPath.c_str(), MAX_PATH, full, nullptr);
    if (n == 0 || n >= MAX_PATH) {
        throw std::runtime_error("GetFullPathNameW falhou ou path >= MAX_PATH");
    }
    // Confirma que o arquivo existe (falha cedo, msg clara). Converte pra
    // narrow (ANSI) so pra colocar no what() da excecao.
    if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES) {
        char narrow[MAX_PATH] = {0};
        WideCharToMultiByte(CP_ACP, 0, full, -1, narrow, MAX_PATH, nullptr, nullptr);
        throw std::runtime_error(std::string("DLL nao existe: ") + narrow);
    }

    // Monta struct do IOCTL.
    INJECT_DLL_INPUT in{};
    in.TargetPid       = pid;
    in.TargetTid       = tid;
    in.LoadLibraryAddr = loadLibraryAddr;

    size_t wlen  = wcslen(full);
    size_t bytes = wlen * sizeof(wchar_t);
    if (bytes > sizeof(in.DllPath) - sizeof(wchar_t)) {
        throw std::runtime_error("path da DLL nao cabe no buffer do IOCTL");
    }
    memcpy(in.DllPath, full, bytes);
    in.DllPathLen = static_cast<unsigned long>(bytes);

    // Envia ao driver. Reusa o helper `ioctl` publico via um wrapper novo.
    comm.injectDll(in);
}

std::vector<uint32_t> Injector::enumPidsByName(const wchar_t* imageName) {
    std::vector<uint32_t> pids;
    if (imageName == nullptr || *imageName == 0) return pids;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, imageName) == 0) {
                pids.push_back(pe.th32ProcessID);
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pids;
}

bool Injector::hasModuleLoaded(uint32_t pid, const wchar_t* dllBaseName) {
    // TH32CS_SNAPMODULE lista modulos user-mode. TH32CS_SNAPMODULE32 tambem
    // pega WOW64. Combinamos os dois via OR.
    HANDLE snap = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        // Falhas comuns: PID nao existe, ou processo esta suspenso/reciclando.
        return false;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    bool found = false;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, dllBaseName) == 0) {
                found = true;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return found;
}
