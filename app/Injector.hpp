// Injector.hpp
// Lado user-mode da injecao via APC do kernel. Responsabilidades:
//   1. Enumerar threads do PID alvo (Toolhelp) — driver so recebe TID pronto.
//   2. Resolver LdrLoadDll em ntdll.dll — mesmo VA no alvo (Known DLL, per-boot ASLR).
//   3. Normalizar o path da DLL (absoluto + validar existencia).
//   4. Chamar IOCTL_INJECT_DLL no driver via DriverComm.
#pragma once
#include <string>
#include <cstdint>
#include <vector>

class DriverComm;

class Injector {
public:
    // Retorna o TID da primeira thread do processo alvo (Toolhelp). Para GUI,
    // qualquer thread do processo eventualmente entra em wait alertable.
    static uint32_t findFirstThreadId(uint32_t pid);

    // Retorna TODAS as threads do processo alvo. Usado para injecao "shotgun"
    // onde enfileiramos APC em cada uma — ao menos uma acaba entrando em wait
    // alertable e dispara nossa carga.
    static std::vector<uint32_t> enumThreadIds(uint32_t pid);

    // Endereco de ntdll!LdrLoadDll no processo atual. E o mesmo endereco
    // no processo alvo — ntdll e Known DLL, VA identico em toda sessao/boot.
    static uint64_t ldrLoadDllAddr();

    // Executa: normaliza path, enfileira APC via driver. Nao aguarda a APC
    // disparar (isso e feito quando a thread do alvo entrar em wait alertable).
    static void inject(DriverComm& comm,
                       uint32_t pid,
                       uint32_t tid,
                       uint64_t ldrLoadDllAddr,
                       const std::wstring& dllPath);

    // Enumera modulos carregados no processo `pid` e retorna true se algum
    // basename bater com `dllBaseName` (case-insensitive). Usa Toolhelp.
    static bool hasModuleLoaded(uint32_t pid, const wchar_t* dllBaseName);

    // Enumera todos os processos ativos cujo basename == `imageName` (case-
    // insensitive). Usado pelo --watch para alertar o operador de que ha
    // instancias vivas — o callback do driver so pega processos criados
    // APOS o registro.
    static std::vector<uint32_t> enumPidsByName(const wchar_t* imageName);
};
