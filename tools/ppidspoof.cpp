// ppidspoof.cpp
// Tool minima para testar a defesa anti-PPID-spoofing do affctl.sys.
//
// Spawna um processo declarando `fake_parent_pid` como pai via
// UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS).
// Isso sobrescreve o campo ParentProcessId visto por:
//   - Ferramentas de tracing (Process Monitor, EDR, Security EventID 4688)
//   - CreateInfo->ParentProcessId nos callbacks PsSetCreateProcessNotifyRoutineEx
//
// O que NAO muda:
//   - PsGetCurrentProcessId() dentro do callback (retorna sempre o PID real
//     da thread que fez NtCreateUserProcess). E exatamente esse valor que o
//     affctl.sys captura para detectar/mitigar essa evasao — ver
//     `anti-PPID-spoofing` em driver/process_notify.cpp.
//
// Uso:
//   ppidspoof.exe <fake_parent_pid> <exe_alvo> [args...]
//
// Exemplo:
//   ppidspoof.exe 5000 C:\Windows\System32\notepad.exe
//   ppidspoof.exe 4820 cmd.exe /c echo ola
//
// Codigos de saida:
//   0  processo spawnado com sucesso
//   1  erro de runtime (OpenProcess, CreateProcess, etc)
//   2  erro de sintaxe / PID invalido

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr,
            "uso: ppidspoof.exe <fake_parent_pid> <exe_alvo> [args...]\n"
            "     ex: ppidspoof.exe 5000 C:\\Windows\\System32\\notepad.exe\n");
        return 2;
    }

    DWORD fakePpid = static_cast<DWORD>(std::atoi(argv[1]));
    if (fakePpid == 0) {
        fprintf(stderr, "[ppidspoof] PID invalido: %s\n", argv[1]);
        return 2;
    }

    // Abre handle pro fake parent — PROCESS_CREATE_PROCESS e o minimo para
    // que UpdateProcThreadAttribute o aceite como parent spoofado. Rodar como
    // Administrator resolve a maioria dos falhas de OpenProcess (SYSTEM/high
    // integrity level continuam bloqueados).
    HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, fakePpid);
    if (!hParent) {
        DWORD e = GetLastError();
        fprintf(stderr,
            "[ppidspoof] OpenProcess(pid=%lu, PROCESS_CREATE_PROCESS) falhou: %lu\n",
            fakePpid, e);
        fprintf(stderr,
            "            (rode como Administrator, e escolha um pai acessivel:\n"
            "             evite PIDs de SYSTEM/CSRSS)\n");
        return 1;
    }

    // Aloca ProcThreadAttributeList com espaco para 1 attribute.
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    auto* attrList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, attrSize));
    if (!attrList) {
        CloseHandle(hParent);
        fprintf(stderr, "[ppidspoof] HeapAlloc(%zu) falhou\n", attrSize);
        return 1;
    }
    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
        DWORD e = GetLastError();
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        fprintf(stderr, "[ppidspoof] InitializeProcThreadAttributeList falhou: %lu\n", e);
        return 1;
    }

    // Configura PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = &hParent.
    if (!UpdateProcThreadAttribute(
            attrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            &hParent, sizeof(HANDLE), nullptr, nullptr)) {
        DWORD e = GetLastError();
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        CloseHandle(hParent);
        fprintf(stderr, "[ppidspoof] UpdateProcThreadAttribute falhou: %lu\n", e);
        return 1;
    }

    // Monta a command line: exe + args. Aspas garantem paths com espacos.
    std::string cmdline = "\"";
    cmdline += argv[2];
    cmdline += "\"";
    for (int i = 3; i < argc; ++i) {
        cmdline += " ";
        cmdline += argv[i];
    }

    STARTUPINFOEXA si{};
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = attrList;
    PROCESS_INFORMATION pi{};

    // EXTENDED_STARTUPINFO_PRESENT e obrigatorio para lpAttributeList ser lido.
    // CREATE_NEW_CONSOLE deixa o alvo com sua propria console (util pra ver
    // saida dele sem se misturar com a nossa).
    BOOL ok = CreateProcessA(
        nullptr,                                                  // App name (usa cmdline)
        cmdline.data(),                                           // Cmdline
        nullptr, nullptr,                                         // Security attrs
        FALSE,                                                    // Inherit handles
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,        // Flags
        nullptr, nullptr,                                         // Env, CWD
        reinterpret_cast<LPSTARTUPINFOA>(&si), &pi);
    DWORD err = ok ? 0 : GetLastError();

    // Cleanup imediato do attribute list e do handle pai. O CreateProcess ja
    // copiou o que precisa; nao ha razao pra segurar essas refs.
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);
    CloseHandle(hParent);

    if (!ok) {
        fprintf(stderr, "[ppidspoof] CreateProcess falhou: %lu\n", err);
        return 1;
    }

    printf("[ppidspoof] processo spawnado com pai spoofado:\n");
    printf("  Real creator PID  : %lu (este processo)\n", GetCurrentProcessId());
    printf("  Fake parent PID   : %lu (declarado via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS)\n",
           fakePpid);
    printf("  Child PID         : %lu\n", pi.dwProcessId);
    printf("  Child TID         : %lu\n", pi.dwThreadId);
    printf("\n");
    printf("Com a defesa anti-PPID-spoof do driver, o filho e injetado via\n");
    printf("match por 'creatingPid' (= real creator = este PID %lu) mesmo com\n",
           GetCurrentProcessId());
    printf("o ParentProcessId reportado ao callback sendo %lu.\n", fakePpid);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
