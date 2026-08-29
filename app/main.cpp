// main.cpp
// affapp.exe — orquestra: discovery do offset -> demo (clear + prova visual) ->
// guard opcional (cabo-de-guerra contra reaplicacao).
//
// Escopo: opera SO sobre janelas criadas pelo proprio app (TestWindow).
#include "DriverComm.hpp"
#include "TestWindow.hpp"
#include "OffsetFinder.hpp"
#include "BmpCapture.hpp"
#include "PdbResolver.hpp"
#include "ModuleBase.hpp"
#include "Injector.hpp"
#include "OffsetCache.hpp"
#include "Version.hpp"

#include <windows.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <string>
#include <io.h>       // _setmode, _fileno (pra --rpm --raw)
#include <fcntl.h>    // _O_BINARY

#ifndef WDA_NONE
#define WDA_NONE               0x00
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE  0x11
#endif

namespace {

void hexdump(const char* label, const unsigned char* p, size_t n) {
    printf("  %s:\n", label);
    for (size_t row = 0; row < n; row += 16) {
        printf("    +0x%02zX: ", row);
        for (size_t i = 0; i < 16 && row + i < n; ++i) {
            printf("%02X ", p[row + i]);
        }
        printf("\n");
    }
}

void printDiag(DriverComm& comm, HWND hwnd) {
    AFF_DIAG_OUTPUT d = comm.diag(hwnd);
    unsigned short expectUniq = static_cast<unsigned short>((reinterpret_cast<unsigned long long>(hwnd) >> 16) & 0xFFFF);
    printf("[diag] hwnd=0x%llX index=%lu (0x%lX) expectWUniq=0x%X\n",
           (unsigned long long)hwnd, d.index, d.index, expectUniq);
    printf("[diag] gShared      = 0x%016llX valido=%lu\n", d.gShared, d.gSharedValid);
    printf("[diag] aheListPtr   = 0x%016llX valido=%lu\n", d.aheListPtr, d.aheListValid);
    printf("[diag] heEntrySize  = %lu (0x%lX)\n", d.heEntrySize, d.heEntrySize);
    printf("[diag] hePtr        = 0x%016llX valido=%lu\n", d.hePtr, d.heValid);
    printf("[diag] entry bType=0x%02X bFlags=0x%02X wUniq=0x%04X %s\n",
           d.bType, d.bFlags, d.wUniq,
           (d.bType == 1 && d.wUniq == expectUniq) ? "(match)" : "(NAO CASOU)");
    hexdump("gSharedRaw[128]", d.gSharedRaw, sizeof(d.gSharedRaw));
    hexdump("heRaw[128]",      d.heRaw,      sizeof(d.heRaw));
    for (int i = 0; i < 4; ++i) {
        const char* nm = (i==0) ? "raw" : (i==1) ? "hi(win32kbase)" : (i==2) ? "hi(psi)" : "hi(aheList)";
        printf("[diag] phead cand[%d] %-15s = 0x%016llX valido=%lu\n",
               i, nm, d.pheadCand[i], d.pheadValid[i]);
        if (d.pheadValid[i]) {
            char lbl[64]; snprintf(lbl, sizeof(lbl), "pheadRaw[%d][32]", i);
            hexdump(lbl, d.pheadRaw[i], sizeof(d.pheadRaw[i]));
        }
    }
}

// Helper: assume driver aberto + gSharedInfo/ValidateHwnd/offset ja configurados.
// So faz o "cria janela -> aplica affinity -> clear -> prova visual". Chamado
// pelo runDemo(argc, argv) que orquestra o setup.
void demoStep(DriverComm& comm) {
    // Janela visivel com conteudo distintivo.
    TestWindow demo(/*visible=*/true, L"AffCtl DEMO");
    HWND h = demo.hwnd();

    // Aplica protecao — a partir daqui, capturas de tela mostram preto.
    demo.setAffinity(WDA_EXCLUDEFROMCAPTURE);
    for (int i = 0; i < 10; ++i) { demo.pump(); Sleep(50); }

    uint8_t before = comm.readAffinity(h);
    printf("[demo] affinity antes do clear = 0x%02X (esperado != 0)\n", before);
    BmpCapture::captureWindow(h, "before.bmp");
    printf("[demo] captura salva: before.bmp\n");

    // Driver zera a flag na tagWND.
    comm.clearAffinity(h);
    for (int i = 0; i < 10; ++i) { demo.pump(); Sleep(50); }

    uint8_t after = comm.readAffinity(h);
    printf("[demo] affinity apos clear  = 0x%02X (esperado 0x00)\n", after);
    BmpCapture::captureWindow(h, "after.bmp");
    printf("[demo] captura salva: after.bmp\n");

    if (before != 0 && after == 0) {
        printf("[demo] OK — flag removida no kernel.\n");
    } else {
        printf("[demo] ATENCAO — valores inesperados; revise offset/structs.\n");
    }

    // Mantem a janela um instante para inspecao manual.
    for (int i = 0; i < 40; ++i) { demo.pump(); Sleep(50); }
}

void runGuard(DriverComm& comm, HWND target) {
    std::atomic<bool> stop{false};
    std::thread worker([&]() {
        while (!stop.load()) {
            try {
                uint8_t v = comm.readAffinity(target);
                if (v != 0) {
                    comm.clearAffinity(target);
                    printf("[guard] reaplicacao detectada (0x%02X) -> reclear\n", v);
                }
            } catch (const std::exception& e) {
                printf("[guard] erro: %s\n", e.what());
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    });

    printf("[guard] ativo. Pressione Enter para parar...\n");
    getchar();
    stop.store(true);
    worker.join();
}

} // namespace

// --probe-dwm: reality-check do PDB de dwmcore.dll para viabilidade do
// ataque "driver -> KeStackAttachProcess(dwm.exe) -> escrita nas structs
// internas". Nao carrega driver; roda 100% user-mode.
static int probeDwm() {
    printf("[probe] carregando PDB de dwmcore.dll...\n");
    try {
        PdbResolver pdb(L"C:\\Windows\\System32\\dwmcore.dll");
        const char* wildcards[] = {
            "*apture*", "*xclude*", "*ffinity*", "*isual*",
            "*indow*",  "*rotect*", "CWindow*",  "CVisual*",
            "*::Add*",  "*Get*"
        };
        size_t total = 0;
        for (const char* mask : wildcards) {
            auto hits = pdb.enumSymbols(mask);
            printf("\n[probe] mask '%s' -> %zu simbolos\n", mask, hits.size());
            total += hits.size();
            for (size_t i = 0; i < hits.size() && i < 15; ++i) {
                printf("  RVA=0x%08X size=%u  %s\n",
                       hits[i].rva, hits[i].size, hits[i].name.c_str());
            }
            if (hits.size() > 15) printf("  ...+%zu adicionais\n", hits.size()-15);
        }
        printf("\n[probe] TOTAL de simbolos entre todas as mascaras: %zu\n", total);
        printf("[probe] Se aparece nomes de classes (CVisual::x, CWindow::y) e\n");
        printf("        metodos internos, o pivot DWM e factivel.\n");
        printf("[probe] Se so aparece exports genericos ou nada, precisamos RE.\n");
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[probe] erro: %s\n", e.what());
        return 1;
    }
}

// Helper compartilhado por --inject e --inject-by-name.
// Recebe PID ja resolvido + path da DLL (ANSI para logs e WIDE para o driver).
static int injectDllIntoPid(DriverComm& comm, uint32_t pid,
                            const std::wstring& dllPathW, const char* dllPathA) {
    uint64_t addr = Injector::ldrLoadDllAddr();
    auto tids = Injector::enumThreadIds(pid);
    if (tids.empty()) {
        throw std::runtime_error("nenhuma thread para PID " + std::to_string(pid));
    }
    printf("[inject] pid=%u threads=%zu LdrLoadDll=0x%llX\n",
           pid, tids.size(), (unsigned long long)addr);
    printf("[inject] dll=%s\n", dllPathA);
    printf("[inject] enfileirando APC em TODAS as threads (shotgun):\n");
    int okCount = 0;
    for (uint32_t tid : tids) {
        try {
            Injector::inject(comm, pid, tid, addr, dllPathW);
            ++okCount;
            printf("  tid=%-6u OK\n", tid);
        } catch (const std::exception& e) {
            printf("  tid=%-6u FALHOU: %s\n", tid, e.what());
        }
    }
    printf("[inject] APC enfileirada em %d/%zu threads. Aguardando ate 15s...\n",
           okCount, tids.size());
    const wchar_t* base = wcsrchr(dllPathW.c_str(), L'\\');
    base = base ? base + 1 : dllPathW.c_str();
    bool loaded = false;
    for (int i = 0; i < 75 && !loaded; ++i) {
        Sleep(200);
        loaded = Injector::hasModuleLoaded(pid, base);
    }
    if (loaded) {
        printf("[inject] OK — DLL '%ls' aparece nos modulos do PID %u.\n",
               base, pid);
        return 0;
    }
    printf("[inject] AVISO: DLL '%ls' NAO apareceu nos modulos do PID %u em 15s.\n",
           base, pid);
    printf("[inject] Verifique %%TEMP%%\\affbypass_status.txt no PROCESSO ALVO.\n");
    return 1;
}

// Converte argv[i] (ANSI) para std::wstring (UTF-16).
static std::wstring argToWide(const char* s) {
    int wlen = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (wlen <= 0) return {};
    std::wstring w(wlen - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s, -1, w.data(), wlen);
    return w;
}

// Path canonico do affbypass.dll no mesmo diretorio de affapp.exe.
// Usado como default nos comandos de injecao — o operador nao precisa mais
// passar o path explicitamente pra caso mais comum.
static std::wstring defaultDllPath() {
    wchar_t exe[MAX_PATH];
    DWORD n = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"affbypass.dll";
    wchar_t* lastSlash = wcsrchr(exe, L'\\');
    if (!lastSlash) return L"affbypass.dll";
    // Substitui o basename do exe por "affbypass.dll".
    *(lastSlash + 1) = L'\0';
    std::wstring path(exe);
    path += L"affbypass.dll";
    return path;
}

// Procura "--dll <path>" em argv (ordem qualquer). Retorna vazio se nao achou.
// Nao valida path aqui — validacao/absolutizacao fica em resolveDllPath.
static std::wstring findExplicitDll(int argc, char** argv) {
    for (int i = 1; i < argc - 1; ++i) {
        if (std::strcmp(argv[i], "--dll") == 0) {
            return argToWide(argv[i + 1]);
        }
    }
    return {};
}

// Resolucao unica do path da DLL usado nos comandos de injecao/watch.
// Ordem de precedencia:
//   1. --dll <path>                                (explicit override)
//   2. argv[posIdx] (se existir e nao comecar com "-")  (retrocompat posicional)
//   3. <dir_do_affapp>\affbypass.dll               (default do caso comum)
//
// Sempre normaliza pra path absoluto e valida existencia — lanca std::runtime_error
// com mensagem clara se a DLL nao existe (exit code 2 no main).
static std::wstring resolveDllPath(int argc, char** argv, int posIdx) {
    std::wstring picked = findExplicitDll(argc, argv);
    if (picked.empty() && posIdx < argc && argv[posIdx] && argv[posIdx][0] != '-') {
        picked = argToWide(argv[posIdx]);
    }
    if (picked.empty()) {
        picked = defaultDllPath();
    }

    wchar_t full[MAX_PATH];
    if (GetFullPathNameW(picked.c_str(), MAX_PATH, full, nullptr) == 0) {
        throw std::runtime_error("resolveDllPath: GetFullPathNameW falhou");
    }
    if (GetFileAttributesW(full) == INVALID_FILE_ATTRIBUTES) {
        // Converte pro erro em UTF-8 pra ficar legivel no console.
        char narrow[MAX_PATH * 3] = {0};
        WideCharToMultiByte(CP_UTF8, 0, full, -1, narrow, sizeof(narrow), nullptr, nullptr);
        throw std::runtime_error(std::string("DLL nao encontrada: ") + narrow +
            "\n         (dica: use --dll <path> ou coloque affbypass.dll junto do affapp.exe)");
    }
    return full;
}

static void printVersion() {
    printf("affapp.exe %s (build %s)\n", AFFAPP_VERSION, AFFAPP_BUILD_STAMP);
}

static void printHelp() {
    printVersion();
    printf(
        "\n"
        "DisplayAffinity bypass PoC — control app para o driver affctl.sys.\n"
        "\n"
        "USO\n"
        "  affapp.exe <comando> [opcoes]\n"
        "\n"
        "COMANDOS DE DIAGNOSTICO\n"
        "  --status                       Diagnostica driver + cache + offset ativo\n"
        "  --version                      Imprime versao e sai\n"
        "  --help, -h, -?                 Este texto\n"
        "\n"
        "COMANDOS DE INJECAO\n"
        "  --inject <pid> [dll]           Injeta DLL num PID especifico via APC\n"
        "  --inject-by-name <exe> [dll]   Resolve PID pelo nome (event-driven) e injeta\n"
        "  --watch <exe> [dll]            Registra watch — driver injeta em qualquer\n"
        "                                 processo futuro com esse basename e filhos\n"
        "  --unwatch <exe>                Remove watch previamente registrado\n"
        "  --global-hook <exe> [dll]      Ring-3 fallback: SetWindowsHookEx global. Use\n"
        "                                 pra alvos com anti-tamper que rejeitam a\n"
        "                                 injecao kernel (ex: MMO clients). Roda ate Ctrl+C.\n"
        "\n"
        "COMANDOS DE ESTADO\n"
        "  --reset-cache                  Apaga offset persistido no Registry\n"
        "                                 (forca re-discovery na proxima execucao)\n"
        "\n"
        "COMANDOS DE TESTE/DESENVOLVIMENTO\n"
        "  --demo [--guard]               Discovery + demo interativa (janela + BMPs).\n"
        "                                 --guard: thread cabo-de-guerra (auto-reclear).\n"
        "                                 Requer driver Debug (IOCTLs de diag).\n"
        "  --capture <saida.bmp> [delay]  Screenshot da tela toda (default delay=3s)\n"
        "  --probe-dwm                    Reality-check do PDB de dwmcore.dll\n"
        "\n"
        "OPCOES GERAIS\n"
        "  --dll <caminho>                Override do path da DLL (default:\n"
        "                                 <dir_do_affapp>\\affbypass.dll)\n"
        "\n"
        "EXEMPLOS\n"
        "  affapp.exe --status\n"
        "  affapp.exe --watch cmd.exe\n"
        "  affapp.exe --watch cmd.exe --dll C:\\payloads\\meu.dll\n"
        "  affapp.exe --inject 4820\n"
        "  affapp.exe --inject-by-name notepad.exe\n"
        "  affapp.exe --global-hook rubinot_dx.exe\n"
        "  affapp.exe --demo --guard\n"
        "\n"
        "CODIGOS DE RETORNO\n"
        "  0  sucesso\n"
        "  1  erro de runtime (driver nao carregado, IOCTL falhou, injecao falhou)\n"
        "  2  erro de argumentos ou ambiente (sintaxe invalida, DLL ausente)\n"
    );
}

// --inject <pid> [dll] — injecao via APC no kernel. Nao carrega discovery
// nem toca gSharedInfo. So abre o device, resolve TID/LdrLoadDll e chama
// IOCTL_INJECT_DLL. Requer driver ja carregado (sc start affctl).
static int runInject(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --inject <pid> [caminho-da-dll]\n");
        fprintf(stderr, "     (default DLL: <dir_do_affapp>\\affbypass.dll)\n");
        return 2;
    }
    uint32_t pid = static_cast<uint32_t>(std::atoi(argv[startIdx + 1]));
    if (pid == 0) {
        fprintf(stderr, "[inject] PID invalido: %s\n", argv[startIdx + 1]);
        return 2;
    }

    std::wstring pathW;
    try {
        pathW = resolveDllPath(argc, argv, startIdx + 2);
    } catch (const std::exception& e) {
        fprintf(stderr, "[inject] %s\n", e.what());
        return 2;
    }
    // Version narrow do path (so pra logs; injectDllIntoPid re-normaliza internamente).
    char pathA[MAX_PATH * 3] = {0};
    WideCharToMultiByte(CP_UTF8, 0, pathW.c_str(), -1, pathA, sizeof(pathA), nullptr, nullptr);

    try {
        DriverComm comm; // abre \\.\AffCtl
        return injectDllIntoPid(comm, pid, pathW, pathA);
    } catch (const std::exception& e) {
        fprintf(stderr, "[inject] erro: %s\n", e.what());
        return 1;
    }
}

// --watch <exe> [dll] — registra watch. Driver auto-injeta em qualquer
// processo futuro com esse basename E em toda a arvore de filhos deles. A
// injecao acontece no callback de thread create, ANTES do EntryPoint do EXE
// rodar (early injection).
static int runWatch(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --watch <nome-exe> [caminho-dll]\n");
        fprintf(stderr, "     ex: affapp.exe --watch afftarget.exe\n");
        fprintf(stderr, "         affapp.exe --watch cmd.exe --dll C:\\payload.dll\n");
        return 2;
    }
    std::wstring nameW = argToWide(argv[startIdx + 1]);
    if (nameW.empty()) {
        fprintf(stderr, "[watch] falha ao converter <nome-exe>\n");
        return 2;
    }

    // Resolve path da DLL — --dll > posicional > default. Valida existencia.
    std::wstring dllPath;
    try {
        dllPath = resolveDllPath(argc, argv, startIdx + 2);
    } catch (const std::exception& e) {
        fprintf(stderr, "[watch] %s\n", e.what());
        return 2;
    }

    // Warning: --watch so pega processos FUTUROS. Se ja existem instancias vivas
    // com esse basename, o operador provavelmente esperava que fossem incluidas
    // tambem — avisamos e apontamos o caminho certo (--inject-by-name).
    auto living = Injector::enumPidsByName(nameW.c_str());
    if (!living.empty()) {
        fprintf(stderr, "\n[!] AVISO: encontradas %zu instancia(s) de '%s' ja em execucao:\n",
                living.size(), argv[startIdx + 1]);
        fprintf(stderr, "    PIDs:");
        for (auto pid : living) fprintf(stderr, " %u", pid);
        fprintf(stderr, "\n");
        fprintf(stderr, "[!] --watch so injeta em processos criados APOS este registro.\n");
        fprintf(stderr, "[!] Para injetar nas instancias vivas use:\n");
        fprintf(stderr, "        affapp.exe --inject-by-name %s\n\n", argv[startIdx + 1]);
    }

    try {
        DriverComm comm;
        uint64_t addr = Injector::ldrLoadDllAddr();
        comm.watchName(nameW.c_str(), dllPath.c_str(), addr);
        printf("[watch] registrado: '%s' -> '%ls' (LdrLoadDll=0x%llX)\n",
               argv[startIdx + 1], dllPath.c_str(), (unsigned long long)addr);
        printf("[watch] Qualquer processo futuro com esse nome (e filhos) recebe\n");
        printf("        injecao APC no NASCIMENTO. Ate voce unregistrar via --unwatch\n");
        printf("        ou o driver ser descarregado.\n");
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[watch] erro: %s\n", e.what());
        return 1;
    }
}

static int runUnwatch(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --unwatch <nome-exe>\n");
        return 2;
    }
    std::wstring nameW = argToWide(argv[startIdx + 1]);
    if (nameW.empty()) return 2;
    try {
        DriverComm comm;
        comm.unwatchName(nameW.c_str());
        printf("[unwatch] removido: '%s'\n", argv[startIdx + 1]);
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[unwatch] erro: %s\n", e.what());
        return 1;
    }
}

// TID da thread que roda o message loop do --global-hook. O handler de Ctrl+C
// (que roda em thread SEPARADA criada pelo Windows) usa isso pra postar WM_QUIT
// pra thread certa — PostQuitMessage() posta pra thread que chamou, e o handler
// nao esta na main.
static DWORD g_globalHookThreadTid = 0;
static BOOL WINAPI GlobalHookCtrlHandler(DWORD ctrl) {
    if ((ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT ||
         ctrl == CTRL_CLOSE_EVENT) && g_globalHookThreadTid) {
        PostThreadMessageW(g_globalHookThreadTid, WM_QUIT, 0, 0);
        return TRUE;
    }
    return FALSE;
}

// --global-hook <exe> [dll] — Ring-3 fallback pra alvos com anti-tamper que
// rejeitam a injecao kernel (Rubinot, MMO clients com hooks internos em
// LdrLoadDll). Usa SetWindowsHookEx global (WH_GETMESSAGE, dwThreadId=0), que
// forca o win32k a carregar a DLL em CADA processo que dispatcha mensagens.
//
// Como o load acontece via user32!__ClientLoadLibrary (modulo signed pela MS),
// hooks internos em LdrLoadDll que validam caller aceitam — a rota e "blessed"
// pelo Windows. A DLL usa filter file em %TEMP%\affbypass_target.txt pra so
// ATIVAR nos processos com o nome alvo (senao ela carrega em tudo).
static int runGlobalHook(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --global-hook <nome-exe> [caminho-dll]\n");
        fprintf(stderr, "     ex: affapp.exe --global-hook rubinot_dx.exe\n");
        fprintf(stderr, "         affapp.exe --global-hook cmd.exe --dll C:\\payload.dll\n");
        return 2;
    }
    const char* exeNameA = argv[startIdx + 1];

    std::wstring dllPath;
    try {
        dllPath = resolveDllPath(argc, argv, startIdx + 2);
    } catch (const std::exception& e) {
        fprintf(stderr, "[global-hook] %s\n", e.what());
        return 2;
    }

    // 1) Escreve o filter file — affbypass!DllMain le e SO ativa em processos
    //    cujo basename bate. Sem esse filtro a DLL carregaria em dezenas de
    //    processos (todo GUI process no desktop).
    char tmpDir[MAX_PATH] = {0};
    if (GetTempPathA(MAX_PATH, tmpDir) == 0) {
        fprintf(stderr, "[global-hook] GetTempPath falhou (GLE=%lu)\n", GetLastError());
        return 1;
    }
    std::string filterPath = std::string(tmpDir) + "affbypass_target.txt";
    {
        HANDLE h = CreateFileA(filterPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            fprintf(stderr, "[global-hook] nao consegui criar filter file: %s (GLE=%lu)\n",
                    filterPath.c_str(), GetLastError());
            return 1;
        }
        DWORD w = 0;
        WriteFile(h, exeNameA, (DWORD)strlen(exeNameA), &w, nullptr);
        CloseHandle(h);
    }

    // 2) Carrega affbypass.dll no PROPRIO processo host (nos mesmos), mas SEM
    //    executar DllMain — DONT_RESOLVE_DLL_REFERENCES mapea a imagem e popula
    //    o export table (permite GetProcAddress) mas nao chama DllMain nem
    //    resolve imports. Isso evita o affapp ficar com o hook do MinHook em
    //    user32!SetWindowDisplayAffinity — side effect inutil e sujo.
    //
    //    O SetWindowsHookEx so precisa do HMODULE pra fazer GetModuleFileName
    //    e descobrir o path da DLL (pra passar aos outros processos, que aí
    //    fazem load NORMAL com DllMain rodando).
    HMODULE hDll = LoadLibraryExW(dllPath.c_str(), nullptr,
                                  DONT_RESOLVE_DLL_REFERENCES |
                                  LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!hDll) {
        fprintf(stderr, "[global-hook] LoadLibraryExW falhou (GLE=%lu). DLL: %ls\n",
                GetLastError(), dllPath.c_str());
        DeleteFileA(filterPath.c_str());
        return 1;
    }

    HOOKPROC pfn = (HOOKPROC)GetProcAddress(hDll, "GlobalHookProc");
    if (!pfn) {
        fprintf(stderr, "[global-hook] GlobalHookProc nao exportado em %ls\n",
                dllPath.c_str());
        fprintf(stderr, "              (recompila affbypass — precisa da Fase C).\n");
        DeleteFileA(filterPath.c_str());
        return 1;
    }

    // 3) Instala hooks GLOBAIS em multiplos tipos — cada um dispara em situacoes
    //    diferentes, e o objetivo e maximizar chance de ativar em qualquer processo
    //    GUI, incluindo jogos que fazem message pump nao-standard:
    //      WH_GETMESSAGE  — GetMessage/PeekMessage retornando (message pump classico)
    //      WH_CBT         — criacao/destruicao/foco/ativacao de janela (universal)
    //      WH_CALLWNDPROC — antes de SendMessage entregar (usado por praticamente
    //                       qualquer inter-window communication)
    //
    //    Basta UM dos 3 disparar em qualquer thread do alvo pro Windows carregar
    //    a DLL. Jogos que evitam WH_GETMESSAGE geralmente ainda passam por WH_CBT
    //    ao criar janelas iniciais.
    struct HookInstall { int id; const char* name; HHOOK handle; };
    HookInstall hooks[] = {
        { WH_GETMESSAGE,  "WH_GETMESSAGE",  nullptr },
        { WH_CBT,         "WH_CBT",         nullptr },
        { WH_CALLWNDPROC, "WH_CALLWNDPROC", nullptr },
    };
    int installed = 0;
    for (auto& hk : hooks) {
        hk.handle = SetWindowsHookExW(hk.id, pfn, hDll, 0);
        if (hk.handle) ++installed;
    }
    if (installed == 0) {
        fprintf(stderr, "[global-hook] SetWindowsHookExW falhou em TODOS os tipos (GLE=%lu)\n",
                GetLastError());
        DeleteFileA(filterPath.c_str());
        return 1;
    }

    printf("[global-hook] instalado (%d/%zu hooks ativos).\n", installed,
           sizeof(hooks)/sizeof(hooks[0]));
    for (auto& hk : hooks) {
        printf("              %-16s %s\n", hk.name, hk.handle ? "OK" : "FALHOU");
    }
    printf("              DLL:        %ls\n", dllPath.c_str());
    printf("              Alvo:       %s\n", exeNameA);
    printf("              Filter:     %s\n", filterPath.c_str());
    printf("              Windows carrega a DLL em cada processo que dispara qualquer\n");
    printf("              um dos hooks; a DLL AUTO-DESCARTA em quem nao bate com o filtro.\n");
    printf("              Ctrl+C pra desinstalar.\n");

    // 4) Ctrl+C handler + message loop. GetMessage bloqueia; sem message loop,
    //    hooks globais nao propagam pra outros processos (Windows precisa que
    //    o processo host esteja "vivo" na pipeline de mensagens do desktop).
    g_globalHookThreadTid = GetCurrentThreadId();
    SetConsoleCtrlHandler(GlobalHookCtrlHandler, TRUE);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    SetConsoleCtrlHandler(GlobalHookCtrlHandler, FALSE);
    for (auto& hk : hooks) {
        if (hk.handle) UnhookWindowsHookEx(hk.handle);
    }
    DeleteFileA(filterPath.c_str());
    printf("[global-hook] desinstalado.\n");
    return 0;
}

// --inject-by-name <exe> [dll] — resolve PID pelo nome do executavel via
// callback event-driven do driver (PsSetCreateProcessNotifyRoutineEx) e reutiliza
// a mecanica de injecao APC.
static int runInjectByName(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --inject-by-name <nome-exe> [caminho-dll]\n");
        fprintf(stderr, "     (default DLL: <dir_do_affapp>\\affbypass.dll)\n");
        return 2;
    }
    const char* nameA = argv[startIdx + 1];
    std::wstring nameW = argToWide(nameA);
    if (nameW.empty()) {
        fprintf(stderr, "[inject-by-name] falha ao converter <nome-exe>\n");
        return 2;
    }

    std::wstring pathW;
    try {
        pathW = resolveDllPath(argc, argv, startIdx + 2);
    } catch (const std::exception& e) {
        fprintf(stderr, "[inject-by-name] %s\n", e.what());
        return 2;
    }
    char pathA[MAX_PATH * 3] = {0};
    WideCharToMultiByte(CP_UTF8, 0, pathW.c_str(), -1, pathA, sizeof(pathA), nullptr, nullptr);

    try {
        DriverComm comm;
        printf("[inject-by-name] resolvendo '%s' via callback do driver...\n", nameA);
        uint32_t pid = comm.resolvePidByName(nameW.c_str());
        if (pid == 0) {
            fprintf(stderr,
                "[inject-by-name] '%s' NAO esta na tabela do driver.\n"
                "                 O callback so registra processos criados APOS o driver carregar.\n"
                "                 Feche o alvo e ABRA-O DE NOVO, depois tente injetar.\n"
                "                 (ou: sc stop affctl / sc start affctl / abra o alvo / injete.)\n",
                nameA);
            return 1;
        }
        printf("[inject-by-name] resolvido -> PID %u\n", pid);
        return injectDllIntoPid(comm, pid, pathW, pathA);
    } catch (const std::exception& e) {
        fprintf(stderr, "[inject-by-name] erro: %s\n", e.what());
        return 1;
    }
}

// --capture <output.bmp> [delaySec] — captura a tela toda apos delaySec (default 3).
// Substituto do Snipping Tool que nao dimeriza/cobre a tela e nao esconde o alvo.
// Se DisplayAffinity estiver ativa numa janela, ela sai PRETA no BMP.
static int runCapture(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --capture <saida.bmp> [delay-em-segundos]\n");
        return 2;
    }
    const char* outPath = argv[startIdx + 1];
    int delaySec = 3;
    if (startIdx + 2 < argc) delaySec = std::atoi(argv[startIdx + 2]);
    if (delaySec < 0) delaySec = 0;

    printf("[capture] capturando em %d segundos... (traga a janela alvo pra frente)\n", delaySec);
    for (int i = delaySec; i > 0; --i) {
        printf("  %d...\n", i); fflush(stdout);
        Sleep(1000);
    }
    printf("[capture] SNAP!\n");

    // BitBlt do desktop inteiro para um DIB, depois grava BMP.
    HWND desktop = GetDesktopWindow();
    HDC  screen  = GetDC(nullptr);
    if (!screen) { fprintf(stderr, "GetDC falhou\n"); return 1; }
    RECT r; GetWindowRect(desktop, &r);
    int w = r.right - r.left, h = r.bottom - r.top;

    HDC mem = CreateCompatibleDC(screen);
    BITMAPINFO bi{};
    bi.bmiHeader.biSize   = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth  = w;
    bi.bmiHeader.biHeight = -h; // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount    = 24;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP dib = CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    HGDIOBJ old = SelectObject(mem, dib);
    BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY);
    SelectObject(mem, old);

    // Grava BMP.
    DWORD rowBytes = ((w * 3 + 3) & ~3);
    DWORD imgSize  = rowBytes * h;
    BITMAPFILEHEADER fh{};
    fh.bfType    = 0x4D42; // "BM"
    fh.bfOffBits = sizeof(fh) + sizeof(bi.bmiHeader);
    fh.bfSize    = fh.bfOffBits + imgSize;
    BITMAPINFOHEADER ih = bi.bmiHeader;
    ih.biHeight = h; // grava bottom-up (padrao BMP)
    ih.biSizeImage = imgSize;

    FILE* f = fopen(outPath, "wb");
    if (f) {
        fwrite(&fh, 1, sizeof(fh), f);
        fwrite(&ih, 1, sizeof(ih), f);
        // Reordena top-down -> bottom-up.
        for (int y = h - 1; y >= 0; --y) {
            fwrite((char*)bits + y * rowBytes, 1, rowBytes, f);
        }
        fclose(f);
        printf("[capture] salvo em %s (%dx%d)\n", outPath, w, h);
    } else {
        fprintf(stderr, "[capture] fopen falhou pra %s\n", outPath);
    }

    DeleteObject(dib);
    DeleteDC(mem);
    ReleaseDC(nullptr, screen);
    return f ? 0 : 1;
}

// --demo [--guard] — orquestra o fluxo completo de PoC:
// resolve PDB, popula gSharedInfo/ValidateHwnd, faz discovery (ou usa cache),
// aplica DisplayAffinity + clear + captura BMPs, e opcionalmente monta a
// thread de guard (cabo-de-guerra).
static int runDemo(int argc, char** argv, int /*startIdx*/) {
    bool guard = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--guard") == 0) { guard = true; break; }
    }

    try {
        DriverComm comm; // abre \\.\AffCtl (lanca se driver nao carregado)

        // --- Resolve gSharedInfo via PDB (100% preciso, future-proof) ---
        printf("[pdb] resolvendo gSharedInfo em win32kbase.sys via PDB...\n");
        uint64_t kernelBase = ModuleBase::find(L"win32kbase.sys");
        printf("[pdb] base kernel de win32kbase.sys = 0x%llX\n",
               (unsigned long long)kernelBase);

        // Nota: dbghelp le o cabecalho local do binario (mesmo path do modulo
        // kernel) para extrair GUID+Age e baixar o PDB certo do symbol server.
        PdbResolver pdb(L"C:\\Windows\\System32\\win32kbase.sys");
        uint32_t rva = pdb.rvaOf("gSharedInfo");
        printf("[pdb] RVA de gSharedInfo = 0x%X\n", rva);

        uint64_t gSharedInfoAddr = kernelBase + rva;
        printf("[pdb] endereco absoluto gSharedInfo = 0x%llX\n",
               (unsigned long long)gSharedInfoAddr);
        comm.setSharedInfoAddr(gSharedInfoAddr);

        // ValidateHwnd: resolvedor oficial HWND->tagWND, unico caminho viavel em
        // Win11 25H2+ (phead sumiu da HANDLEENTRY publica). Tenta candidatos.
        const char* vhCandidates[] = {
            "ValidateHwnd", "HMValidateHandleNoSecure", "HMValidateHandle" };
        uint32_t vhRva = 0;
        const char* vhSym = nullptr;
        for (const char* sym : vhCandidates) {
            try { vhRva = pdb.rvaOf(sym); vhSym = sym; break; }
            catch (const std::exception&) { /* tenta o proximo */ }
        }
        if (vhSym) {
            uint64_t vhAddr = kernelBase + vhRva;
            printf("[pdb] %s RVA=0x%X abs=0x%llX\n", vhSym, vhRva,
                   (unsigned long long)vhAddr);
            comm.setValidateHwndAddr(vhAddr);
        } else {
            printf("[pdb] ATENCAO: nenhum simbolo ValidateHwnd* no PDB — usando fallback aheList (pode falhar em Win11 25H2+).\n");
        }

        // --- Offset: cache ou discovery ---
        // Fast-path: se ja existe entrada persistida no Registry (gravada por
        // uma execucao anterior com discovery bem-sucedido), pula direto pra
        // setOffset e evita o discovery — este exige IOCTLs de diagnostico
        // (AFFCTL_DIAG_IOCTLS), que so existem em build Debug do driver.
        uint32_t effectiveOffset  = 0;
        uint8_t  effectiveMask    = 0xFF;
        if (auto cached = OffsetCache::load()) {
            printf("[cache] offset=%u (0x%X) mask=0x%02X — pulando discovery\n",
                   cached->offset, cached->offset, cached->clearMask);
            effectiveOffset = cached->offset;
            effectiveMask   = cached->clearMask;
        } else {
            printf("[discovery] cache vazio; descobrindo offset da flag DisplayAffinity...\n");
            OffsetFinder::Result found;
            {
                TestWindow probe(/*visible=*/true, L"AffCtl PROBE");
                for (int i = 0; i < 10; ++i) { probe.pump(); Sleep(30); }
                found = OffsetFinder::findOffset(comm, probe.hwnd(), AFFCTL_MAX_RANGE);
            }
            printf("[discovery] offset=%u (0x%X) mask=0x%02X\n",
                   found.offset, found.offset, found.clearMask);
            effectiveOffset = found.offset;
            effectiveMask   = found.clearMask;

            OffsetCacheEntry e{ effectiveOffset, effectiveMask };
            if (OffsetCache::save(e)) {
                printf("[cache] gravado no Registry — proximas execucoes pulam discovery.\n");
            } else {
                printf("[cache] AVISO: falha ao gravar no Registry (sem admin?).\n");
            }
        }
        comm.setOffset(effectiveOffset, effectiveMask);

        demoStep(comm);

        if (guard) {
            TestWindow g(/*visible=*/true, L"AffCtl GUARD");
            g.setAffinity(WDA_EXCLUDEFROMCAPTURE);
            comm.clearAffinity(g.hwnd());
            runGuard(comm, g.hwnd());
        }

        printf("[demo] concluido.\n");
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[erro] %s\n", e.what());
        return 1;
    }
}

// ============================================================================
// Scan de memoria: --scan-int32, --scan-refine, --scan-show, --scan-clear
// State em %TEMP%\affapp_scan_state.bin — layout:
//   [pid u32][hitCount u32][hits u64 * hitCount]
// Fluxo tipico pra achar HP em rubinot:
//   1. affapp --scan-int32 <pid> 100    (HP atual, escreve state)
//   2. (tomar hit no jogo, HP -> 95)
//   3. affapp --scan-refine <pid> 95    (filtra candidates que agora = 95)
//   4. repetir 2-3 ate ~5-10 candidates
//   5. affapp --scan-show               (mostra VAs sobreviventes)
// ============================================================================

// Nome do slot de state (permite paralelizar multiplos scans em curso:
// --state hp / --state mp / --state stat3 ...). Default = "default".
static std::wstring g_stateSlot = L"default";

static std::wstring scanStatePath() {
    wchar_t tmp[MAX_PATH];
    GetTempPathW(MAX_PATH, tmp);
    std::wstring p(tmp);
    if (!p.empty() && p.back() != L'\\' && p.back() != L'/') p += L'\\';
    p += L"affapp_scan_";
    p += g_stateSlot;
    p += L".bin";
    return p;
}

// Extrai --state <name> de argv. Modifica g_stateSlot. Nao remove os args
// (os handlers ja ignoram flags desconhecidas).
static void parseStateSlot(int argc, char** argv, int startIdx) {
    for (int i = startIdx; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--state") == 0) {
            const char* s = argv[i + 1];
            std::wstring w;
            while (*s) w.push_back(static_cast<wchar_t>(*s++));
            if (!w.empty()) g_stateSlot = w;
            return;
        }
    }
}

struct ScanState {
    uint32_t pid;
    std::vector<uint64_t> hits;
};

static bool loadScanState(ScanState& out) {
    std::wstring path = scanStatePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint32_t pid = 0, hitCount = 0;
    DWORD r = 0;
    if (!ReadFile(h, &pid, sizeof(pid), &r, nullptr) || r != sizeof(pid)) {
        CloseHandle(h); return false;
    }
    if (!ReadFile(h, &hitCount, sizeof(hitCount), &r, nullptr) || r != sizeof(hitCount)) {
        CloseHandle(h); return false;
    }
    if (hitCount > 10'000'000u) { CloseHandle(h); return false; } // sanity
    out.pid = pid;
    out.hits.assign(hitCount, 0);
    if (hitCount > 0) {
        DWORD need = static_cast<DWORD>(hitCount * sizeof(uint64_t));
        if (!ReadFile(h, out.hits.data(), need, &r, nullptr) || r != need) {
            CloseHandle(h); return false;
        }
    }
    CloseHandle(h);
    return true;
}

static bool saveScanState(const ScanState& s) {
    std::wstring path = scanStatePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0,
        nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint32_t hitCount = static_cast<uint32_t>(s.hits.size());
    DWORD w = 0;
    WriteFile(h, &s.pid, sizeof(s.pid), &w, nullptr);
    WriteFile(h, &hitCount, sizeof(hitCount), &w, nullptr);
    if (hitCount > 0) {
        WriteFile(h, s.hits.data(),
            static_cast<DWORD>(hitCount * sizeof(uint64_t)), &w, nullptr);
    }
    CloseHandle(h);
    return true;
}

// Constroi (pattern, mask) pra scan de int32 exato.
static void int32Pattern(uint32_t value, uint8_t (&pat)[4], uint8_t (&mask)[4]) {
    memcpy(pat, &value, 4);
    memset(mask, 0xFF, 4);
}

// --scan-int32 <pid> <value> [--start HEX] [--end HEX]
// Full scan. Default range: 0x10000 .. 0x7FFF'FFFF'FFFF (user space).
// Escreve state (pid + hits) em %TEMP%\affapp_scan_state.bin.
static int runScanInt32(int argc, char** argv, int startIdx) {
    if (startIdx + 2 >= argc) {
        fprintf(stderr, "uso: affapp.exe --scan-int32 <pid> <value> [--start HEX] [--end HEX] [--state NAME]\n");
        fprintf(stderr, "  default range: 0x10000 .. 0x7FFFFFFF0000\n");
        fprintf(stderr, "  --state NAME  slot de persistencia (default 'default'). Paraleliza scans.\n");
        return 2;
    }
    parseStateSlot(argc, argv, startIdx);
    uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[startIdx + 1], nullptr, 0));
    uint32_t value = static_cast<uint32_t>(std::strtoul(argv[startIdx + 2], nullptr, 0));
    // Default range: user space completo. VAD skip no kernel torna varredura de
    // 128TB viavel em ~1min mesmo com heap valida grande. User pode restringir
    // com --start/--end se souber onde alvo aloca (ex: 0x100000000..0x200000000
    // pra heap tipica de app medio, sub-segundo scan).
    uint64_t start = 0x10000ULL;
    uint64_t end   = 0x7FFFFFFF0000ULL;
    for (int i = startIdx + 3; i + 1 < argc; ++i) {
        if (std::strcmp(argv[i], "--start") == 0) start = std::strtoull(argv[++i], nullptr, 0);
        else if (std::strcmp(argv[i], "--end")   == 0) end   = std::strtoull(argv[++i], nullptr, 0);
    }
    if (pid == 0 || end <= start) { fprintf(stderr, "params invalidos\n"); return 2; }

    uint8_t pat[4], mask[4];
    int32Pattern(value, pat, mask);

    try {
        DriverComm comm;
        printf("[scan] PID=%u int32=%u (0x%X) range=[0x%llX..0x%llX]\n",
            pid, value, value, (unsigned long long)start, (unsigned long long)end);

        ScanState state{ pid, {} };
        uint64_t cursor = start;
        uint64_t chunkSize = AFFCTL_SCAN_MAX_CHUNK;
        auto t0 = GetTickCount64();
        uint64_t chunks = 0;
        uint64_t totalHits = 0;
        while (cursor < end) {
            uint64_t size = (end - cursor < chunkSize) ? (end - cursor) : chunkSize;
            auto out = comm.scanMemory(pid, cursor, size,
                                       pat, mask, 4, AFFCTL_SCAN_MAX_HITS);
            for (uint32_t i = 0; i < out.HitCount; ++i) {
                state.hits.push_back(out.Hits[i]);
            }
            totalHits += out.HitCount;
            ++chunks;
            if (out.Truncated) {
                // Chunk truncou por MaxHits — continua deste ponto pra proximo scanMemory
                cursor = out.NextVa;
                if (cursor == 0) cursor += size; // fallback
            } else {
                cursor += size;
            }
            // Progress a cada 100 chunks (~ 25GB)
            if (chunks % 100 == 0) {
                printf("  progress: cursor=0x%llX hits=%llu chunks=%llu elapsed=%llums\n",
                    (unsigned long long)cursor, (unsigned long long)totalHits,
                    (unsigned long long)chunks, GetTickCount64() - t0);
                fflush(stdout);
            }
            // Sanity cutoff: rejeitar scans com hits absurdos (padrao muito comum)
            if (state.hits.size() > 1'000'000ULL) {
                printf("[scan!] > 1M hits, abortando (padrao muito comum? use --start pra restringir).\n");
                break;
            }
        }
        auto elapsed = GetTickCount64() - t0;
        printf("[scan] DONE: %zu hits em %llu chunks, %llums\n",
            state.hits.size(), (unsigned long long)chunks, elapsed);

        if (!saveScanState(state)) {
            fprintf(stderr, "[scan!] falha ao salvar state\n"); return 1;
        }
        printf("[scan] state salvo em: %ls\n", scanStatePath().c_str());
        printf("[scan] proximo passo: mude o valor no jogo, rode 'affapp --scan-refine %u <novo_valor>'\n", pid);
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[scan!] %s\n", e.what()); return 1;
    }
}

// --scan-refine <pid> <novo_value>
// Filtra candidates carregados do state por igualdade com novo_value.
// Faz RPM de 4 bytes pra cada VA (batch); mantem apenas os que casam.
static int runScanRefine(int argc, char** argv, int startIdx) {
    if (startIdx + 2 >= argc) {
        fprintf(stderr, "uso: affapp.exe --scan-refine <pid> <novo_value> [--state NAME]\n");
        return 2;
    }
    parseStateSlot(argc, argv, startIdx);
    uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[startIdx + 1], nullptr, 0));
    uint32_t newVal = static_cast<uint32_t>(std::strtoul(argv[startIdx + 2], nullptr, 0));

    ScanState state;
    if (!loadScanState(state)) {
        fprintf(stderr, "[refine!] sem state — rode --scan-int32 antes\n"); return 1;
    }
    if (state.pid != pid) {
        fprintf(stderr, "[refine!] state e do PID %u, pediu %u\n", state.pid, pid); return 1;
    }
    printf("[refine] carregou %zu candidates do PID %u\n", state.hits.size(), pid);
    if (state.hits.empty()) { fprintf(stderr, "[refine!] sem candidates\n"); return 1; }

    try {
        DriverComm comm;
        std::vector<uint64_t> survivors;
        survivors.reserve(state.hits.size());
        auto t0 = GetTickCount64();
        for (size_t i = 0; i < state.hits.size(); ++i) {
            try {
                auto buf = comm.readProcessMemory(pid, state.hits[i], 4);
                if (buf.size() == 4) {
                    uint32_t v = 0;
                    memcpy(&v, buf.data(), 4);
                    if (v == newVal) survivors.push_back(state.hits[i]);
                }
            } catch (...) {
                // VA nao mais acessivel (paginas remapeadas etc) — ignora
            }
        }
        auto elapsed = GetTickCount64() - t0;
        printf("[refine] %zu -> %zu candidates em %llums\n",
            state.hits.size(), survivors.size(), elapsed);
        state.hits = std::move(survivors);
        if (!saveScanState(state)) { fprintf(stderr, "[refine!] save falhou\n"); return 1; }
        if (state.hits.size() <= 20) {
            printf("[refine] survivors:\n");
            for (uint64_t va : state.hits) printf("  0x%llX\n", (unsigned long long)va);
        }
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[refine!] %s\n", e.what()); return 1;
    }
}

// --scan-show [--state NAME] — mostra state atual (pid + N primeiros hits).
static int runScanShow(int argc, char** argv, int startIdx) {
    parseStateSlot(argc, argv, startIdx);
    ScanState state;
    if (!loadScanState(state)) { fprintf(stderr, "[show!] sem state\n"); return 1; }
    printf("[state] PID=%u candidates=%zu\n", state.pid, state.hits.size());
    size_t max = state.hits.size() < 50 ? state.hits.size() : 50;
    for (size_t i = 0; i < max; ++i) {
        printf("  [%zu] 0x%llX\n", i, (unsigned long long)state.hits[i]);
    }
    if (state.hits.size() > max) {
        printf("  ... (+%zu ocultos)\n", state.hits.size() - max);
    }
    return 0;
}

// --scan-clear [--state NAME] — apaga state.
static int runScanClear(int argc, char** argv, int startIdx) {
    parseStateSlot(argc, argv, startIdx);
    std::wstring p = scanStatePath();
    if (DeleteFileW(p.c_str())) {
        printf("[clear] state removido\n"); return 0;
    }
    if (GetLastError() == ERROR_FILE_NOT_FOUND) {
        printf("[clear] ja estava vazio\n"); return 0;
    }
    fprintf(stderr, "[clear!] DeleteFile err=%lu\n", GetLastError()); return 1;
}

// --peb <pid> — retorna VA do PEB via PsGetProcessPeb (sem HANDLE).
static int runPebCmd(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --peb <pid>\n"); return 2;
    }
    uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[startIdx + 1], nullptr, 0));
    if (pid == 0) return 2;
    try {
        DriverComm comm;
        uint64_t peb = comm.getProcessPeb(pid);
        printf("[peb] PID=%u PEB=0x%llX\n", pid, (unsigned long long)peb);
        return peb ? 0 : 1;
    } catch (const std::exception& e) {
        fprintf(stderr, "[peb!] %s\n", e.what()); return 1;
    }
}

// --modules <pid>
// Walk PEB->Ldr->InLoadOrderModuleList via RPM. Lista todo modulo carregado
// (nome, DllBase, SizeOfImage). Layout PEB/LDR_DATA_TABLE_ENTRY x64 estavel
// desde Win10 (nao muda entre 22H2/24H2). Limite defensivo: 512 iteracoes.
static int runModulesCmd(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --modules <pid>\n"); return 2;
    }
    uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[startIdx + 1], nullptr, 0));
    if (pid == 0) return 2;

    auto readU64 = [](DriverComm& c, uint32_t p, uint64_t va) -> uint64_t {
        auto b = c.readProcessMemory(p, va, 8);
        if (b.size() != 8) throw std::runtime_error("read u64 falhou");
        uint64_t v = 0; memcpy(&v, b.data(), 8); return v;
    };
    auto readU32 = [](DriverComm& c, uint32_t p, uint64_t va) -> uint32_t {
        auto b = c.readProcessMemory(p, va, 4);
        if (b.size() != 4) throw std::runtime_error("read u32 falhou");
        uint32_t v = 0; memcpy(&v, b.data(), 4); return v;
    };
    auto readU16 = [](DriverComm& c, uint32_t p, uint64_t va) -> uint16_t {
        auto b = c.readProcessMemory(p, va, 2);
        if (b.size() != 2) throw std::runtime_error("read u16 falhou");
        uint16_t v = 0; memcpy(&v, b.data(), 2); return v;
    };

    try {
        DriverComm comm;
        uint64_t peb = comm.getProcessPeb(pid);
        if (!peb) { fprintf(stderr, "[modules!] PEB=0\n"); return 1; }
        printf("[modules] PID=%u PEB=0x%llX\n", pid, (unsigned long long)peb);

        // PEB->Ldr @ +0x18
        uint64_t ldr = readU64(comm, pid, peb + 0x18);
        if (!ldr) { fprintf(stderr, "[modules!] Ldr=0\n"); return 1; }

        // InLoadOrderModuleList.Flink @ Ldr+0x10 (LIST_ENTRY first field)
        uint64_t headVa = ldr + 0x10;
        uint64_t current = readU64(comm, pid, headVa);
        if (!current) { fprintf(stderr, "[modules!] first Flink=0\n"); return 1; }

        printf("%-4s %-18s %-10s %s\n", "#", "DllBase", "Size", "Name");
        int count = 0;
        while (current != headVa && count < 512) {
            // LDR_DATA_TABLE_ENTRY offsets (Win10/11 x64):
            //   +0x30 = DllBase (PVOID)
            //   +0x40 = SizeOfImage (ULONG)
            //   +0x58 = BaseDllName.Length (u16), +0x58+8 = Buffer (PVOID)
            uint64_t entry = current; // InLoadOrderLinks is first field, entry == current
            uint64_t dllBase = 0;
            uint32_t sizeOfImage = 0;
            uint16_t nameLen = 0;
            uint64_t nameBuf = 0;
            try {
                dllBase = readU64(comm, pid, entry + 0x30);
                sizeOfImage = readU32(comm, pid, entry + 0x40);
                nameLen = readU16(comm, pid, entry + 0x58);
                nameBuf = readU64(comm, pid, entry + 0x58 + 8);
            } catch (...) {
                fprintf(stderr, "  [entry %d] read falhou @ 0x%llX\n", count, (unsigned long long)entry);
                break;
            }
            std::string name = "(?)";
            if (nameBuf && nameLen > 0 && nameLen < 512) {
                try {
                    auto nb = comm.readProcessMemory(pid, nameBuf, nameLen);
                    // UTF-16 → ASCII simples (drop bytes altos)
                    name.clear();
                    for (size_t i = 0; i + 1 < nb.size(); i += 2) {
                        uint16_t ch = nb[i] | (nb[i+1] << 8);
                        name.push_back(ch < 0x80 ? static_cast<char>(ch) : '?');
                    }
                } catch (...) { name = "(read fail)"; }
            }
            printf("[%3d] 0x%016llX %8u  %s\n",
                count, (unsigned long long)dllBase, sizeOfImage, name.c_str());
            ++count;
            // Proximo Flink @ current+0x00
            uint64_t next = readU64(comm, pid, current);
            if (!next || next == current) break;
            current = next;
        }
        printf("[modules] total: %d modulos\n", count);
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[modules!] %s\n", e.what()); return 1;
    }
}

// --pib <pid> — Process Image Base. Retorna VA do PE image base via kernel
// PsGetProcessSectionBaseAddress. Sem OpenProcess, sem HANDLE — bypassa
// ObRegisterCallbacks. Util pra ancorar --rpm em processos que negam
// GetProcAddress/QueryModuleInfo.
static int runPib(int argc, char** argv, int startIdx) {
    if (startIdx + 1 >= argc) {
        fprintf(stderr, "uso: affapp.exe --pib <pid>\n");
        return 2;
    }
    uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[startIdx + 1], nullptr, 0));
    if (pid == 0) { fprintf(stderr, "pid invalido\n"); return 2; }
    try {
        DriverComm comm;
        uint64_t base = comm.getProcessImageBase(pid);
        printf("[pib] PID=%u ImageBase=0x%llX\n", pid, (unsigned long long)base);
        return base ? 0 : 1;
    } catch (const std::exception& e) {
        fprintf(stderr, "[pib!] %s\n", e.what()); return 1;
    }
}

// --rpm <pid> <addr_hex|base|base+HEX> <bytes> [--raw]
// Read Process Memory via kernel — usa affctl IOCTL_READ_PROCESS_MEMORY.
// Bypassa ObRegisterCallbacks porque driver usa PsLookupProcessByProcessId
// (sem HANDLE) + KeStackAttachProcess + RtlCopyMemory.
// addr especial:
//   base           = image base do proprio processo (via PsGetProcessSectionBaseAddress)
//   base+0xNNN     = image base + offset hexadecimal
// Default: hexdump. `--raw` escreve binario direto no stdout (redirecionar pra arquivo).
static int runRpm(int argc, char** argv, int startIdx) {
    if (startIdx + 3 >= argc) {
        fprintf(stderr, "uso: affapp.exe --rpm <pid> <addr_hex|base|base+0xNNN> <bytes> [--raw]\n");
        fprintf(stderr, "  ex: affapp.exe --rpm 1234 0x7ff600000000 256\n");
        fprintf(stderr, "  ex: affapp.exe --rpm 1234 base 64      # image base do exe\n");
        fprintf(stderr, "  ex: affapp.exe --rpm 1234 base+0x1000 128\n");
        return 2;
    }
    uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[startIdx + 1], nullptr, 0));
    uint64_t addr = 0;
    const char* addrArg = argv[startIdx + 2];
    // Suporta "base" e "base+0xNNN" resolvendo via IOCTL_GET_PROCESS_BASE.
    if (std::strncmp(addrArg, "base", 4) == 0) {
        try {
            DriverComm resolver;
            uint64_t base = resolver.getProcessImageBase(pid);
            if (base == 0) { fprintf(stderr, "[rpm] image base retornou 0 (proc morto?)\n"); return 1; }
            uint64_t off = 0;
            if (addrArg[4] == '+') off = std::strtoull(addrArg + 5, nullptr, 0);
            addr = base + off;
            printf("[rpm] base=0x%llX  off=0x%llX  addr=0x%llX\n",
                (unsigned long long)base, (unsigned long long)off, (unsigned long long)addr);
        } catch (const std::exception& e) {
            fprintf(stderr, "[rpm] falha ao resolver base: %s\n", e.what()); return 1;
        }
    } else {
        addr = std::strtoull(addrArg, nullptr, 0);
    }
    uint32_t bytes = static_cast<uint32_t>(std::strtoul(argv[startIdx + 3], nullptr, 0));
    bool raw = false;
    const char* outPath = nullptr;
    for (int i = startIdx + 4; i < argc; ++i) {
        if (std::strcmp(argv[i], "--raw") == 0) raw = true;
        else if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc) outPath = argv[++i];
    }

    if (pid == 0 || bytes == 0 || bytes > AFFCTL_RPM_MAX) {
        fprintf(stderr, "[rpm] parametros invalidos (pid=%u bytes=%u max=%u)\n",
                pid, bytes, AFFCTL_RPM_MAX);
        return 2;
    }

    try {
        DriverComm comm;
        // Em --raw stdout eh binario puro; headers vao pra stderr pra nao corromper.
        FILE* logFp = raw ? stderr : stdout;
        fprintf(logFp, "[rpm] PID=%u addr=0x%llX size=%u\n",
               pid, (unsigned long long)addr, bytes);
        auto buf = comm.readProcessMemory(pid, addr, bytes);
        fprintf(logFp, "[rpm] OK - %zu bytes lidos\n", buf.size());

        if (outPath) {
            FILE* fout = nullptr;
            if (fopen_s(&fout, outPath, "wb") != 0 || !fout) {
                fprintf(stderr, "[rpm!] fopen %s falhou\n", outPath); return 1;
            }
            fwrite(buf.data(), 1, buf.size(), fout);
            fclose(fout);
            fprintf(logFp, "[rpm] escrito em %s\n", outPath);
            return 0;
        }
        if (raw) {
            _setmode(_fileno(stdout), _O_BINARY);
            fwrite(buf.data(), 1, buf.size(), stdout);
            fflush(stdout);
            return 0;
        }

        // Hexdump padrao 16 bytes/linha.
        for (size_t off = 0; off < buf.size(); off += 16) {
            printf("  %012llX  ", (unsigned long long)(addr + off));
            size_t line = std::min<size_t>(16, buf.size() - off);
            for (size_t i = 0; i < 16; ++i) {
                if (i < line) printf("%02X ", buf[off + i]); else printf("   ");
                if (i == 7) printf(" ");
            }
            printf(" |");
            for (size_t i = 0; i < line; ++i) {
                uint8_t c = buf[off + i];
                putchar((c >= 0x20 && c < 0x7F) ? c : '.');
            }
            printf("|\n");
        }
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[rpm!] %s\n", e.what());
        return 1;
    }
}

// --status — diagnostico leve. Nao carrega PDB, nao cria janelas, nao acessa
// internet. Reporta:
//   1. driver \\.\AffCtl abre? (CreateFileW succeeds)
//   2. cache OffsetCache existe no Registry? (chave + valores)
// Codigo: 0 se tudo OK, 1 se qualquer check falhou.
static int runStatus() {
    printf("=== affapp status ===\n\n");
    int failures = 0;

    // 1. Driver
    printf("[driver]\n");
    try {
        DriverComm comm;
        printf("  \\\\.\\AffCtl : OK (handle aberto)\n");
    } catch (const std::exception& e) {
        printf("  \\\\.\\AffCtl : FALHA - %s\n", e.what());
        printf("  dica      : rode 'sc query affctl' e 'sc start affctl'.\n");
        printf("              O SDDL restringe a Admin+SYSTEM; execute como Administrador.\n");
        ++failures;
    }

    // 2. OffsetCache (Registry)
    printf("\n[offset cache]\n");
    printf("  chave     : %ls\n", OffsetCache::registryPath());
    auto cached = OffsetCache::load();
    if (cached) {
        printf("  offset    : %u (0x%X)\n", cached->offset, cached->offset);
        printf("  clearMask : 0x%02X\n", cached->clearMask);
        printf("  status    : POPULADO (proximas execucoes pulam discovery)\n");
    } else {
        printf("  status    : VAZIO\n");
        printf("  dica      : rode 'affapp.exe --demo' com driver Debug pra popular.\n");
    }

    printf("\n=== fim status (%s) ===\n", failures ? "com problemas" : "OK");
    return failures ? 1 : 0;
}

// --reset-cache — apaga os valores Offset/ClearMask do Registry (mantem a
// subkey Parameters do servico). Uso: apos update de build do Windows onde
// o offset persistido pode nao mais bater.
static int runResetCache() {
    printf("[reset-cache] apagando %ls\\{Offset,ClearMask}...\n",
           OffsetCache::registryPath());
    if (OffsetCache::clear()) {
        printf("[reset-cache] OK. Proximo --demo (driver Debug) redescobre e regrava.\n");
        return 0;
    }
    fprintf(stderr, "[reset-cache] FALHA - sem privilegio de escrita no Registry.\n");
    fprintf(stderr, "              Execute como Administrador.\n");
    return 1;
}

int main(int argc, char** argv) {
    // Sem args -> mostra help e sai com sucesso (comportamento esperado).
    if (argc < 2) {
        printHelp();
        return 0;
    }

    const char* cmd = argv[1];

    if (std::strcmp(cmd, "--help") == 0 ||
        std::strcmp(cmd, "-h")     == 0 ||
        std::strcmp(cmd, "-?")     == 0) {
        printHelp();
        return 0;
    }
    if (std::strcmp(cmd, "--version") == 0) {
        printVersion();
        return 0;
    }
    if (std::strcmp(cmd, "--status")      == 0) return runStatus();
    if (std::strcmp(cmd, "--reset-cache") == 0) return runResetCache();
    if (std::strcmp(cmd, "--demo")        == 0) return runDemo(argc, argv, 1);
    if (std::strcmp(cmd, "--probe-dwm")   == 0) return probeDwm();
    if (std::strcmp(cmd, "--inject")          == 0) return runInject(argc, argv, 1);
    if (std::strcmp(cmd, "--inject-by-name")  == 0) return runInjectByName(argc, argv, 1);
    if (std::strcmp(cmd, "--watch")           == 0) return runWatch(argc, argv, 1);
    if (std::strcmp(cmd, "--unwatch")         == 0) return runUnwatch(argc, argv, 1);
    if (std::strcmp(cmd, "--global-hook")     == 0) return runGlobalHook(argc, argv, 1);
    if (std::strcmp(cmd, "--capture")         == 0) return runCapture(argc, argv, 1);
    if (std::strcmp(cmd, "--rpm")             == 0) return runRpm(argc, argv, 1);
    if (std::strcmp(cmd, "--pib")             == 0) return runPib(argc, argv, 1);
    if (std::strcmp(cmd, "--peb")             == 0) return runPebCmd(argc, argv, 1);
    if (std::strcmp(cmd, "--modules")         == 0) return runModulesCmd(argc, argv, 1);
    if (std::strcmp(cmd, "--scan-int32")      == 0) return runScanInt32(argc, argv, 1);
    if (std::strcmp(cmd, "--scan-refine")     == 0) return runScanRefine(argc, argv, 1);
    if (std::strcmp(cmd, "--scan-show")       == 0) return runScanShow(argc, argv, 1);
    if (std::strcmp(cmd, "--scan-clear")      == 0) return runScanClear(argc, argv, 1);

    // Comando desconhecido -> mensagem clara + help + exit code 2 (usage error).
    fprintf(stderr, "affapp: comando desconhecido: '%s'\n\n", cmd);
    printHelp();
    return 2;
}
