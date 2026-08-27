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

#include <windows.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>

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

void runDemo(DriverComm& comm) {
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

// --inject <pid> <dll-path> — injecao via APC no kernel. Nao carrega discovery
// nem toca gSharedInfo. So abre o device, resolve TID/LoadLibraryW e chama
// IOCTL_INJECT_DLL. Requer driver ja carregado (sc start affctl).
static int runInject(int argc, char** argv, int startIdx) {
    if (startIdx + 2 >= argc) {
        fprintf(stderr, "uso: affapp.exe --inject <pid> <caminho-da-dll>\n");
        return 2;
    }
    uint32_t pid = static_cast<uint32_t>(std::atoi(argv[startIdx + 1]));
    if (pid == 0) {
        fprintf(stderr, "[inject] PID invalido: %s\n", argv[startIdx + 1]);
        return 2;
    }

    // Converte path ANSI (argv) -> UTF-16.
    const char* pathA = argv[startIdx + 2];
    int wlen = MultiByteToWideChar(CP_ACP, 0, pathA, -1, nullptr, 0);
    if (wlen <= 0) {
        fprintf(stderr, "[inject] falha ao converter path\n");
        return 2;
    }
    std::wstring pathW(wlen - 1, L'\0'); // -1 pra tirar o NUL contado
    MultiByteToWideChar(CP_ACP, 0, pathA, -1, pathW.data(), wlen);

    try {
        DriverComm comm; // abre \\.\AffCtl
        uint64_t addr = Injector::loadLibraryWAddr();
        auto tids = Injector::enumThreadIds(pid);
        if (tids.empty()) {
            throw std::runtime_error("nenhuma thread encontrada para o PID " + std::to_string(pid));
        }
        printf("[inject] pid=%u threads=%zu LoadLibraryW=0x%llX\n",
               pid, tids.size(), (unsigned long long)addr);
        printf("[inject] dll=%s\n", pathA);
        printf("[inject] enfileirando APC em TODAS as threads (shotgun):\n");
        int okCount = 0, failCount = 0;
        for (uint32_t tid : tids) {
            try {
                Injector::inject(comm, pid, tid, addr, pathW);
                ++okCount;
                printf("  tid=%-6u OK\n", tid);
            } catch (const std::exception& e) {
                ++failCount;
                printf("  tid=%-6u FALHOU: %s\n", tid, e.what());
            }
        }
        printf("[inject] APC enfileirada em %d/%zu threads. Aguardando ate 15s...\n",
               okCount, tids.size());

        // Extrai basename do path (ex: "hellodll.dll").
        const wchar_t* base = wcsrchr(pathW.c_str(), L'\\');
        base = base ? base + 1 : pathW.c_str();
        bool loaded = false;
        for (int i = 0; i < 75 && !loaded; ++i) {
            Sleep(200);
            loaded = Injector::hasModuleLoaded(pid, base);
        }
        if (loaded) {
            printf("[inject] OK — DLL '%ls' aparece nos modulos do PID %u.\n",
                   base, pid);
        } else {
            printf("[inject] AVISO: DLL '%ls' NAO apareceu nos modulos do PID %u em 15s.\n",
                   base, pid);
            printf("[inject] Verifique %%TEMP%%\\hellodll_loaded.txt no PROCESSO ALVO:\n");
            printf("         se existir -> DllMain rodou, so a enumeracao de modulos falhou.\n");
            printf("         se nao existir -> APC nao disparou ou LoadLibraryW falhou.\n");
        }
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[inject] erro: %s\n", e.what());
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

int main(int argc, char** argv) {
    bool guard = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--guard") == 0) guard = true;
        if (std::strcmp(argv[i], "--probe-dwm") == 0) return probeDwm();
        if (std::strcmp(argv[i], "--inject") == 0)   return runInject(argc, argv, i);
        if (std::strcmp(argv[i], "--capture") == 0)  return runCapture(argc, argv, i);
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

        // --- Discovery ---
        printf("[discovery] descobrindo offset da flag DisplayAffinity...\n");
        OffsetFinder::Result found;
        {
            // Probe VISIVEL: em Win11 25H2+ o DWM parece so refletir WDA na
            // tagWND para janelas efetivamente mostradas ao compositor.
            TestWindow probe(/*visible=*/true, L"AffCtl PROBE");
            for (int i = 0; i < 10; ++i) { probe.pump(); Sleep(30); }
            found = OffsetFinder::findOffset(comm, probe.hwnd(), 8192);
        }
        printf("[discovery] offset=%u (0x%X) mask=0x%02X\n",
               found.offset, found.offset, found.clearMask);
        comm.setOffset(found.offset, found.clearMask);

        // --- Demo ---
        runDemo(comm);

        // --- Guard (opcional) ---
        if (guard) {
            TestWindow g(/*visible=*/true, L"AffCtl GUARD");
            g.setAffinity(WDA_EXCLUDEFROMCAPTURE);
            comm.clearAffinity(g.hwnd());
            runGuard(comm, g.hwnd());
        }

        printf("[main] concluido.\n");
        return 0;
    } catch (const std::exception& e) {
        fprintf(stderr, "[erro] %s\n", e.what());
        return 1;
    }
}
