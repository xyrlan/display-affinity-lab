// main.cpp
// affapp.exe — orquestra: discovery do offset -> demo (clear + prova visual) ->
// guard opcional (cabo-de-guerra contra reaplicacao).
//
// Escopo: opera SO sobre janelas criadas pelo proprio app (TestWindow).
#include "DriverComm.hpp"
#include "TestWindow.hpp"
#include "OffsetFinder.hpp"
#include "BmpCapture.hpp"

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

void runDemo(DriverComm& comm) {
    // Janela visivel com conteudo distintivo.
    TestWindow demo(/*visible=*/true, L"AffCtl DEMO");
    HWND h = demo.hwnd();

    // Aplica protecao — a partir daqui, capturas de tela mostram preto.
    demo.setAffinity(WDA_EXCLUDEFROMCAPTURE);
    for (int i = 0; i < 10; ++i) { demo.pump(); Sleep(50); }

    uint8_t before = comm.readAffinity(h);
    printf("[demo] affinity antes do clear = 0x%02X (esperado 0x11)\n", before);
    BmpCapture::captureWindow(h, "before.bmp");
    printf("[demo] captura salva: before.bmp\n");

    // Driver zera a flag na tagWND.
    comm.clearAffinity(h);
    for (int i = 0; i < 10; ++i) { demo.pump(); Sleep(50); }

    uint8_t after = comm.readAffinity(h);
    printf("[demo] affinity apos clear  = 0x%02X (esperado 0x00)\n", after);
    BmpCapture::captureWindow(h, "after.bmp");
    printf("[demo] captura salva: after.bmp\n");

    if (before == WDA_EXCLUDEFROMCAPTURE && after == WDA_NONE) {
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
                if (v != WDA_NONE) {
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

int main(int argc, char** argv) {
    bool guard = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--guard") == 0) guard = true;
    }

    try {
        DriverComm comm; // abre \\.\AffCtl (lanca se driver nao carregado)

        // --- Discovery ---
        printf("[discovery] descobrindo offset da flag DisplayAffinity...\n");
        uint32_t offset;
        {
            TestWindow probe(/*visible=*/false, L"AffCtl PROBE");
            offset = OffsetFinder::findOffset(comm, probe.hwnd(), 512);
        }
        printf("[discovery] offset encontrado = %u (0x%X)\n", offset, offset);
        comm.setOffset(offset);

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
