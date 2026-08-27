// Version.hpp
// Versao string do affapp.exe — atualize a cada release pra facilitar triagem
// de suporte pos-assinatura. `--version` imprime este valor + timestamp de build.
#pragma once

#define AFFAPP_VERSION      "1.0.0"
#define AFFAPP_BUILD_STAMP  __DATE__ " " __TIME__
