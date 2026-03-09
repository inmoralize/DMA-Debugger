#include "app.hpp"
#include <windows.h>

int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    dma::App app;
    app.run();
    return 0;
}
