// ============================================================================
// ZerpexPS5 — Launcher v0.6 (библиотека игр в стиле PS5)
//
// Что есть:    окно, DX11-рендер, ImGui, PS5-тема, библиотека игр (скан
//              папок, param.json, обложки через WIC), выбор игры ставит её
//              обложку на фон, games.json рядом с EXE.
// Новое v0.6:  кнопки "Открыть лог" и "Папка игры", размер res.pak в шапке,
//              запоминание последней запущенной игры, запуск по Enter и
//              двойному клику, версия ядра в интерфейсе.
// Новое v0.5:  версии ядра и лаунчера — в src/version.h (ядро 0.8.2:
//              GPU-демо, сплаш "иконка игры + RUNNED WITH ZerpexPS5",
//              транслятор RDNA2->SPIR-V).
// Новое v0.4:  клик по аватарке выезжает панель настроек (settings.json):
//              выбор видеокарты для эмуляции (честное перечисление через
//              vulkan-1.dll, без линковки), доп. параметры запуска ядра,
//              прямой запуск любого ELF-файла с этими параметрами. Ядру
//              передаётся "--gpu <N>" — приоритет карты (gpu_vk.cpp).
// Новое v0.3:  честные бейджи состояния дампа (ELF / SELF открыт / SELF
//              зашифрован — по энтропии сегментов) и кнопка «Запустить»,
//              которая передаёт путь игры ядру ZerpexPS5.exe (фаза 3).
// Чего нет:    исполнение retail-SELF (фаза 7), рендер игр (фаза 5.1+).
//
// ПРАВИЛА ХОЗЯИНА ПРОЕКТА:
//   1. Ничего не скачивать через PowerShell.
//   2. Работать только внутри D:\ZerpexPS5.
//   3. Собранный EXE НЕ запускать — тесты делает хозяин.
// ============================================================================

#include <windows.h>
#include <shellapi.h>
#include <objbase.h>
#include <d3d11.h>
#include <dxgi.h>
#include <shobjidl.h>

#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include "../core/log.h"
#include "../core/game.h"
#include "../core/texture.h"
#include "../version.h"

// Хедеры Vulkan нужны только для перечисления видеокарт в настройках;
// грузим DLL динамически, линковки нет. Если SDK нет при сборке —
// выбор карты честно отключается (__has_include).
#if defined(__has_include)
#  if __has_include(<vulkan/vulkan.h>)
#    include <vulkan/vulkan.h>
#    define ZRX_VK_HEADERS 1
#  endif
#endif

// В ImGui 1.93 эта функция объявлена внутри '#if 0' — так задумано:
// приложение само дублирует объявление (см. imgui_impl_win32.h).
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ----------------------------------------------------------------------------
// Глобальное состояние окна и рендера
// ----------------------------------------------------------------------------
static HWND g_hwnd = nullptr;
static ID3D11Device* g_dev = nullptr;
static ID3D11DeviceContext* g_ctx = nullptr;
static IDXGISwapChain* g_swap = nullptr;
static ID3D11RenderTargetView* g_rtv = nullptr;

static bool g_imgui_ready = false;
static bool g_running = true;
static ImFont* g_font = nullptr;       // основной, 22px (кириллица)
static ImFont* g_font_title = nullptr; // крупный, 34px (логотип)
static ImFont* g_font_big = nullptr;   // очень крупный, 48px (название игры)

static std::vector<zrx::Game> g_games; // библиотека
static int g_selected = -1;            // выбранная игра (обложка на фоне), -1 = главная

// --- Настройки лаунчера (settings.json рядом с EXE) — v0.4 -------------------
static int     g_gpuIndex = -1;            // приоритет видеокарты, -1 = авто
static char    g_coreArgs[256] = {};       // доп. параметры командной строки ядра
static wchar_t g_elfPath[MAX_PATH] = {};   // ELF для прямого запуска
static char    g_lastGame[1024] = {};      // UTF-8 root последней запущенной игры
static float   g_setAnim = 0.0f;           // анимация панели настроек, 0..1
static bool    g_setOpen = false;
static std::vector<std::string> g_gpus;    // имена карт (порядок перечисления Vulkan)

// Палитра (PS blue #0070D1)
static const ImU32 ACCENT     = IM_COL32(0, 112, 209, 255);
static const ImU32 ACCENT_DIM = IM_COL32(0, 112, 209, 110);
static const ImU32 COL_WHITE  = IM_COL32(235, 242, 250, 255);
static const ImU32 COL_DIM    = IM_COL32(120, 140, 170, 255);
static const ImU32 COL_AMBER  = IM_COL32(230, 170, 60, 255);
static const ImU32 COL_GREEN  = IM_COL32(90, 220, 150, 255);

// ----------------------------------------------------------------------------
// Утилиты
// ----------------------------------------------------------------------------
static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)(n > 0 ? n : 0), '\0');
    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)(n > 0 ? n : 0), L'\0');
    if (n > 0)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

static std::wstring ExeDir() {
    wchar_t buf[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring p(buf);
    size_t s = p.find_last_of(L"\\/");
    return s == std::wstring::npos ? std::wstring(L".") : p.substr(0, s);
}

// Человеческий размер файла — для статуса res.pak в шапке.
static std::string HumanSize(uint64_t n) {
    char b[64];
    if (n >= (1ull << 30))      snprintf(b, sizeof(b), "%.2f GB", (double)n / (double)(1ull << 30));
    else if (n >= (1ull << 20)) snprintf(b, sizeof(b), "%.1f MB", (double)n / (double)(1ull << 20));
    else if (n >= 1024)         snprintf(b, sizeof(b), "%.1f KB", (double)n / 1024.0);
    else                        snprintf(b, sizeof(b), "%llu B", (unsigned long long)n);
    return b;
}

// "res.pak 1.96 GB" или "res.pak НЕТ" — быстрый честный статус файлов игры.
static std::string ResPakStatus(const zrx::Game& g) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    const std::wstring p = g.root + L"\\res.pak";
    if (!GetFileAttributesExW(p.c_str(), GetFileExInfoStandard, &fad))
        return "res.pak НЕТ";
    const uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    return "res.pak " + HumanSize(sz);
}

// Шапка рисуется каждый кадр — не дёргаем ФС 60 раз в секунду.
static const std::string& ResPakStatusCached(const zrx::Game& g) {
    static std::wstring cachedRoot;
    static std::string  cachedText;
    if (cachedRoot != g.root) {
        cachedRoot = g.root;
        cachedText = ResPakStatus(g);
    }
    return cachedText;
}

// Открыть папку/файл в проводнике. Для файла — с выделением.
static void OpenInExplorer(const std::wstring& path, bool select) {
    if (select && GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) {
        const std::wstring args = L"/select,\"" + path + L"\"";
        ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
        return;
    }
    if (select) {
        const size_t s = path.find_last_of(L"\\/");
        if (s != std::wstring::npos) {
            ShellExecuteW(nullptr, L"open", path.substr(0, s).c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            return;
        }
    }
    ShellExecuteW(nullptr, L"open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

static void OpenCoreLog() {
    OpenInExplorer(ExeDir() + L"\\zerpex_log.txt", true);
}

static void OpenSelectedGameFolder() {
    if (g_selected >= 0 && g_selected < (int)g_games.size())
        OpenInExplorer(g_games[(size_t)g_selected].root, false);
}

// Системный диалог выбора папки (чистый WinAPI/COM, без новых зависимостей)
static bool PickFolder(HWND owner, std::wstring& out_path) {
    IFileDialog* dlg = nullptr;
    bool ok = false;
    if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_PPV_ARGS(&dlg))) && dlg) {
        DWORD opts = 0;
        if (SUCCEEDED(dlg->GetOptions(&opts)))
            dlg->SetOptions(opts | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
        dlg->SetTitle(L"Выберите папку с игрой или дампом");
        if (dlg->Show(owner) == S_OK) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dlg->GetFolder(&item)) && item) {
                PWSTR wpath = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &wpath)) && wpath) {
                    out_path = wpath;
                    ok = true;
                    CoTaskMemFree(wpath);
                }
                item->Release();
            }
        }
        dlg->Release();
    }
    return ok;
}

// Диалог выбора ФАЙЛА — для прямого запуска ELF из настроек (v0.4)
static bool PickFile(HWND owner, wchar_t* buf, size_t bufn) {
    IFileOpenDialog* dlg = nullptr;
    bool ok = false;
    if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_INPROC_SERVER,
                                   IID_PPV_ARGS(&dlg))) && dlg) {
        static const COMDLG_FILTERSPEC kFilters[] = {
            { L"ELF / SELF PS5", L"*.elf;*.bin;*.self;*.eboot*" },
            { L"Все файлы",      L"*.*" },
        };
        dlg->SetFileTypes(2, kFilters);
        dlg->SetTitle(L"Выберите ELF для прямого запуска");
        DWORD opts = 0;
        if (SUCCEEDED(dlg->GetOptions(&opts)))
            dlg->SetOptions(opts | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST);
        if (dlg->Show(owner) == S_OK) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(dlg->GetResult(&item)) && item) {
                PWSTR wpath = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &wpath)) && wpath) {
                    if (wcslen(wpath) + 1 <= bufn) {
                        wcscpy_s(buf, bufn, wpath);
                        ok = true;
                    } else {
                        zrx::Log::warn("Путь слишком длинный");
                    }
                    CoTaskMemFree(wpath);
                }
                item->Release();
            }
        }
        dlg->Release();
    }
    return ok;
}

// Добавить игры из выбранной папки
static void AddGamesFromFolder(const std::wstring& path) {
    std::vector<zrx::Game> found = zrx::ScanForGames(path);
    int added = 0, dup = 0;
    for (const zrx::Game& g : found) {
        bool exists = false;
        for (const zrx::Game& e : g_games) {
            if (_wcsicmp(e.root.c_str(), g.root.c_str()) == 0) { exists = true; break; }
        }
        if (!exists) { g_games.push_back(g); ++added; }
        else ++dup;
    }
    zrx::SaveGames(ExeDir() + L"\\games.json", g_games);

    if (added > 0)
        zrx::Log::info("Добавлено игр: %d%s", added, dup > 0 ? " (некоторые уже были)" : "");
    else if (dup > 0)
        zrx::Log::warn("Новеньких нет — всё уже в библиотеке");
    else
        zrx::Log::warn("Игры PS5 не найдены: ищу eboot.bin или sce_sys\\param.json");
}

static void SaveSettings();   // определена ниже; нужна для запоминания игры

// Запуск ядра: путь ELF/игры + приоритет карты и доп. параметры из настроек
static void LaunchCorePath(const std::wstring& target) {
    const std::wstring exe = ExeDir() + L"\\ZerpexPS5.exe";
    std::wstring cmd = L"\"" + exe + L"\" \"" + target + L"\"";
    if (g_gpuIndex >= 0)
        cmd += L" --gpu " + std::to_wstring(g_gpuIndex);
    if (g_coreArgs[0]) {
        cmd += L" ";
        cmd += ToWide(g_coreArgs);            // параметры пользователь пишет сам
    }

    STARTUPINFOW si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};
    const BOOL ok = CreateProcessW(nullptr, &cmd[0], nullptr, nullptr, FALSE,
                                   CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi);
    if (ok) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        zrx::Log::info("Ядро запущено: %s", ToUtf8(target).c_str());
    } else {
        zrx::Log::error("CreateProcess не удался (код %lu)", (unsigned long)GetLastError());
    }
}

// Фаза 3: передать игру ядру ZerpexPS5.exe в новой консоли (с настройками v0.4)
static void LaunchCore(const zrx::Game& g) {
    if (g.eboot_path.empty()) {
        zrx::Log::warn("У игры нет eboot — запускать нечего");
        return;
    }
    const std::string root = ToUtf8(g.root);
    if (root.size() < sizeof(g_lastGame)) {
        strcpy_s(g_lastGame, root.c_str());
        SaveSettings();
    }
    LaunchCorePath(g.eboot_path);
}

// ----------------------------------------------------------------------------
// Настройки (settings.json) — v0.4
// ----------------------------------------------------------------------------
static std::wstring SettingsFile() { return ExeDir() + L"\\settings.json"; }

static void SaveSettings() {
    std::ofstream f(SettingsFile().c_str(), std::ios::binary | std::ios::trunc);
    if (!f) return;
    auto esc = [](const std::string& s) {
        std::string o;
        char b[8];
        for (char c : s) {
            if (c == '"' || c == '\\') { o += '\\'; o += c; }
            else if ((unsigned char)c < 0x20) { snprintf(b, sizeof(b), "\\u%04X", c); o += b; }
            else o += c;
        }
        return o;
    };
    f << "{\n";
    f << "  \"gpuIndex\": " << g_gpuIndex << ",\n";
    f << "  \"coreArgs\": \"" << esc(g_coreArgs) << "\",\n";
    f << "  \"elfPath\": \"" << esc(ToUtf8(g_elfPath)) << "\",\n";
    f << "  \"lastGame\": \"" << esc(g_lastGame) << "\"\n";
    f << "}\n";
}

static void LoadSettings() {
    std::ifstream f(SettingsFile().c_str(), std::ios::binary);
    if (!f) return;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string src = ss.str();

    auto findInt = [&](const char* key, int def) {
        const std::string k = std::string("\"") + key + "\"";
        const size_t p = src.find(k);
        if (p == std::string::npos) return def;
        const size_t c = src.find(':', p + k.size());
        if (c == std::string::npos) return def;
        return atoi(src.c_str() + c + 1);
    };
    auto findStr = [&](const char* key, std::string& out) {
        out.clear();                       // ключа может не быть в старом settings.json
        const std::string k = std::string("\"") + key + "\"";
        size_t p = src.find(k);
        if (p == std::string::npos) return;
        p = src.find('"', p + k.size());
        if (p == std::string::npos) return;
        for (size_t i = p + 1; i < src.size(); ++i) {
            const char c = src[i];
            if (c == '\\' && i + 1 < src.size()) {
                const char n = src[++i];
                if (n == 'n') { out += '\n'; continue; }
                out += n;                 // \" и \\ — как есть
                continue;
            }
            if (c == '"') break;
            out += c;
        }
    };

    g_gpuIndex = findInt("gpuIndex", -1);
    std::string s;
    findStr("coreArgs", s);
    if (s.size() >= sizeof(g_coreArgs)) s.resize(sizeof(g_coreArgs) - 1);
    strcpy_s(g_coreArgs, s.c_str());
    findStr("elfPath", s);
    const std::wstring w = ToWide(s);
    if (w.size() + 1 <= (size_t)MAX_PATH) wcscpy_s(g_elfPath, w.c_str());
    findStr("lastGame", s);
    if (s.size() >= sizeof(g_lastGame)) s.resize(sizeof(g_lastGame) - 1);
    strcpy_s(g_lastGame, s.c_str());
}

// Честное перечисление видеокарт через vulkan-1.dll (без линковки) — v0.4.
// Порядок совпадает с тем, что увидит ядро; ядро берёт карту по индексу --gpu.
static void EnumerateGpus() {
    g_gpus.clear();
#ifdef ZRX_VK_HEADERS
    const HMODULE dll = LoadLibraryW(L"vulkan-1.dll");
    if (!dll) {
        g_gpus.push_back("(vulkan-1.dll не найден — кадры выводиться не будут)");
        return;
    }
    const auto gpia = (PFN_vkGetInstanceProcAddr)GetProcAddress(dll, "vkGetInstanceProcAddr");
    if (!gpia) { g_gpus.push_back("(vulkan-1.dll повреждён)"); FreeLibrary(dll); return; }
    PFN_vkCreateInstance pCi = (PFN_vkCreateInstance)gpia(nullptr, "vkCreateInstance");
    if (!pCi) { g_gpus.push_back("(vulkan-1.dll без vkCreateInstance)"); FreeLibrary(dll); return; }

    VkApplicationInfo app { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    app.pApplicationName = "ZerpexPS5 Launcher v" ZERPEX_LAUNCHER_VERSION;
    app.apiVersion = VK_API_VERSION_1_0;
    VkInstanceCreateInfo ci { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    ci.pApplicationInfo = &app;

    VkInstance inst = VK_NULL_HANDLE;
    if (pCi(&ci, nullptr, &inst) != VK_SUCCESS) {
        g_gpus.push_back("(vkCreateInstance не удался — Vulkan недоступен)");
        FreeLibrary(dll);
        return;
    }
    // vkDestroyInstance — функция УРОВНЯ instance: глобально (с NULL-инстансом)
    // загрузчик её не отдаёт, поэтому берём только ПОСЛЕ создания instance.
    PFN_vkDestroyInstance pDi =
        (PFN_vkDestroyInstance)gpia(inst, "vkDestroyInstance");
    PFN_vkEnumeratePhysicalDevices pEn =
        (PFN_vkEnumeratePhysicalDevices)gpia(inst, "vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceProperties pPr =
        (PFN_vkGetPhysicalDeviceProperties)gpia(inst, "vkGetPhysicalDeviceProperties");
    if (pEn && pPr) {
        uint32_t n = 0;
        pEn(inst, &n, nullptr);
        if (n == 0)
            g_gpus.push_back("(видеоустройств не найдено — типично для ВМ без 3D)");
        std::vector<VkPhysicalDevice> devs(n);
        if (n && pEn(inst, &n, devs.data()) == VK_SUCCESS)
            for (uint32_t i = 0; i < n; ++i) {
                VkPhysicalDeviceProperties props;
                pPr(devs[i], &props);
                g_gpus.push_back(props.deviceName);
            }
    } else {
        g_gpus.push_back("(функции перечисления не найдены)");
    }
    if (pDi) pDi(inst, nullptr);
    FreeLibrary(dll);
#else
    g_gpus.push_back("(SDK-хедеры Vulkan не найдены при сборке)");
#endif
}

// ----------------------------------------------------------------------------
// D3D11
// ----------------------------------------------------------------------------
static bool CreateRtv() {
    ID3D11Texture2D* bb = nullptr;
    if (FAILED(g_swap->GetBuffer(0, IID_PPV_ARGS(&bb))) || !bb)
        return false;
    HRESULT hr = g_dev->CreateRenderTargetView(bb, nullptr, &g_rtv);
    bb->Release();
    return SUCCEEDED(hr);
}

static void ResizeTargets(int w, int h) {
    if (!g_swap || !g_dev || w <= 0 || h <= 0) return;
    if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
    if (FAILED(g_swap->ResizeBuffers(0, (UINT)w, (UINT)h, DXGI_FORMAT_UNKNOWN, 0)))
        return;
    CreateRtv();
}

static bool InitD3D(HWND hwnd) {
    DXGI_SWAP_CHAIN_DESC scd = {};
    scd.BufferCount = 2;
    scd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    scd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    scd.OutputWindow = hwnd;
    scd.SampleDesc.Count = 1;
    scd.Windowed = TRUE;
    scd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    HRESULT hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                                               0, nullptr, 0, D3D11_SDK_VERSION,
                                               &scd, &g_swap, &g_dev, nullptr, &g_ctx);
    if (FAILED(hr)) {
        zrx::Log::error("D3D11: не удалось создать устройство (HRESULT=0x%08lX)", (unsigned long)hr);
        return false;
    }

    RECT rc = {};
    GetClientRect(hwnd, &rc);
    if (!CreateRtv()) {
        zrx::Log::error("D3D11: не удалось создать render target view");
        return false;
    }
    zrx::Log::info("D3D11: устройство создано, буфер %ux%u", (unsigned)rc.right, (unsigned)rc.bottom);
    return true;
}

static void ShutdownD3D() {
    zrx::ReleaseTextures();
    if (g_rtv)  { g_rtv->Release();  g_rtv = nullptr; }
    if (g_swap) { g_swap->Release(); g_swap = nullptr; }
    if (g_ctx)  { g_ctx->Release();  g_ctx = nullptr; }
    if (g_dev)  { g_dev->Release();  g_dev = nullptr; }
}

// ----------------------------------------------------------------------------
// Шрифт и стиль (PS5-палитра)
// ----------------------------------------------------------------------------
static void LoadFonts() {
    ImGuiIO& io = ImGui::GetIO();

    // Segoe UI есть на любой Windows Vista+; грузим с кириллицей,
    // иначе русский текст рисуется знаками "?"
    wchar_t windir[MAX_PATH] = L"C:\\Windows";
    GetWindowsDirectoryW(windir, MAX_PATH);
    std::wstring font_path = std::wstring(windir) + L"\\Fonts\\segoeui.ttf";
    // Кириллица + нужные нам глифы (▶ ✓ ✕ ·) — иначе будут "?" в кнопках.
    static const ImWchar ranges[] = {
        0x0020, 0x00FF,   // латиница + пунктуация
        0x2013, 0x2014,   // – —
        0x2018, 0x201F,   // кавычки
        0x2022, 0x2022,   // •
        0x25B6, 0x25B6,   // ▶
        0x2713, 0x2713,   // ✓
        0x2715, 0x2715,   // ✕
        0x0400, 0x052F,   // кириллица
        0x2DE0, 0x2DFF,   // кириллица расширенная
        0xA640, 0xA69F,   // кириллица историческая
        0,
    };

    g_font = io.Fonts->AddFontFromFileTTF(ToUtf8(font_path).c_str(), 22.0f, nullptr, ranges);
    if (!g_font) {
        zrx::Log::warn("Segoe UI не найден — используется встроенный шрифт");
        g_font = io.Fonts->AddFontDefault();
    }
    g_font_title = io.Fonts->AddFontFromFileTTF(ToUtf8(font_path).c_str(), 34.0f, nullptr, ranges);
    if (!g_font_title) g_font_title = g_font;
    g_font_big = io.Fonts->AddFontFromFileTTF(ToUtf8(font_path).c_str(), 48.0f, nullptr, ranges);
    if (!g_font_big) g_font_big = g_font_title;
}

static void ApplyPS5Style() {
    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowRounding    = 10.0f;
    s.PopupRounding     = 12.0f;
    s.FrameRounding     = 8.0f;
    s.GrabRounding      = 6.0f;
    s.ScrollbarRounding = 8.0f;
    s.FramePadding      = ImVec2(12, 9);
    s.ItemSpacing       = ImVec2(12, 10);
    s.WindowPadding     = ImVec2(16, 14);

    const ImVec4 text  (0.92f, 0.94f, 0.98f, 1.00f);
    const ImVec4 dim   (0.55f, 0.60f, 0.68f, 1.00f);
    const ImVec4 panel (0.06f, 0.08f, 0.12f, 0.94f);
    const ImVec4 panel2(0.09f, 0.11f, 0.16f, 1.00f);

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text]             = text;
    c[ImGuiCol_TextDisabled]     = dim;
    c[ImGuiCol_WindowBg]         = panel;
    c[ImGuiCol_ChildBg]          = panel;
    c[ImGuiCol_PopupBg]          = ImVec4(0.05f, 0.07f, 0.11f, 0.97f);
    c[ImGuiCol_Border]           = ImVec4(0.20f, 0.30f, 0.45f, 0.40f);
    c[ImGuiCol_Separator]        = ImVec4(0.00f, 0.44f, 0.82f, 0.35f);
    c[ImGuiCol_Button]           = panel2;
    c[ImGuiCol_ButtonHovered]    = ImVec4(0.02f, 0.30f, 0.60f, 1.00f);
    c[ImGuiCol_ButtonActive]     = ImVec4(0.00f, 0.44f, 0.82f, 1.00f);
    c[ImGuiCol_ModalWindowDimBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.60f);
    c[ImGuiCol_TitleBg]          = panel;
    c[ImGuiCol_TitleBgActive]    = panel2;
}

// ----------------------------------------------------------------------------
// Плитки
// ----------------------------------------------------------------------------
static bool TileAdd(const ImVec2& pos, float size) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGui::SetCursorScreenPos(pos);
    bool pressed = ImGui::InvisibleButton("##add_game", ImVec2(size, size));
    bool hovered = ImGui::IsItemHovered();
    bool held    = ImGui::IsItemActive();

    const float lift = hovered ? -5.0f : 0.0f;
    const ImVec2 p(pos.x, pos.y + lift);

    ImU32 fill   = hovered ? IM_COL32(6, 64, 120, 255) : IM_COL32(16, 22, 34, 255);
    if (held) fill = IM_COL32(4, 50, 95, 255);
    const ImU32 border = hovered ? ACCENT : IM_COL32(48, 66, 94, 130);

    dl->AddRectFilled(ImVec2(p.x + 4, p.y + size + 2), ImVec2(p.x + size - 4, p.y + size + 8),
                      IM_COL32(0, 0, 0, 70), 10.0f);
    dl->AddRectFilled(p, ImVec2(p.x + size, p.y + size), fill, 14.0f);
    dl->AddRect(p, ImVec2(p.x + size, p.y + size), border, 14.0f);

    const float cx = p.x + size * 0.5f;
    const ImVec2 plus_sz = g_font_title->CalcTextSizeA(36.0f, FLT_MAX, 0.0f, "+");
    dl->AddText(g_font_title, 36.0f, ImVec2(cx - plus_sz.x * 0.5f, p.y + size * 0.16f),
                IM_COL32(150, 195, 255, 255), "+");

    const char* label = "Добавить\nигру";
    const ImVec2 label_sz = g_font->CalcTextSizeA(22.0f, FLT_MAX, 0.0f, label);
    dl->AddText(g_font, 22.0f, ImVec2(cx - label_sz.x * 0.5f, p.y + size * 0.56f),
                COL_WHITE, label);

    return pressed;
}

static void TileGhost(const ImVec2& pos, float size, const char* label) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(pos, ImVec2(pos.x + size, pos.y + size), IM_COL32(12, 16, 24, 110), 14.0f);
    dl->AddRect(pos, ImVec2(pos.x + size, pos.y + size), IM_COL32(60, 80, 110, 55), 14.0f);
    if (label && label[0]) {
        const ImVec2 ls = g_font->CalcTextSizeA(18.0f, FLT_MAX, 0.0f, label);
        dl->AddText(g_font, 18.0f,
                    ImVec2(pos.x + (size - ls.x) * 0.5f, pos.y + (size - ls.y) * 0.5f),
                    IM_COL32(90, 105, 130, 160), label);
    }
}

// Плитка игры с обложкой; возвращает true по клику
static bool TileGame(int idx, const ImVec2& pos, float size) {
    const zrx::Game& g = g_games[(size_t)idx];
    zrx::Texture* tex = zrx::GetTexture(g_dev, g.icon);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImGui::SetCursorScreenPos(pos);

    char id[32];
    snprintf(id, sizeof(id), "##game%d", idx);
    bool pressed = ImGui::InvisibleButton(id, ImVec2(size, size));
    bool hovered = ImGui::IsItemHovered();

    const float lift = hovered ? -5.0f : 0.0f;
    const ImVec2 p(pos.x, pos.y + lift);

    dl->AddRectFilled(ImVec2(p.x + 4, p.y + size + 2), ImVec2(p.x + size - 4, p.y + size + 8),
                      IM_COL32(0, 0, 0, 70), 10.0f);

    if (tex && tex->srv) {
        // обложка + затемнение снизу + название
        dl->AddImage((ImTextureID)tex->srv, p, ImVec2(p.x + size, p.y + size));
        dl->AddRectFilledMultiColor(p, ImVec2(p.x + size, p.y + size),
                                    IM_COL32(0, 0, 0, 0), IM_COL32(0, 0, 0, 0),
                                    IM_COL32(0, 0, 0, 170), IM_COL32(0, 0, 0, 170));
        dl->AddText(g_font, 15.0f, ImVec2(p.x + 8, p.y + size - 23), COL_WHITE,
                    g.title.c_str(), nullptr, size - 16);
    } else {
        dl->AddRectFilled(p, ImVec2(p.x + size, p.y + size), IM_COL32(16, 22, 34, 255), 14.0f);
        dl->AddText(g_font, 16.0f, ImVec2(p.x + 10, p.y + 12), COL_WHITE,
                    g.title.c_str(), nullptr, size - 20);
        const char* st;
        ImU32 col;
        if (g.eboot == "elf")                 { st = "[ELF]";    col = COL_GREEN; }
        else if (g.self_state == "self-open") { st = "[SELF ✓]"; col = COL_GREEN; }
        else                                  { st = "[SELF]";   col = COL_AMBER; }
        dl->AddText(g_font, 15.0f, ImVec2(p.x + 10, p.y + size - 24), col, st);
    }

    if (idx == g_selected)
        dl->AddRect(p, ImVec2(p.x + size, p.y + size), ACCENT, 14.0f, 0, 3.0f);
    else if (hovered)
        dl->AddRect(p, ImVec2(p.x + size, p.y + size), IM_COL32(150, 195, 255, 200), 14.0f, 0, 2.0f);

    return pressed;
}

// ----------------------------------------------------------------------------
// Фон главной страницы / выбранной игры
// ----------------------------------------------------------------------------
static void DrawBackdrop(const ImVec2& disp) {
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    if (g_selected >= 0 && g_selected < (int)g_games.size()) {
        const zrx::Game& g = g_games[(size_t)g_selected];
        zrx::Texture* tex = zrx::GetTexture(g_dev, g.icon);

        if (tex && tex->srv && tex->w > 0 && tex->h > 0) {
            // cover-fit: растягиваем с сохранением пропорций, края уходят за экран
            const float sx = disp.x / (float)tex->w;
            const float sy = disp.y / (float)tex->h;
            const float sc = sx > sy ? sx : sy;
            const float dw = (float)tex->w * sc;
            const float dh = (float)tex->h * sc;
            const float ox = (dw - disp.x) * 0.5f;
            const float oy = (dh - disp.y) * 0.5f;
            dl->AddImage((ImTextureID)tex->srv,
                         ImVec2(-ox, -oy), ImVec2(disp.x + ox, disp.y + oy));
        } else {
            dl->AddRectFilledMultiColor(ImVec2(0, 0), disp,
                                        IM_COL32(24, 30, 48, 255), IM_COL32(24, 30, 48, 255),
                                        IM_COL32(10, 13, 24, 255), IM_COL32(10, 13, 24, 255));
        }

        // затемнение сверху и снизу для читаемости
        dl->AddRectFilledMultiColor(ImVec2(0, 0), ImVec2(disp.x, disp.y * 0.38f),
                                    IM_COL32(3, 5, 10, 200), IM_COL32(3, 5, 10, 200),
                                    IM_COL32(3, 5, 10, 0), IM_COL32(3, 5, 10, 0));
        dl->AddRectFilledMultiColor(ImVec2(0, disp.y * 0.55f), disp,
                                    IM_COL32(3, 5, 10, 0), IM_COL32(3, 5, 10, 0),
                                    IM_COL32(3, 5, 10, 230), IM_COL32(3, 5, 10, 230));
    } else {
        // главная: градиент + мягкое синее свечение
        const ImU32 col_top = IM_COL32(14, 19, 34, 255);
        const ImU32 col_bot = IM_COL32(6, 9, 18, 255);
        dl->AddRectFilledMultiColor(ImVec2(0, 0), disp, col_top, col_top, col_bot, col_bot);
        dl->AddCircleFilled(ImVec2(disp.x * 0.86f, disp.y * 0.08f), 300.0f, IM_COL32(0, 112, 209, 10), 64);
        dl->AddCircleFilled(ImVec2(disp.x * 0.86f, disp.y * 0.08f), 190.0f, IM_COL32(0, 112, 209, 16), 64);
    }
}

// ----------------------------------------------------------------------------
// Верхняя часть (логотип / название выбранной игры)
// ----------------------------------------------------------------------------
static void DrawHeader(const ImVec2& disp) {
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    if (g_selected >= 0 && g_selected < (int)g_games.size()) {
        const zrx::Game& g = g_games[(size_t)g_selected];

        // Акцентная полоска + крупное название игры
        dl->AddRectFilled(ImVec2(30, 44), ImVec2(38, 100), ACCENT, 4.0f);
        dl->AddText(g_font_big, 48.0f, ImVec2(54, 40), COL_WHITE, g.title.c_str());

        // Мета: ID · версия · тип
        std::string meta;
        if (!g.title_id.empty()) meta += g.title_id;
        if (!g.version.empty()) {
            if (!meta.empty()) meta += "  ·  ";
            meta += "v" + g.version;
        }
        if (!meta.empty()) meta += "  ·  ";
        meta += ResPakStatusCached(g);            // v0.6: видно, есть ли архив
        dl->AddText(g_font, 16.0f, ImVec2(56, 96), COL_DIM, meta.c_str());

        // Статус: честное состояние дампа (фаза 2.5)
        const char* st_text;
        ImU32 st_col;
        if (g.eboot == "elf") {
            st_text = "ELF — домашний, запуск готов (фаза 3)";
            st_col  = COL_GREEN;
        } else if (g.self_state == "self-open") {
            st_text = "SELF — данные открыты, ядро попытается запустить";
            st_col  = COL_GREEN;
        } else {
            st_text = "SELF — зашифрован, ждём ключи сцены (фаза 7)";
            st_col  = COL_AMBER;
        }
        const float st_y = disp.y * 0.5f;
        const ImVec2 ss = g_font->CalcTextSizeA(17.0f, FLT_MAX, 0.0f, st_text);
        dl->AddRectFilled(ImVec2(50, st_y), ImVec2(56 + ss.x + 12, st_y + 36),
                          IM_COL32(6, 9, 18, 170), 8.0f);
        dl->AddRect(ImVec2(50, st_y), ImVec2(56 + ss.x + 12, st_y + 36), st_col, 8.0f);
        dl->AddText(g_font, 17.0f, ImVec2(56, st_y + 9), st_col, st_text);
    } else {
        dl->AddRectFilled(ImVec2(30, 34), ImVec2(38, 72), ACCENT, 4.0f);
        dl->AddText(g_font_title, 34.0f, ImVec2(54, 32), COL_WHITE, "ZerpexPS5");
        dl->AddText(g_font, 15.0f, ImVec2(56, 72), COL_DIM,
                    "LAUNCHER v" ZERPEX_LAUNCHER_VERSION " · ЯДРО v" ZERPEX_CORE_VERSION " — БИБЛИОТЕКА");
    }

    // «Чип» пользователя справа (как в PS5)
    const float av_r = 18.0f;
    const float av_x = disp.x - 44.0f, av_y = 54.0f;
    const char* who = "Хозяин";
    const ImVec2 ws = g_font->CalcTextSizeA(16.0f, FLT_MAX, 0.0f, who);
    dl->AddText(g_font, 16.0f, ImVec2(av_x - av_r - 10.0f - ws.x, av_y - ws.y * 0.5f), COL_DIM, who);
    dl->AddCircleFilled(ImVec2(av_x, av_y), av_r, ACCENT, 24);
    const ImVec2 zs = g_font->CalcTextSizeA(17.0f, FLT_MAX, 0.0f, "Z");
    dl->AddText(g_font, 17.0f, ImVec2(av_x - zs.x * 0.5f, av_y - zs.y * 0.5f), COL_WHITE, "Z");
}

// ----------------------------------------------------------------------------
// Панель настроек: выезжает по клику на аватарку (v0.4)
// ----------------------------------------------------------------------------
static void DrawSettingsPanel(const ImVec2& disp) {
    ImGuiIO& io = ImGui::GetIO();
    const float dt = io.DeltaTime > 0.0f ? io.DeltaTime : 1.0f / 60.0f;
    g_setAnim += (g_setOpen ? 1.0f : -1.0f) * dt * 4.0f;
    if (g_setAnim < 0.0f) g_setAnim = 0.0f;
    if (g_setAnim > 1.0f) g_setAnim = 1.0f;
    if (g_setAnim <= 0.001f) return;

    // Плавный выезд: smoothstep поверх линейного времени.
    const float e = g_setAnim * g_setAnim * (3.0f - 2.0f * g_setAnim);

    const float W = 520.0f, H = 620.0f;
    const float top = 88.0f;
    const float px  = disp.x - W * e;

    // Мягкое затемнение остального экрана (косметика, клики не блокирует).
    ImGui::GetBackgroundDrawList()->AddRectFilled(
        ImVec2(0, 0), disp, IM_COL32(0, 0, 0, (int)(110 * e)));

    ImGui::SetNextWindowPos(ImVec2(px, top));
    ImGui::SetNextWindowSize(ImVec2(W, H));
    ImGui::SetNextWindowBgAlpha(0.94f * e);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 16.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 8.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, 10.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_GrabRounding, 8.0f);
    ImGui::PushStyleColor(ImGuiCol_WindowBg,        ImVec4(0.045f, 0.058f, 0.088f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_Text,            ImVec4(0.82f,  0.87f, 0.94f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_FrameBg,         ImVec4(0.100f, 0.132f, 0.190f, 0.90f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered,  ImVec4(0.135f, 0.175f, 0.250f, 0.95f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive,   ImVec4(0.165f, 0.215f, 0.300f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_PopupBg,         ImVec4(0.052f, 0.068f, 0.105f, 0.98f));
    ImGui::PushStyleColor(ImGuiCol_Button,          ImVec4(0.120f, 0.152f, 0.220f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered,   ImVec4(0.165f, 0.205f, 0.290f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,    ImVec4(0.085f, 0.110f, 0.160f, 1.00f));
    ImGui::PushStyleColor(ImGuiCol_Header,          ImVec4(0.00f,  0.00f,  0.00f,  0.00f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered,   ImVec4(0.00f,  0.44f,  0.82f,  0.35f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,    ImVec4(0.00f,  0.44f,  0.82f,  0.45f));
    ImGui::Begin("##settings", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                 ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse |
                 ImGuiWindowFlags_NoSavedSettings);
    ImGui::PopStyleColor(12);
    ImGui::PopStyleVar(5);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImVec2 pmin = ImGui::GetWindowPos();
    const ImVec2 pmax = ImVec2(pmin.x + W, pmin.y + H);

    // Рамка и акцентная полоса слева (как у шапки лаунчера).
    dl->AddRect(pmin, pmax, IM_COL32(255, 255, 255, 18), 16.0f);
    dl->AddRectFilled(ImVec2(pmin.x, pmin.y + 16.0f), ImVec2(pmin.x + 3.0f, pmax.y - 16.0f),
                      ACCENT, 1.5f);

    // Шапка: заголовок, подзаголовок, крестик.
    dl->AddText(g_font_title, 28.0f, ImVec2(pmin.x + 26.0f, pmin.y + 16.0f),
                COL_WHITE, "Настройки");
    dl->AddText(g_font, 15.0f, ImVec2(pmin.x + 26.0f, pmin.y + 58.0f),
                COL_DIM, "ядро ZerpexPS5 v" ZERPEX_CORE_VERSION " · видеокарта · запуск ELF");
    ImGui::SetCursorScreenPos(ImVec2(pmin.x + W - 26.0f - 32.0f, pmin.y + 16.0f));
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(1, 1, 1, 0.08f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(1, 1, 1, 0.04f));
    if (ImGui::Button("✕", ImVec2(32, 32))) g_setOpen = false;
    ImGui::PopStyleColor(3);

    float y = pmin.y + 96.0f;
    dl->AddLine(ImVec2(pmin.x + 26.0f, y), ImVec2(pmin.x + W - 26.0f, y),
                IM_COL32(255, 255, 255, 14));
    y += 20.0f;

    // --- вспомогательные примитивы панели ---
    auto Section = [&](const char* s) {
        dl->AddRectFilled(ImVec2(pmin.x + 26.0f, y), ImVec2(pmin.x + 29.0f, y + 16.0f),
                          ACCENT, 1.5f);
        dl->AddText(g_font, 16.0f, ImVec2(pmin.x + 40.0f, y - 1.0f),
                    IM_COL32(208, 218, 234, 255), s);
        y += 30.0f;
    };
    auto Hint = [&](const char* s, ImU32 col) {
        dl->AddText(g_font, 14.5f, ImVec2(pmin.x + 27.0f, y), col, s);
        y += 22.0f;
    };

    // --- Видеокарта ------------------------------------------------------------
    Section("ВИДЕОКАРТА ДЛЯ ЭМУЛЯЦИИ");
    // элементы, начинающиеся с '(' — честные статусы «карты нет», не имена
    const bool gpuOk = !g_gpus.empty() && g_gpus[0][0] != '(';
    const char* cur = g_gpuIndex < 0
        ? "Авто (первая доступная)"
        : (g_gpuIndex < (int)g_gpus.size() ? g_gpus[(size_t)g_gpuIndex].c_str()
                                           : "(индекс вне списка)");
    ImGui::SetCursorScreenPos(ImVec2(pmin.x + 26.0f, y));
    ImGui::SetNextItemWidth(W - 52.0f);
    if (ImGui::BeginCombo("##gpu", cur)) {
        if (ImGui::Selectable(g_gpuIndex < 0 ? "✓ Авто (первая доступная)"
                                             : "   Авто (первая доступная)", g_gpuIndex < 0)) {
            g_gpuIndex = -1;
            SaveSettings();
            zrx::Log::info("Видеокарта: авто (первая доступная)");
        }
        for (size_t i = 0; i < g_gpus.size(); ++i) {
            const bool sel = (g_gpuIndex == (int)i);
            const std::string row = std::string(sel ? "✓ " : "   ") + g_gpus[i];
            if (ImGui::Selectable(row.c_str(), sel)) {
                g_gpuIndex = (int)i;
                SaveSettings();
                zrx::Log::info("Видеокарта для эмуляции: %s", g_gpus[i].c_str());
            }
        }
        ImGui::EndCombo();
    }
    y += 40.0f;
    if (!gpuOk)
        Hint(g_gpus.empty() ? "(Vulkan не найден)" : g_gpus[0].c_str(), COL_AMBER);
    Hint("Ядро получит --gpu N; если у карты нет нужной очереди — честно возьмёт другую.",
         COL_DIM);

    // --- Параметры ядра ----------------------------------------------------------
    y += 12.0f;
    Section("ПАРАМЕТРЫ ЗАПУСКА ЯДРА");
    ImGui::SetCursorScreenPos(ImVec2(pmin.x + 26.0f, y));
    ImGui::SetNextItemWidth(W - 52.0f);
    if (ImGui::InputTextWithHint("##args", "доп. параметры командной строки ядра",
                                 g_coreArgs, sizeof(g_coreArgs)))
        SaveSettings();
    y += 40.0f;
    Hint("Дописываются после пути к ELF. Что ядро не знает — оно честно напишет в логе.",
         COL_DIM);

    // --- Прямой запуск ELF ---------------------------------------------------------
    y += 12.0f;
    Section("ПРЯМОЙ ЗАПУСК ELF");
    // ImGui показывает UTF-8; храним путь в wchar_t, копируем для показа
    static char elfU8[1024] = "";
    {
        const std::string u8 = ToUtf8(g_elfPath);
        if (u8.size() < sizeof(elfU8)) strcpy_s(elfU8, u8.c_str());
    }
    ImGui::SetCursorScreenPos(ImVec2(pmin.x + 26.0f, y));
    ImGui::SetNextItemWidth(W - 52.0f);
    ImGui::InputTextWithHint("##elf", "файл .elf для запуска ядром", elfU8,
                             sizeof(elfU8), ImGuiInputTextFlags_ReadOnly);
    y += 44.0f;

    ImGui::SetCursorScreenPos(ImVec2(pmin.x + 26.0f, y));
    if (ImGui::Button("Выбрать ELF...", ImVec2(150, 36))) {
        wchar_t tmp[MAX_PATH] = {};
        if (PickFile(g_hwnd, tmp, (size_t)MAX_PATH)) {
            wcscpy_s(g_elfPath, tmp);
            SaveSettings();
            zrx::Log::info("Выбран ELF: %s", ToUtf8(g_elfPath).c_str());
        }
    }
    ImGui::SameLine();
    const bool canRun = g_elfPath[0] != 0;
    ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.00f, 0.44f, 0.82f, canRun ? 1.00f : 0.35f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.05f, 0.55f, 0.95f, canRun ? 1.00f : 0.35f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.00f, 0.34f, 0.66f, canRun ? 1.00f : 0.35f));
    if (ImGui::Button("▶  Запустить ELF", ImVec2(190, 36))) {
        if (canRun) LaunchCorePath(g_elfPath);
        else        zrx::Log::warn("Сначала выбери ELF-файл");
    }
    ImGui::PopStyleColor(3);

    // --- Диагностика (v0.6): лог ядра и папка выбранной игры ------------------
    y += 46.0f;                       // кнопки ELF выше нарисованы от текущего y
    Section("ДИАГНОСТИКА");
    ImGui::SetCursorScreenPos(ImVec2(pmin.x + 26.0f, y));
    if (ImGui::Button("Открыть лог ядра", ImVec2(180, 36)))
        OpenCoreLog();
    ImGui::SameLine();
    ImGui::BeginDisabled(g_selected < 0);
    if (ImGui::Button("Папка игры", ImVec2(150, 36)))
        OpenSelectedGameFolder();
    ImGui::EndDisabled();
    y += 40.0f;
    Hint("zerpex_log.txt лежит рядом с ядром (в build).", COL_DIM);

    // Клик мимо панели (когда она раскрыта) — закрыть. Аватарку и выпадающий
    // список комбо не считаем «мимо»: первый сам тогглит, вторая — окно попапа.
    if (g_setAnim >= 0.999f && ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
        !ImGui::IsMouseHoveringRect(pmin, pmax) &&
        !ImGui::IsMouseHoveringRect(ImVec2(disp.x - 66.0f, 32.0f),
                                    ImVec2(disp.x - 22.0f, 76.0f)) &&
        !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId)) {
        g_setOpen = false;
        zrx::Log::info("Панель настроек: закрыта");
    }

    // Честный футер
    dl->AddText(g_font, 13.5f, ImVec2(pmin.x + 26.0f, pmin.y + H - 34.0f), COL_DIM,
                "settings.json рядом с EXE · ядро v" ZERPEX_CORE_VERSION " получает путь, --gpu N и параметры");
    ImGui::End();
}

// ----------------------------------------------------------------------------
// Интерфейс кадра
// ----------------------------------------------------------------------------
static void DrawUI() {
    ImGuiIO& io = ImGui::GetIO();
    const ImVec2 disp = io.DisplaySize;
    ImDrawList* dl = ImGui::GetBackgroundDrawList();

    DrawBackdrop(disp);
    DrawHeader(disp);

    const float bar_h = 185.0f;

    // ---- Невидимое полноэкранное окно: весь виджетный UI ----
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(disp);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("##root", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                 ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                 ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoCollapse |
                 ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoSavedSettings |
                 ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNav);

    // ---- Кнопка настроек «шестерёнка» (справа сверху) -> панель (v0.4) ----
    {
        ImDrawList* wdl = ImGui::GetWindowDrawList();
        const float av_r = 18.0f, av_x = disp.x - 44.0f, av_y = 54.0f;
        const ImVec2 ac(av_x, av_y);
        ImGui::SetCursorPos(ImVec2(av_x - av_r - 4.0f, av_y - av_r - 4.0f));
        if (ImGui::InvisibleButton("##avatar", ImVec2((av_r + 4.0f) * 2.0f, (av_r + 4.0f) * 2.0f))) {
            g_setOpen = !g_setOpen;
            zrx::Log::info(g_setOpen ? "Панель настроек: открыта" : "Панель настроек: закрыта");
        }
        const bool hov = ImGui::IsItemHovered();
        wdl->AddCircleFilled(ac, av_r, hov || g_setOpen
                             ? IM_COL32(48, 58, 78, 255) : IM_COL32(36, 44, 60, 255));
        // шестерёнка: кольцо + 8 спиц
        wdl->AddCircle(ac, 6.0f, IM_COL32(205, 218, 236, 255), 0, 2.0f);
        for (int k = 0; k < 8; ++k) {
            const float a = (float)k * 0.7853981634f;   // 45°
            const float c = cosf(a), s = sinf(a);
            wdl->AddLine(ImVec2(av_x + c * 8.5f, av_y + s * 8.5f),
                         ImVec2(av_x + c * 12.5f, av_y + s * 12.5f),
                         IM_COL32(205, 218, 236, 255), 2.0f);
        }
        wdl->AddCircle(ac, av_r, hov || g_setOpen ? ACCENT : IM_COL32(255, 255, 255, 36),
                       0, hov || g_setOpen ? 2.0f : 1.5f);
        if (hov)
            ImGui::SetTooltip("Настройки: видеокарта, параметры, запуск ELF");
    }

    // Заголовок секции с акцентной чертой
    ImGui::SetCursorPos(ImVec2(48, disp.y * 0.26f));
    ImGui::TextColored(ImVec4(0.70f, 0.76f, 0.85f, 1.0f), "БИБЛИОТЕКА ИГР");
    {
        const ImVec2 tp = ImGui::GetItemRectMin();
        ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(tp.x, tp.y + 27.0f),
                                                  ImVec2(tp.x + 152.0f, tp.y + 30.0f),
                                                  ACCENT, 2.0f);
    }

    // Ряд плиток
    const float tile = 150.0f;
    const float row_y = disp.y * 0.26f + 52.0f;
    float x = 48.0f;

    if (TileAdd(ImVec2(x, row_y), tile))
        {
            std::wstring path;
            if (PickFolder(g_hwnd, path))
                AddGamesFromFolder(path);
            else
                zrx::Log::info("Выбор папки отменён");
        }
    x += tile + 20.0f;

    for (int i = 0; i < (int)g_games.size(); ++i) {
        if (TileGame(i, ImVec2(x, row_y), tile)) {
            // v0.6: двойной клик сразу запускает игру (первый клик уже выбрал её)
            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                g_selected = i;
                zrx::Log::info("Запуск двойным кликом: %s", g_games[(size_t)i].title.c_str());
                LaunchCore(g_games[(size_t)i]);
            } else {
                g_selected = (g_selected == i) ? -1 : i;
                if (g_selected >= 0)
                    zrx::Log::info("Выбрана игра: %s", g_games[(size_t)i].title.c_str());
                else
                    zrx::Log::info("Возврат в библиотеку");
            }
        }
        x += tile + 20.0f;
    }
    TileGhost(ImVec2(x, row_y), tile, g_games.empty() ? "Игры появятся\nпосле добавления" : "Скоро");

    // Клик по пустому фону (под курсором нет ни плитки, ни диалога) — назад.
    // Пока открыта/выезжает панель настроек — фон-клик игнорируем.
    const bool back_click = ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
                            !ImGui::IsAnyItemHovered() &&
                            g_setAnim <= 0.01f &&
                            !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId);
    if (back_click && g_selected >= 0) {
        g_selected = -1;
        zrx::Log::info("Возврат в библиотеку");
    }

    // Кнопка «Запустить» под статус-чипом (фаза 3)
    if (g_selected >= 0) {
        const zrx::Game& gsel = g_games[(size_t)g_selected];
        ImGui::SetCursorPos(ImVec2(56, disp.y * 0.5f + 56.0f));
        ImGui::PushStyleColor(ImGuiCol_Button,        ImVec4(0.00f, 0.44f, 0.82f, 1.00f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.05f, 0.55f, 0.95f, 1.00f));
        ImGui::PushStyleColor(ImGuiCol_ButtonActive,  ImVec4(0.00f, 0.34f, 0.66f, 1.00f));
        if (ImGui::Button("▶  Запустить", ImVec2(230, 46)))
            LaunchCore(gsel);
        ImGui::PopStyleColor(3);
        if (ImGui::IsItemHovered()) {
            if (gsel.eboot == "elf")
                ImGui::SetTooltip("Консоль ядра: разбор + НАТИВНОЕ исполнение\nс перехватом syscall (фаза 3)");
            else if (gsel.self_state == "self-open")
                ImGui::SetTooltip("Консоль ядра: анализ + попытка запуска открытого\nвложенного ELF (фаза 7, шаг 1)");
            else
                ImGui::SetTooltip("Консоль ядра: анализ покажет шифрование сегментов\n(retail — исполнение после дешифровки, фаза 7)");
        }
    }

    // Подсказка Esc справа над панелью журнала
    {
        const char* hint = g_selected >= 0
            ? "Enter / двойной клик — запуск   ·   Esc или клик по фону — назад"
            : "Esc — выход";
        const ImVec2 hs = ImGui::CalcTextSize(hint);
        ImGui::SetCursorPos(ImVec2(disp.x - hs.x - 28.0f, disp.y - bar_h - 36.0f));
        ImGui::TextColored(ImVec4(0.42f, 0.47f, 0.55f, 1.0f), "%s", hint);
    }

    ImGui::End();
    ImGui::PopStyleVar(2);

    // ---- Панель журнала (низ экрана) ----
    {
        const float by = disp.y - bar_h;
        dl->AddRectFilled(ImVec2(0, by), disp, IM_COL32(5, 7, 12, 215), 0.0f);
        dl->AddRectFilled(ImVec2(0, by - 2), ImVec2(disp.x, by), ACCENT_DIM, 0.0f);
        dl->AddText(g_font, 15.0f, ImVec2(24, by + 10), IM_COL32(90, 110, 140, 255), "ЖУРНАЛ");

        const auto& lines = zrx::Log::lines();
        int shown = 0;
        for (int i = (int)lines.size() - 1; i >= 0 && shown < 6; --i, ++shown) {
            const std::string& s = lines[(size_t)i];
            ImU32 col = IM_COL32(150, 190, 235, 255);      // [info]
            if (s.compare(0, 6, "[warn]") == 0)  col = IM_COL32(230, 170, 60, 255);
            else if (s.compare(0, 6, "[error") == 0) col = IM_COL32(235, 90, 90, 255);
            const float y = disp.y - 26.0f - (float)shown * 25.0f;
            dl->AddText(g_font, 17.0f, ImVec2(24, y), col, s.c_str());
        }
    }

    // ---- Панель настроек (поверх всего, выезжает справа) — v0.4 ----
    DrawSettingsPanel(disp);

    // v0.6: Enter запускает выбранную игру (если не открыты настройки/попап)
    if (g_selected >= 0 && g_selected < (int)g_games.size() && !g_setOpen &&
        ImGui::IsKeyPressed(ImGuiKey_Enter, false) &&
        !ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId)) {
        LaunchCore(g_games[(size_t)g_selected]);
    }

    // Esc: закрыть настройки / назад из игры / выход из программы
    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
        if (g_setAnim > 0.01f) {
            g_setOpen = false;
            zrx::Log::info("Панель настроек: закрыта (Esc)");
        } else if (g_selected >= 0) {
            g_selected = -1;
            zrx::Log::info("Возврат в библиотеку (Esc)");
        } else if (!ImGui::IsPopupOpen(nullptr, ImGuiPopupFlags_AnyPopupId)) {
            zrx::Log::info("Выход (Esc)");
            g_running = false;
        }
    }
}

// ----------------------------------------------------------------------------
// Окно
// ----------------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    if (g_imgui_ready && ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam))
        return 1;

    switch (msg) {
    case WM_SIZE:
        if (wparam != SIZE_MINIMIZED)
            ResizeTargets((int)LOWORD(lparam), (int)HIWORD(lparam));
        return 0;
    case WM_SYSCOMMAND:
        if ((wparam & 0xfff0) == SC_KEYMENU)  // отключаем Alt-меню
            return 0;
        break;
    case WM_DESTROY:
        g_running = false;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

// ----------------------------------------------------------------------------
// Точка входа
// ----------------------------------------------------------------------------
int WINAPI WinMain(HINSTANCE hinst, HINSTANCE, LPSTR, int) {
    if (FAILED(CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE)))
        return 1;

    ImGui_ImplWin32_EnableDpiAwareness();

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(WNDCLASSEXW);
    wc.style         = CS_CLASSDC;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hinst;
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"ZerpexLauncher";
    RegisterClassExW(&wc);

    const int client_w = 1280, client_h = 720;
    RECT wr = { 0, 0, client_w, client_h };
    AdjustWindowRect(&wr, WS_OVERLAPPEDWINDOW, FALSE);
    const int win_w = wr.right - wr.left;
    const int win_h = wr.bottom - wr.top;
    const int pos_x = (GetSystemMetrics(SM_CXSCREEN) - win_w) / 2;
    const int pos_y = (GetSystemMetrics(SM_CYSCREEN) - win_h) / 2;

    g_hwnd = CreateWindowExW(0, wc.lpszClassName,
                             L"ZerpexPS5 Launcher v" ZERPEX_LAUNCHER_VERSION_W
                             L" · ядро v" ZERPEX_CORE_VERSION_W,
                             WS_OVERLAPPEDWINDOW, pos_x, pos_y, win_w, win_h,
                             nullptr, nullptr, hinst, nullptr);
    if (!g_hwnd || !InitD3D(g_hwnd)) {
        if (g_hwnd) DestroyWindow(g_hwnd);
        ShutdownD3D();
        CoUninitialize();
        return 1;
    }
    ShowWindow(g_hwnd, SW_SHOWDEFAULT);
    UpdateWindow(g_hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    {
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.ConfigWindowsMoveFromTitleBarOnly = true;
    }
    LoadFonts();
    ApplyPS5Style();
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_dev, g_ctx);
    g_imgui_ready = true;

    zrx::Log::info("ZerpexPS5 Launcher v" ZERPEX_LAUNCHER_VERSION " запущен");
    zrx::Log::info("Ядро: v" ZERPEX_CORE_VERSION " (ZerpexPS5.exe)");
    zrx::Log::info("Рендер: DirectX 11 + Dear ImGui 1.93");

    // Загружаем сохранённую библиотеку
    if (zrx::LoadGames(ExeDir() + L"\\games.json", &g_games))
        zrx::Log::info("Библиотека загружена: игр %d", (int)g_games.size());
    else
        zrx::Log::info("Библиотека пуста — добавь игры кнопкой \"+\"");

    // Настройки (v0.4): gpu/параметры/ELF + честное перечисление видеокарт
    LoadSettings();
    EnumerateGpus();
    zrx::Log::info("Видеокарт найдено: %d%s", (int)g_gpus.size(),
                   g_gpuIndex >= 0 ? "  (приоритет выбран в настройках)" : "");

    // v0.6: на старте открыть последнюю запущенную игру (если она ещё в библиотеке)
    if (g_lastGame[0]) {
        const std::wstring w = ToWide(g_lastGame);
        for (int i = 0; i < (int)g_games.size(); ++i) {
            if (_wcsicmp(g_games[(size_t)i].root.c_str(), w.c_str()) == 0) {
                g_selected = i;
                zrx::Log::info("Последняя игра: %s", g_games[(size_t)i].title.c_str());
                break;
            }
        }
    }

    MSG msg = {};
    while (g_running) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                g_running = false;
        }
        if (!g_running)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        DrawUI();
        ImGui::Render();

        const float clear[4] = { 0.004f, 0.006f, 0.012f, 1.0f };
        g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
        g_ctx->ClearRenderTargetView(g_rtv, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        if (FAILED(g_swap->Present(1, 0))) {
            zrx::Log::error("DXGI: Present не удался — выход");
            break;
        }
    }

    g_imgui_ready = false;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    ShutdownD3D();
    DestroyWindow(g_hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    CoUninitialize();
    return 0;
}
