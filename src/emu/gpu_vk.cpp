// ============================================================================
// ZerpexPS5 — фаза 5.0: Vulkan-слой (окно + свапчейн + копия кадра)
//
// Что делает честно:
//   - грузит vulkan-1.dll динамически (линковки нет, SDK нужен только для
//     хедеров при сборке; если их нет — сборка не падает, слой отключается);
//   - окно Win32 1280x720, instance/device/свапчейн лениво;
//   - кадр: staging-буфер (хост-память, gpu.cpp копирует туда кадр гостя)
//     -> оффскрин-изображение -> картинка свапчейна -> present.
//     НИ ОДНОГО шейдера — только copy/barrier (фаза 5.1+ добавит PM4).
//   - один кадр в полёте: vkQueueWaitIdle после present. Медленно, зато
//     тупо-надёжно — это фаза "первого пикселя", не перфоманса.
// ============================================================================
#include "gpu_vk.h"

#include <cstdio>
#include <cstring>
#include <vector>

#include <windows.h>

#if defined(__has_include)
#  if __has_include(<vulkan/vulkan.h>)
#    define VK_USE_PLATFORM_WIN32_KHR
#    include <vulkan/vulkan.h>
#    define ZRX_VK_HEADERS 1
#  endif
#endif

namespace zrx {
namespace gpu_vk {

#ifdef ZRX_VK_HEADERS

// --- Глобальное состояние ---------------------------------------------------
static HMODULE g_dll = nullptr;
static PFN_vkGetInstanceProcAddr g_gpia = nullptr;

static VkInstance       g_inst   = VK_NULL_HANDLE;
static VkPhysicalDevice g_phys   = VK_NULL_HANDLE;
static VkDevice         g_dev    = VK_NULL_HANDLE;
static VkQueue          g_queue  = VK_NULL_HANDLE;
static uint32_t         g_qFam   = 0;
static VkSurfaceKHR     g_surf   = VK_NULL_HANDLE;
static VkSwapchainKHR   g_swap   = VK_NULL_HANDLE;
static VkFormat         g_fmt    = VK_FORMAT_B8G8R8A8_UNORM;
static VkColorSpaceKHR  g_cs     = VK_COLOR_SPACE_SRGB_NONLINEAR_KHR;
static VkExtent2D       g_ext    { 1280, 720 };
static std::vector<VkImage>     g_swImg;
static std::vector<VkImageView> g_swView;

static VkImage         g_off       = VK_NULL_HANDLE;
static VkDeviceMemory  g_offMem    = VK_NULL_HANDLE;
static bool            g_offIsDst  = false;    // лейаут оффскрина: TRANSFER_DST?
static uint32_t        g_offW = 0, g_offH = 0;

static VkBuffer        g_stage     = VK_NULL_HANDLE;
static VkDeviceMemory  g_stageMem  = VK_NULL_HANDLE;
static void*           g_stageMap  = nullptr;
static uint64_t        g_stageSize = 0;

static VkCommandPool   g_cmdPool   = VK_NULL_HANDLE;
static VkCommandBuffer g_cmd       = VK_NULL_HANDLE;
static VkSemaphore     g_semAcq    = VK_NULL_HANDLE;
static VkSemaphore     g_semDone   = VK_NULL_HANDLE;

static HWND  g_hwnd       = nullptr;
static bool  g_winClosed  = false;
static bool  g_dllMissing = false;    // vulkan-1.dll нет — не спамим
static bool  g_noDevice   = false;    // DLL есть, устройств нет (напр. ВМ)
static bool  g_initTried  = false;    // instance/device уже пробовали создать
static int   g_prefDevice = -1;       // приоритет видеокарты (--gpu N из лаунчера)

// --- Функции уровня instance (после vkCreateInstance) ------------------------
static PFN_vkDestroyInstance                   pDestroyInstance;
static PFN_vkEnumeratePhysicalDevices          pEnumPhys;
static PFN_vkGetPhysicalDeviceProperties       pPhysProps;
static PFN_vkGetPhysicalDeviceQueueFamilyProperties pPhysQF;
static PFN_vkGetPhysicalDeviceMemoryProperties pPhysMem;
static PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR pSurfCaps;
static PFN_vkGetPhysicalDeviceSurfaceFormatsKHR      pSurfFmts;
static PFN_vkGetPhysicalDeviceSurfaceSupportKHR      pSurfSup;
static PFN_vkCreateDevice                      pCreateDevice;
static PFN_vkGetDeviceProcAddr                 pGdpa;
static PFN_vkCreateWin32SurfaceKHR             pWin32Surface;
static PFN_vkDestroySurfaceKHR                 pDestroySurface;

// --- Функции уровня device (после vkCreateDevice) ----------------------------
static PFN_vkDestroyDevice                     pDestroyDevice;
static PFN_vkGetDeviceQueue                    pGetQueue;
static PFN_vkCreateSwapchainKHR                pCreateSwap;
static PFN_vkDestroySwapchainKHR               pDestroySwap;
static PFN_vkGetSwapchainImagesKHR             pSwapImages;
static PFN_vkCreateImageView                   pCreateView;
static PFN_vkDestroyImageView                  pDestroyView;
static PFN_vkCreateCommandPool                 pCreatePool;
static PFN_vkDestroyCommandPool                pDestroyPool;
static PFN_vkAllocateCommandBuffers            pAllocCmd;
static PFN_vkResetCommandBuffer                pResetCmd;
static PFN_vkBeginCommandBuffer                pBeginCmd;
static PFN_vkEndCommandBuffer                  pEndCmd;
static PFN_vkCmdPipelineBarrier                pCmdBarrier;
static PFN_vkCmdCopyBufferToImage              pCmdCopyBufToImg;
static PFN_vkCmdCopyImage                      pCmdCopyImg;
static PFN_vkCreateImage                       pCreateImage;
static PFN_vkDestroyImage                      pDestroyImage;
static PFN_vkGetImageMemoryRequirements        pImgReqs;
static PFN_vkBindImageMemory                   pBindImage;
static PFN_vkCreateBuffer                      pCreateBuffer;
static PFN_vkDestroyBuffer                     pDestroyBuffer;
static PFN_vkGetBufferMemoryRequirements       pBufReqs;
static PFN_vkBindBufferMemory                  pBindBuffer;
static PFN_vkAllocateMemory                    pAllocMem;
static PFN_vkFreeMemory                        pFreeMem;
static PFN_vkMapMemory                         pMapMem;
static PFN_vkCreateSemaphore                   pCreateSem;
static PFN_vkDestroySemaphore                  pDestroySem;
static PFN_vkQueueSubmit                       pSubmit;
static PFN_vkQueuePresentKHR                   pPresent;
static PFN_vkAcquireNextImageKHR               pAcquire;
static PFN_vkQueueWaitIdle                     pQueueIdle;
static PFN_vkDeviceWaitIdle                    pDevIdle;

// Загрузка функций Vulkan. name — ГОЛЫЙ идентификатор (без кавычек):
// строку для vkGet*ProcAddr и для печати даёт #name, а PFN_##name
// склеивается в корректный токен типа указателя (PFN_vkXxx).
#define LOAD_I(var, name) \
    do { (var) = (PFN_##name)g_gpia(g_inst, #name); \
         if (!(var)) { printf("[GPU] Vulkan: функция %s не найдена\n", #name); \
                      fflush(stdout); return false; } } while (0)
#define LOAD_D(var, name) \
    do { (var) = (PFN_##name)pGdpa(g_dev, #name); \
         if (!(var)) { printf("[GPU] Vulkan: функция %s не найдена\n", #name); \
                      fflush(stdout); return false; } } while (0)

// --- Окно -------------------------------------------------------------------
static LRESULT CALLBACK WndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CLOSE:
        g_winClosed = true;
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        g_winClosed = true;
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, msg, wp, lp);
}

static void EnsureWindow() {
    if (g_hwnd || g_winClosed) return;
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = &WndProc;
    wc.hInstance     = GetModuleHandleW(nullptr);
    wc.hCursor       = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"ZerpexGuestWnd";
    RegisterClassExW(&wc);

    RECT r = { 0, 0, 1280, 720 };
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    g_hwnd = CreateWindowExW(0, wc.lpszClassName,
                             L"ZerpexPS5 — вывод гостя (фаза 5.0)",
                             WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT,
                             r.right - r.left, r.bottom - r.top,
                             nullptr, nullptr, wc.hInstance, nullptr);
    if (g_hwnd) {
        ShowWindow(g_hwnd, SW_SHOW);
        printf("[GPU] окно гостя открыто (1280x720)\n");
        fflush(stdout);
    } else {
        printf("[GPU] окно не открылось (CreateWindowExW отказал)\n");
        fflush(stdout);
    }
}

static void PumpMessages() {
    MSG m;
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
        if (m.message == WM_QUIT) { g_winClosed = true; break; }
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

// --- Память под ресурсы ------------------------------------------------------
static uint32_t FindMemType(const VkPhysicalDeviceMemoryProperties& mp,
                            uint32_t bits, uint32_t want) {
    for (uint32_t i = 0; i < mp.memoryTypeCount; ++i)
        if ((bits & (1u << i)) &&
            (mp.memoryTypes[i].propertyFlags & want) == want)
            return i;
    return UINT32_MAX;
}

static bool AllocFor(const VkMemoryRequirements& reqs, uint32_t preferred,
                     VkDeviceMemory* out) {
    VkPhysicalDeviceMemoryProperties mp;
    pPhysMem(g_phys, &mp);
    uint32_t t = FindMemType(mp, reqs.memoryTypeBits, preferred);
    if (t == UINT32_MAX) t = FindMemType(mp, reqs.memoryTypeBits, 0);
    if (t == UINT32_MAX) {
        printf("[GPU] Vulkan: подходящего типа памяти нет\n");
        fflush(stdout);
        return false;
    }
    VkMemoryAllocateInfo ai { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    ai.allocationSize = reqs.size;
    ai.memoryTypeIndex = t;
    return pAllocMem(g_dev, &ai, nullptr, out) == VK_SUCCESS;
}

// --- Инициализация -----------------------------------------------------------
static bool InitInstance() {
    g_gpia = (PFN_vkGetInstanceProcAddr)GetProcAddress(g_dll, "vkGetInstanceProcAddr");
    if (!g_gpia) {
        printf("[GPU] vulkan-1.dll без vkGetInstanceProcAddr — странная DLL\n");
        fflush(stdout);
        return false;
    }

    PFN_vkCreateInstance pCreateInstance =
        (PFN_vkCreateInstance)g_gpia(nullptr, "vkCreateInstance");
    if (!pCreateInstance) return false;

    VkApplicationInfo app { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    app.pApplicationName = "ZerpexPS5";
    app.applicationVersion = 5;
    app.pEngineName = "ZerpexPS5";
    app.engineVersion = 5;
    app.apiVersion = VK_API_VERSION_1_0;

    const char* exts[2] = { "VK_KHR_surface", "VK_KHR_win32_surface" };
    VkInstanceCreateInfo ci { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    ci.pApplicationInfo = &app;
    ci.enabledExtensionCount = 2;
    ci.ppEnabledExtensionNames = exts;

    VkResult r = pCreateInstance(&ci, nullptr, &g_inst);
    if (r != VK_SUCCESS) {
        printf("[GPU] vkCreateInstance: %d — Vulkan недоступен\n", (int)r);
        fflush(stdout);
        return false;
    }

    LOAD_I(pDestroyInstance,  vkDestroyInstance);
    LOAD_I(pEnumPhys,         vkEnumeratePhysicalDevices);
    LOAD_I(pPhysProps,        vkGetPhysicalDeviceProperties);
    LOAD_I(pPhysQF,           vkGetPhysicalDeviceQueueFamilyProperties);
    LOAD_I(pPhysMem,          vkGetPhysicalDeviceMemoryProperties);
    LOAD_I(pSurfCaps,         vkGetPhysicalDeviceSurfaceCapabilitiesKHR);
    LOAD_I(pSurfFmts,         vkGetPhysicalDeviceSurfaceFormatsKHR);
    LOAD_I(pSurfSup,          vkGetPhysicalDeviceSurfaceSupportKHR);
    LOAD_I(pCreateDevice,     vkCreateDevice);
    LOAD_I(pGdpa,             vkGetDeviceProcAddr);
    LOAD_I(pWin32Surface,     vkCreateWin32SurfaceKHR);
    LOAD_I(pDestroySurface,   vkDestroySurfaceKHR);

    return true;
}

static bool InitSurfaceDevice() {
    VkWin32SurfaceCreateInfoKHR sci { VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR };
    sci.hinstance = GetModuleHandleW(nullptr);
    sci.hwnd = g_hwnd;
    if (pWin32Surface(g_inst, &sci, nullptr, &g_surf) != VK_SUCCESS) {
        printf("[GPU] vkCreateWin32SurfaceKHR не удался\n");
        fflush(stdout);
        return false;
    }

    uint32_t n = 0;
    pEnumPhys(g_inst, &n, nullptr);
    if (n == 0) {
        g_noDevice = true;
        printf("[GPU] Vulkan: физических устройств 0 — растеризатора нет "
               "(типично для ВМ без 3D). Кадров не будет, вызовы гостя "
               "продолжат отрабатывать честно.\n");
        fflush(stdout);
        return false;
    }
    std::vector<VkPhysicalDevice> devs(n);
    pEnumPhys(g_inst, &n, devs.data());

    // Приоритет карты из лаунчера (--gpu N): выбранную ставим первой в очереди
    // проверки. Если у неё нет GRAPHICS+present — честно логируем и берём
    // первую подходящую.
    if (g_prefDevice >= 0) {
        if (g_prefDevice < (int)n) {
            std::vector<VkPhysicalDevice> ordered;
            ordered.reserve(n);
            ordered.push_back(devs[(size_t)g_prefDevice]);
            for (uint32_t i = 0; i < n; ++i)
                if ((int)i != g_prefDevice) ordered.push_back(devs[i]);
            devs.swap(ordered);
        } else {
            printf("[GPU] --gpu %d вне диапазона (устройств %u) — игнорирую\n",
                   g_prefDevice, n);
            fflush(stdout);
        }
    }

    uint32_t qn = 0;
    bool found = false;
    for (uint32_t di = 0; di < n && !found; ++di) {
        g_phys = devs[di];
        qn = 0;
        pPhysQF(g_phys, &qn, nullptr);
        std::vector<VkQueueFamilyProperties> qs(qn);
        pPhysQF(g_phys, &qn, qs.data());
        for (uint32_t i = 0; i < qn; ++i) {
            VkBool32 sup = VK_FALSE;
            pSurfSup(g_phys, i, g_surf, &sup);
            if ((qs[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) && sup) {
                g_qFam = i;
                found = true;
                break;
            }
        }
    }

    if (!found) {
        g_noDevice = true;
        printf("[GPU] нет очереди с GRAPHICS + present — кадры не вывожу\n");
        fflush(stdout);
        return false;
    }

    VkPhysicalDeviceProperties props;
    pPhysProps(g_phys, &props);
    if (g_prefDevice > 0 && (int)n > 1)
        printf("[GPU] Vulkan-устройство: %s (№%d — приоритет из лаунчера)\n",
               props.deviceName, g_prefDevice);
    else
        printf("[GPU] Vulkan-устройство: %s\n", props.deviceName);
    fflush(stdout);

    const float prio = 1.0f;
    VkDeviceQueueCreateInfo qci { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    qci.queueFamilyIndex = g_qFam;
    qci.queueCount = 1;
    qci.pQueuePriorities = &prio;

    const char* devExts[1] = { "VK_KHR_swapchain" };
    VkDeviceCreateInfo dci { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    dci.enabledExtensionCount = 1;
    dci.ppEnabledExtensionNames = devExts;
    // Диагностические крошки: краш 0xC0000005 после печати устройства (фаза 5).
    // Каждый шаг -> печать+fflush, чтобы по последней строке найти виновника.
    printf("[GPU] шаг: vkCreateDevice (очередь %u, ext VK_KHR_swapchain)\n", g_qFam);
    fflush(stdout);
    if (pCreateDevice(g_phys, &dci, nullptr, &g_dev) != VK_SUCCESS) {
        printf("[GPU] vkCreateDevice не удался\n");
        fflush(stdout);
        return false;
    }
    printf("[GPU] шаг: vkCreateDevice ок\n"); fflush(stdout);

    LOAD_D(pDestroyDevice,    vkDestroyDevice);
    LOAD_D(pGetQueue,         vkGetDeviceQueue);
    LOAD_D(pCreateSwap,       vkCreateSwapchainKHR);
    LOAD_D(pDestroySwap,      vkDestroySwapchainKHR);
    LOAD_D(pSwapImages,       vkGetSwapchainImagesKHR);
    LOAD_D(pCreateView,       vkCreateImageView);
    LOAD_D(pDestroyView,      vkDestroyImageView);
    LOAD_D(pCreatePool,       vkCreateCommandPool);
    LOAD_D(pDestroyPool,      vkDestroyCommandPool);
    LOAD_D(pAllocCmd,         vkAllocateCommandBuffers);
    LOAD_D(pResetCmd,         vkResetCommandBuffer);
    LOAD_D(pBeginCmd,         vkBeginCommandBuffer);
    LOAD_D(pEndCmd,           vkEndCommandBuffer);
    LOAD_D(pCmdBarrier,       vkCmdPipelineBarrier);
    LOAD_D(pCmdCopyBufToImg,  vkCmdCopyBufferToImage);
    LOAD_D(pCmdCopyImg,       vkCmdCopyImage);
    LOAD_D(pCreateImage,      vkCreateImage);
    LOAD_D(pDestroyImage,     vkDestroyImage);
    LOAD_D(pImgReqs,          vkGetImageMemoryRequirements);
    LOAD_D(pBindImage,        vkBindImageMemory);
    LOAD_D(pCreateBuffer,     vkCreateBuffer);
    LOAD_D(pDestroyBuffer,    vkDestroyBuffer);
    LOAD_D(pBufReqs,          vkGetBufferMemoryRequirements);
    LOAD_D(pBindBuffer,       vkBindBufferMemory);
    LOAD_D(pAllocMem,         vkAllocateMemory);
    LOAD_D(pFreeMem,          vkFreeMemory);
    LOAD_D(pMapMem,           vkMapMemory);
    LOAD_D(pCreateSem,        vkCreateSemaphore);
    LOAD_D(pDestroySem,       vkDestroySemaphore);
    LOAD_D(pSubmit,           vkQueueSubmit);
    LOAD_D(pPresent,          vkQueuePresentKHR);
    LOAD_D(pAcquire,          vkAcquireNextImageKHR);
    LOAD_D(pQueueIdle,        vkQueueWaitIdle);
    LOAD_D(pDevIdle,          vkDeviceWaitIdle);

    pGetQueue(g_dev, g_qFam, 0, &g_queue);
    printf("[GPU] шаг: очередь %u получена\n", g_qFam); fflush(stdout);

    printf("[GPU] шаг: vkCreateCommandPool\n"); fflush(stdout);
    VkCommandPoolCreateInfo pci { VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
    pci.queueFamilyIndex = g_qFam;
    if (pCreatePool(g_dev, &pci, nullptr, &g_cmdPool) != VK_SUCCESS) return false;
    printf("[GPU] шаг: vkAllocateCommandBuffers\n"); fflush(stdout);
    VkCommandBufferAllocateInfo cai { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    cai.commandPool = g_cmdPool;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    // ВНИМАНИЕ: у vkAllocateCommandBuffers 3 параметра (без аллокатора!) —
    // см. ZERPEX FIX в vulkan_core.h. Прошлый вызов с nullptr 4-м аргументом
    // отдавал драйверу pCommandBuffers = nullptr -> запись по 0x0.
    if (pAllocCmd(g_dev, &cai, &g_cmd) != VK_SUCCESS) return false;
    printf("[GPU] шаг: command pool + буфер ок\n"); fflush(stdout);

    VkSemaphoreCreateInfo semi { VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO };
    if (pCreateSem(g_dev, &semi, nullptr, &g_semAcq)  != VK_SUCCESS) return false;
    if (pCreateSem(g_dev, &semi, nullptr, &g_semDone) != VK_SUCCESS) return false;
    printf("[GPU] шаг: семафоры ок\n"); fflush(stdout);

    return true;
}

// --- Свапчейн ----------------------------------------------------------------
static bool CreateSwapchain() {
    printf("[GPU] шаг: surface capabilities\n"); fflush(stdout);
    VkSurfaceCapabilitiesKHR caps;
    pSurfCaps(g_phys, g_surf, &caps);
    printf("[GPU] шаг: caps ок (min=%u max=%u, %ux%u)\n",
           caps.minImageCount, caps.maxImageCount, g_ext.width, g_ext.height);
    fflush(stdout);

    g_ext = caps.currentExtent;
    if (g_ext.width == 0xFFFFFFFFu) {
        g_ext.width  = 1280;
        g_ext.height = 720;
    }

    uint32_t fn = 0;
    printf("[GPU] шаг: surface formats\n"); fflush(stdout);
    pSurfFmts(g_phys, g_surf, &fn, nullptr);
    if (fn) {
        std::vector<VkSurfaceFormatKHR> f(fn);
        pSurfFmts(g_phys, g_surf, &fn, f.data());
        g_fmt = f[0].format;
        g_cs  = f[0].colorSpace;
        for (const VkSurfaceFormatKHR& x : f)
            if (x.format == VK_FORMAT_B8G8R8A8_UNORM) {
                g_fmt = x.format;
                g_cs  = x.colorSpace;
                break;
            }
    }

    uint32_t imgs = caps.minImageCount + 1;
    if (caps.maxImageCount && imgs > caps.maxImageCount)
        imgs = caps.maxImageCount;

    VkSwapchainCreateInfoKHR sci { VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR };
    sci.surface = g_surf;
    sci.minImageCount = imgs;
    sci.imageFormat = g_fmt;
    sci.imageColorSpace = g_cs;
    sci.imageExtent = g_ext;
    sci.imageArrayLayers = 1;
    sci.imageUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT
                   | VK_IMAGE_USAGE_TRANSFER_DST_BIT;
    sci.imageSharingMode = VK_SHARING_MODE_EXCLUSIVE;
    sci.preTransform = caps.currentTransform;
    sci.compositeAlpha = VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR;
    sci.presentMode = VK_PRESENT_MODE_FIFO_KHR;   // есть всегда
    sci.clipped = VK_TRUE;

    printf("[GPU] шаг: vkCreateSwapchainKHR (%u картинок, fmt %d)\n",
           imgs, (int)g_fmt);
    fflush(stdout);
    VkResult r = pCreateSwap(g_dev, &sci, nullptr, &g_swap);
    if (r != VK_SUCCESS) {
        printf("[GPU] vkCreateSwapchainKHR: %d\n", (int)r);
        fflush(stdout);
        return false;
    }
    printf("[GPU] шаг: свапчейн ок\n"); fflush(stdout);

    uint32_t n = 0;
    pSwapImages(g_dev, g_swap, &n, nullptr);
    g_swImg.resize(n);
    pSwapImages(g_dev, g_swap, &n, g_swImg.data());

    for (VkImage img : g_swImg) {
        VkImageViewCreateInfo vci { VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO };
        vci.image = img;
        vci.viewType = VK_IMAGE_VIEW_TYPE_2D;
        vci.format = g_fmt;
        vci.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        vci.subresourceRange.levelCount = 1;
        vci.subresourceRange.layerCount = 1;
        VkImageView v = VK_NULL_HANDLE;
        if (pCreateView(g_dev, &vci, nullptr, &v) != VK_SUCCESS) return false;
        g_swView.push_back(v);
    }
    printf("[GPU] шаг: image views ок (%u)\n", (unsigned)g_swView.size());
    fflush(stdout);
    return true;
}

static void DestroySwapchainViews() {
    for (VkImageView v : g_swView) pDestroyView(g_dev, v, nullptr);
    g_swView.clear();
    g_swImg.clear();
    if (g_swap) { pDestroySwap(g_dev, g_swap, nullptr); g_swap = VK_NULL_HANDLE; }
}

static bool RecreateSwapchain() {
    if (!g_dev) return false;
    pQueueIdle(g_queue);
    DestroySwapchainViews();
    return CreateSwapchain();
}

// --- Оффскрин + staging -------------------------------------------------------
static void DestroyFrame() {
    g_stageMap = nullptr;   // vkFreeMemory неявно снимает мап
    if (g_stage)    { pDestroyBuffer(g_dev, g_stage, nullptr); g_stage = VK_NULL_HANDLE; }
    if (g_stageMem) { pFreeMem(g_dev, g_stageMem, nullptr); g_stageMem = VK_NULL_HANDLE; }
    if (g_off)      { pDestroyImage(g_dev, g_off, nullptr); g_off = VK_NULL_HANDLE; }
    if (g_offMem)   { pFreeMem(g_dev, g_offMem, nullptr); g_offMem = VK_NULL_HANDLE; }
    g_stageSize = 0;
    g_offIsDst = false;
}

static bool CreateFrame(uint32_t w, uint32_t h, uint64_t frameBytes) {
    DestroyFrame();
    g_offW = w;
    g_offH = h;

    // Оффскрин: принимаем копию из буфера и отдаём её в свапчейн.
    VkImageCreateInfo ici { VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO };
    ici.imageType = VK_IMAGE_TYPE_2D;
    ici.format = VK_FORMAT_B8G8R8A8_UNORM;
    ici.extent = { w, h, 1 };
    ici.mipLevels = 1;
    ici.arrayLayers = 1;
    ici.samples = VK_SAMPLE_COUNT_1_BIT;
    ici.tiling = VK_IMAGE_TILING_OPTIMAL;
    ici.usage = VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT;
    ici.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    printf("[GPU] шаг: offscreen image %ux%u\n", w, h); fflush(stdout);
    if (pCreateImage(g_dev, &ici, nullptr, &g_off) != VK_SUCCESS) {
        printf("[GPU] vkCreateImage (оффскрин) не удался\n");
        fflush(stdout);
        return false;
    }
    printf("[GPU] шаг: offscreen image ок\n"); fflush(stdout);
    VkMemoryRequirements rq;
    pImgReqs(g_dev, g_off, &rq);
    if (!AllocFor(rq, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, &g_offMem)) return false;
    if (pBindImage(g_dev, g_off, g_offMem, 0) != VK_SUCCESS) return false;
    printf("[GPU] шаг: offscreen память + bind ок\n"); fflush(stdout);

    // Staging: хост-память, gpu.cpp пишет туда кадр гостя напрямую.
    const uint64_t need = frameBytes > (uint64_t)w * h * 4
                        ? frameBytes : (uint64_t)w * h * 4;
    printf("[GPU] шаг: staging buffer %llu байт\n", (unsigned long long)need);
    fflush(stdout);
    VkBufferCreateInfo bci { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    bci.size = need;
    bci.usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT;
    bci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (pCreateBuffer(g_dev, &bci, nullptr, &g_stage) != VK_SUCCESS) return false;
    pBufReqs(g_dev, g_stage, &rq);
    if (!AllocFor(rq, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT
                     | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, &g_stageMem))
        return false;
    if (pBindBuffer(g_dev, g_stage, g_stageMem, 0) != VK_SUCCESS) return false;
    if (pMapMem(g_dev, g_stageMem, 0, VK_WHOLE_SIZE, 0, &g_stageMap) != VK_SUCCESS)
        return false;
    g_stageSize = need;
    printf("[GPU] шаг: staging + map ок — Vulkan готов\n"); fflush(stdout);
    return true;
}

// --- Барьеры -------------------------------------------------------------------
static void Barrier(VkCommandBuffer cb, VkImage img,
                    VkImageLayout oldL, VkImageLayout newL,
                    VkPipelineStageFlags srcStage, VkAccessFlags srcAcc,
                    VkPipelineStageFlags dstStage, VkAccessFlags dstAcc) {
    VkImageMemoryBarrier b { VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER };
    b.srcAccessMask = srcAcc;
    b.dstAccessMask = dstAcc;
    b.oldLayout = oldL;
    b.newLayout = newL;
    b.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    b.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
    b.image = img;
    b.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    b.subresourceRange.levelCount = 1;
    b.subresourceRange.layerCount = 1;
    pCmdBarrier(cb, srcStage, dstStage, 0, 0, nullptr, 0, nullptr, 1, &b);
}

// --- Public API -----------------------------------------------------------------
bool Prepare(uint32_t w, uint32_t h, uint64_t frameBytes) {
    if (g_winClosed) return false;

    if (!g_dll) {
        if (g_dllMissing) return false;
        g_dll = LoadLibraryW(L"vulkan-1.dll");
        if (!g_dll) {
            g_dllMissing = true;
            printf("[GPU] vulkan-1.dll не найден — рантайма Vulkan нет, "
                   "кадры выводиться не будут (вызовы гостя продолжат работать)\n");
            fflush(stdout);
            return false;
        }
        printf("[GPU] vulkan-1.dll загружен (динамически, без линковки)\n");
        fflush(stdout);
    }

    EnsureWindow();
    if (!g_hwnd) return false;

    if (!g_initTried) {
        g_initTried = true;
        if (!InitInstance()) return false;
        if (!InitSurfaceDevice()) return false;   // может честно дать g_noDevice
    }
    if (g_noDevice) return false;

    if (!g_swap && !CreateSwapchain()) return false;

    if (g_offW != w || g_offH != h || g_stageSize < frameBytes) {
        if (!CreateFrame(w, h, frameBytes)) {
            printf("[GPU] кадровые ресурсы не создались — кадров не будет\n");
            fflush(stdout);
            return false;
        }
    }
    return true;
}

void* StagePtr(uint64_t* sizeOut) {
    if (sizeOut) *sizeOut = g_stageSize;
    return g_stageMap;
}

bool Present(uint32_t w, uint32_t h, uint64_t bytes) {
    if (g_winClosed || g_noDevice || !g_dev || !g_swap) return false;

    PumpMessages();
    if (g_winClosed) return false;

    if (!g_stageMap || bytes > g_stageSize) return false;

    uint32_t idx = 0;
    VkResult r = pAcquire(g_dev, g_swap, UINT64_MAX, g_semAcq, VK_NULL_HANDLE, &idx);
    if (r == VK_ERROR_OUT_OF_DATE_KHR) {
        if (!RecreateSwapchain()) return false;
        r = pAcquire(g_dev, g_swap, UINT64_MAX, g_semAcq, VK_NULL_HANDLE, &idx);
    }
    if (r != VK_SUCCESS && r != VK_SUBOPTIMAL_KHR) {
        static int said = 0;
        if (said++ < 5) {
            printf("[GPU]   vkAcquireNextImageKHR: %d — кадр пропущен\n", (int)r);
            fflush(stdout);
        }
        return false;
    }

    const uint32_t cw = w < g_ext.width  ? w : g_ext.width;
    const uint32_t ch = h < g_ext.height ? h : g_ext.height;
    const bool doCopy = (cw != 0 && ch != 0);

    VkCommandBufferBeginInfo bi { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    pResetCmd(g_cmd, 0);
    if (pBeginCmd(g_cmd, &bi) != VK_SUCCESS) return false;

    if (doCopy) {
        // 1) буфер -> оффскрин
        if (!g_offIsDst) {
            Barrier(g_cmd, g_off,
                    VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                    VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, 0,
                    VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT);
            g_offIsDst = true;
        }
        VkBufferImageCopy reg;
        memset(&reg, 0, sizeof(reg));
        reg.imageSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        reg.imageSubresource.layerCount = 1;
        reg.imageExtent = { cw, ch, 1 };
        pCmdCopyBufToImg(g_cmd, g_stage, g_off,
                         VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &reg);

        // 2) оффскрин -> картинка свапчейна (форматы одной размерности)
        Barrier(g_cmd, g_off,
                VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_READ_BIT);
        Barrier(g_cmd, g_swImg[idx],
                VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, 0,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT);

        VkImageCopy cp;
        memset(&cp, 0, sizeof(cp));
        cp.srcSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        cp.srcSubresource.layerCount = 1;
        cp.dstSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        cp.dstSubresource.layerCount = 1;
        cp.extent = { cw, ch, 1 };
        pCmdCopyImg(g_cmd, g_off, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                    g_swImg[idx], VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &cp);

        // 3) вернуть лейауты: свапчейн — на показ, оффскрин — под следующий кадр
        Barrier(g_cmd, g_swImg[idx],
                VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT,
                VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, 0);
        Barrier(g_cmd, g_off,
                VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_READ_BIT,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT);
    }

    if (pEndCmd(g_cmd) != VK_SUCCESS) return false;

    VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_TRANSFER_BIT;
    VkSubmitInfo si { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    si.waitSemaphoreCount = 1;
    si.pWaitSemaphores = &g_semAcq;
    si.pWaitDstStageMask = &waitStage;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &g_cmd;
    si.signalSemaphoreCount = 1;
    si.pSignalSemaphores = &g_semDone;
    if (pSubmit(g_queue, 1, &si, VK_NULL_HANDLE) != VK_SUCCESS) return false;

    VkSwapchainKHR sc = g_swap;
    VkPresentInfoKHR pi { VK_STRUCTURE_TYPE_PRESENT_INFO_KHR };
    pi.waitSemaphoreCount = 1;
    pi.pWaitSemaphores = &g_semDone;
    pi.swapchainCount = 1;
    pi.pSwapchains = &sc;
    pi.pImageIndices = &idx;
    r = pPresent(g_queue, &pi);
    if (r == VK_ERROR_OUT_OF_DATE_KHR) RecreateSwapchain();   // к следующему acquire

    pQueueIdle(g_queue);   // фаза 5.0: один кадр в полёте — простота важнее скорости
    return true;
}

void Shutdown() {
    if (g_dev) pDevIdle(g_dev);
    DestroyFrame();
    if (g_semAcq)  { pDestroySem(g_dev, g_semAcq, nullptr);  g_semAcq = VK_NULL_HANDLE; }
    if (g_semDone) { pDestroySem(g_dev, g_semDone, nullptr); g_semDone = VK_NULL_HANDLE; }
    if (g_cmdPool) { pDestroyPool(g_dev, g_cmdPool, nullptr); g_cmdPool = VK_NULL_HANDLE; }
    g_cmd = VK_NULL_HANDLE;
    DestroySwapchainViews();
    if (g_surf) { pDestroySurface(g_inst, g_surf, nullptr); g_surf = VK_NULL_HANDLE; }
    if (g_dev)  { pDestroyDevice(g_dev, nullptr); g_dev = VK_NULL_HANDLE; }
    if (g_inst) { pDestroyInstance(g_inst, nullptr); g_inst = VK_NULL_HANDLE; }
    g_phys = VK_NULL_HANDLE;
    if (g_hwnd) { DestroyWindow(g_hwnd); g_hwnd = nullptr; }
    UnregisterClassW(L"ZerpexGuestWnd", GetModuleHandleW(nullptr));
    if (g_dll) { FreeLibrary(g_dll); g_dll = nullptr; }
    printf("[GPU] Vulkan-слой выгружен\n");
    fflush(stdout);
}

bool DeviceAlive() { return g_dev != VK_NULL_HANDLE; }

void SetPreferredDevice(int index) { g_prefDevice = index; }

// ============================================================================
// Probe: изолированные эксперименты инициализации Vulkan (--vkprobe).
// Цель: локализовать краш vkAllocateCommandBuffers (nvoglv64, запись по 0x0),
// который воспроизводится и на worker-нити. Эксперименты идут в ОТДЕЛЬНЫХ
// процессах (запускает main.cpp): без гостя, без VEH, без нашего аллокатора.
//   1 — как в ядре: окно+поверхность, устройство c VK_KHR_swapchain,
//       очередь, пул, командный буфер.
//   2 — устройство БЕЗ расширений, без поверхности: пул + командный буфер.
//   3 — как 1, но свапчейн создаётся ПЕРЕД командными объектами.
//   4 — устройство c VK_KHR_swapchain, но БЕЗ окна/поверхности.
//   5 — как 1, но с явными (нулевыми) VkPhysicalDeviceFeatures.
// ============================================================================
static void ProbeStep(const char* s) {
    printf("[PROBE]   шаг: %s\n", s);
    fflush(stdout);
}

// Своё устройство + пул + командный буфер для вариантов 2/4/5.
static int ProbeCustom(bool withSwapExt, bool withSurface, bool explicitFeat,
                       int num) {
    VkSurfaceKHR surf = VK_NULL_HANDLE;
    if (withSurface) {
        ProbeStep("окно + поверхность");
        EnsureWindow();
        if (!g_hwnd) { printf("[PROBE] окно не создалось\n"); return 1; }
        VkWin32SurfaceCreateInfoKHR sci { VK_STRUCTURE_TYPE_WIN32_SURFACE_CREATE_INFO_KHR };
        sci.hinstance = GetModuleHandleW(nullptr);
        sci.hwnd = g_hwnd;
        if (pWin32Surface(g_inst, &sci, nullptr, &surf) != VK_SUCCESS) {
            printf("[PROBE] vkCreateWin32SurfaceKHR не удался\n");
            return 1;
        }
    }

    ProbeStep("перечисление устройств");
    uint32_t n = 0;
    pEnumPhys(g_inst, &n, nullptr);
    if (!n) { printf("[PROBE] устройств 0\n"); return 1; }
    std::vector<VkPhysicalDevice> devs(n);
    pEnumPhys(g_inst, &n, devs.data());
    g_phys = devs[0];

    ProbeStep("выбор очереди");
    uint32_t qn = 0;
    g_qFam = UINT32_MAX;
    pPhysQF(g_phys, &qn, nullptr);
    std::vector<VkQueueFamilyProperties> qs(qn);
    pPhysQF(g_phys, &qn, qs.data());
    for (uint32_t i = 0; i < qn; ++i) {
        VkBool32 sup = VK_FALSE;
        if (surf) pSurfSup(g_phys, i, surf, &sup);
        if ((qs[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) && (!surf || sup)) {
            g_qFam = i;
            break;
        }
    }
    if (g_qFam == UINT32_MAX) {
        printf("[PROBE] подходящей очереди нет\n");
        return 1;
    }

    ProbeStep("vkCreateDevice");
    const float prio = 1.0f;
    VkDeviceQueueCreateInfo qci { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    qci.queueFamilyIndex = g_qFam;
    qci.queueCount = 1;
    qci.pQueuePriorities = &prio;
    const char* exts[1] = { "VK_KHR_swapchain" };
    VkPhysicalDeviceFeatures feats {};    // явные нули
    VkDeviceCreateInfo dci { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &qci;
    if (withSwapExt) {
        dci.enabledExtensionCount = 1;
        dci.ppEnabledExtensionNames = exts;
    }
    if (explicitFeat) dci.pEnabledFeatures = &feats;
    if (pCreateDevice(g_phys, &dci, nullptr, &g_dev) != VK_SUCCESS) {
        printf("[PROBE] vkCreateDevice не удался\n");
        return 1;
    }

    ProbeStep("vkGetDeviceQueue");
    PFN_vkGetDeviceQueue pGQ = (PFN_vkGetDeviceQueue)pGdpa(g_dev, "vkGetDeviceQueue");
    if (!pGQ) { printf("[PROBE] нет vkGetDeviceQueue\n"); return 1; }
    VkQueue q = VK_NULL_HANDLE;
    pGQ(g_dev, g_qFam, 0, &q);

    ProbeStep("vkCreateCommandPool");
    PFN_vkCreateCommandPool pCP =
        (PFN_vkCreateCommandPool)pGdpa(g_dev, "vkCreateCommandPool");
    if (!pCP) { printf("[PROBE] нет vkCreateCommandPool\n"); return 1; }
    VkCommandPoolCreateInfo pci { VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
    pci.queueFamilyIndex = g_qFam;
    VkCommandPool pool = VK_NULL_HANDLE;
    if (pCP(g_dev, &pci, nullptr, &pool) != VK_SUCCESS) {
        printf("[PROBE] vkCreateCommandPool не удался\n");
        return 1;
    }

    ProbeStep("vkAllocateCommandBuffers");
    PFN_vkAllocateCommandBuffers pAC =
        (PFN_vkAllocateCommandBuffers)pGdpa(g_dev, "vkAllocateCommandBuffers");
    if (!pAC) { printf("[PROBE] нет vkAllocateCommandBuffers\n"); return 1; }
    VkCommandBufferAllocateInfo cai { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    cai.commandPool = pool;
    cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    cai.commandBufferCount = 1;
    VkCommandBuffer cmd = VK_NULL_HANDLE;
    // 3 параметра (без аллокатора) — см. ZERPEX FIX в vulkan_core.h.
    if (pAC(g_dev, &cai, &cmd) != VK_SUCCESS) {
        printf("[PROBE] vkAllocateCommandBuffers не удался (без краша)\n");
        return 1;
    }

    printf("[PROBE] эксперимент %d ПРОШЁЛ полностью\n", num);
    fflush(stdout);

    // Приберёмся, чтобы процесс-эксперимент не держал объекты молча.
    PFN_vkDestroyCommandPool pDP =
        (PFN_vkDestroyCommandPool)pGdpa(g_dev, "vkDestroyCommandPool");
    if (pDP) pDP(g_dev, pool, nullptr);
    if (surf) pDestroySurface(g_inst, surf, nullptr);
    PFN_vkDestroyDevice pDD = (PFN_vkDestroyDevice)pGdpa(g_dev, "vkDestroyDevice");
    if (pDD) pDD(g_dev, nullptr);
    g_dev = VK_NULL_HANDLE;
    return 0;
}

int Probe(int which) {
    if (g_dll) { printf("[PROBE] DLL уже загружена?\n"); return 1; }
    g_dll = LoadLibraryW(L"vulkan-1.dll");
    if (!g_dll) { printf("[PROBE] vulkan-1.dll не найден\n"); return 1; }
    printf("[PROBE] vulkan-1.dll загружен\n");
    fflush(stdout);

    ProbeStep("vkCreateInstance + функции уровня instance");
    if (!InitInstance()) {
        printf("[PROBE] InitInstance не удался\n");
        return 1;
    }
    printf("[PROBE] instance создан\n");
    fflush(stdout);

    // Пул + командный буфер после производственной инициализации (1 и 3).
    auto PoolAndCmd = []() -> int {
        ProbeStep("vkCreateCommandPool");
        VkCommandPoolCreateInfo pci { VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
        pci.queueFamilyIndex = g_qFam;
        if (pCreatePool(g_dev, &pci, nullptr, &g_cmdPool) != VK_SUCCESS) {
            printf("[PROBE] vkCreateCommandPool не удался\n");
            return 1;
        }
        ProbeStep("vkAllocateCommandBuffers");
        VkCommandBufferAllocateInfo cai { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
        cai.commandPool = g_cmdPool;
        cai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cai.commandBufferCount = 1;
        // ВНИМАНИЕ: у vkAllocateCommandBuffers 3 параметра (без аллокатора!) —
        // см. ZERPEX FIX в vulkan_core.h.
        if (pAllocCmd(g_dev, &cai, &g_cmd) != VK_SUCCESS) {
            printf("[PROBE] vkAllocateCommandBuffers не удался (без краша)\n");
            return 1;
        }
        printf("[PROBE] командный буфер выделен\n");
        fflush(stdout);
        return 0;
    };

    switch (which) {
    case 1:
        ProbeStep("окно + поверхность + устройство (как в ядре)");
        EnsureWindow();
        if (!g_hwnd) { printf("[PROBE] окно не создалось\n"); return 1; }
        if (!InitSurfaceDevice()) {
            printf("[PROBE] InitSurfaceDevice не удался\n");
            return 1;
        }
        return PoolAndCmd();
    case 3:
        ProbeStep("окно + поверхность + устройство (как в ядре)");
        EnsureWindow();
        if (!g_hwnd) { printf("[PROBE] окно не создалось\n"); return 1; }
        if (!InitSurfaceDevice()) {
            printf("[PROBE] InitSurfaceDevice не удался\n");
            return 1;
        }
        ProbeStep("vkCreateSwapchainKHR (ДО командных объектов)");
        if (!CreateSwapchain()) {
            printf("[PROBE] свапчейн не создался\n");
            return 1;
        }
        return PoolAndCmd();
    case 2: return ProbeCustom(false, false, false, 2);
    case 4: return ProbeCustom(true,  false, false, 4);
    case 5: return ProbeCustom(true,  true,  true,  5);
    default:
        printf("[PROBE] неизвестный номер эксперимента\n");
        return 1;
    }
}

#else  /* !ZRX_VK_HEADERS — SDK-хедеров нет: честная пустышка --------------- */

static bool said = false;
static void SayOnce() {
    if (said) return;
    said = true;
    printf("[GPU] хедеры Vulkan не найдены при сборке — слой отключён "
           "(вызовы гостя продолжат отрабатывать, кадров не будет)\n");
    fflush(stdout);
}

bool Prepare(uint32_t, uint32_t, uint64_t) { SayOnce(); return false; }
void* StagePtr(uint64_t* sizeOut) { if (sizeOut) *sizeOut = 0; return nullptr; }
bool Present(uint32_t, uint32_t, uint64_t) { return false; }
void Shutdown() {}
bool DeviceAlive() { return false; }
void SetPreferredDevice(int) {}
int Probe(int) { SayOnce(); return -1; }

#endif

} } // namespace zrx::gpu_vk
