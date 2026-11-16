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
static VkImageView     g_offView   = VK_NULL_HANDLE;
static VkFramebuffer   g_offFb     = VK_NULL_HANDLE;
// Фактический лейаут оффскрина между кадрами (инвариант: TRANSFER_SRC,
// и CPU-путь, и PM4-путь завершают кадр именно в нём).
enum class OffLayout { Undefined, TransferDst, TransferSrc };
static OffLayout       g_offLayout = OffLayout::Undefined;
static uint32_t        g_offW = 0, g_offH = 0;

static VkBuffer        g_stage     = VK_NULL_HANDLE;
static VkDeviceMemory  g_stageMem  = VK_NULL_HANDLE;
static void*           g_stageMap  = nullptr;
static uint64_t        g_stageSize = 0;

static VkCommandPool   g_cmdPool   = VK_NULL_HANDLE;
static VkCommandBuffer g_cmd       = VK_NULL_HANDLE;
static VkSemaphore     g_semAcq    = VK_NULL_HANDLE;
static VkSemaphore     g_semDone   = VK_NULL_HANDLE;

// --- Фаза 5.2: прокси-рендер из PM4 (без компилятора шейдеров) ---------------
// SPIR-V собран вручную (опкоды сверены с грамматикой Khronos). Геометрия и
// цвета — в хост-вершинном буфере; guest-шейдеров пока нет (фаза 5.3).
static VkShaderModule        g_pmVs      = VK_NULL_HANDLE;
static VkShaderModule        g_pmFs      = VK_NULL_HANDLE;
static VkRenderPass          g_pmPass    = VK_NULL_HANDLE;
static VkPipelineLayout      g_pmLayout  = VK_NULL_HANDLE;
static VkPipeline            g_pmPipe    = VK_NULL_HANDLE;
static VkBuffer              g_pmVb      = VK_NULL_HANDLE;
static VkDeviceMemory        g_pmVbMem   = VK_NULL_HANDLE;
static void*                 g_pmVbMap   = nullptr;
static bool                  g_pmReady   = false;
static bool                  g_pmFailed  = false;   // один честный отчёт об ошибке

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
// Фаза 5.2: рендер из PM4 (шейдеры, пайплайн, отрисовка).
static PFN_vkCreateShaderModule                pCreateShader;
static PFN_vkDestroyShaderModule               pDestroyShader;
static PFN_vkCreateRenderPass                  pCreatePass;
static PFN_vkDestroyRenderPass                 pDestroyPass;
static PFN_vkCreateFramebuffer                 pCreateFb;
static PFN_vkDestroyFramebuffer                pDestroyFb;
static PFN_vkCreatePipelineLayout              pCreatePipeLayout;
static PFN_vkDestroyPipelineLayout             pDestroyPipeLayout;
static PFN_vkCreateGraphicsPipelines           pCreatePipelines;
static PFN_vkDestroyPipeline                   pDestroyPipeline;
static PFN_vkCmdBeginRenderPass                pCmdBeginPass;
static PFN_vkCmdEndRenderPass                  pCmdEndPass;
static PFN_vkCmdBindPipeline                   pCmdBindPipe;
static PFN_vkCmdDraw                           pCmdDraw;
static PFN_vkCmdSetViewport                    pCmdSetViewport;
static PFN_vkCmdSetScissor                     pCmdSetScissor;
static PFN_vkCmdBindVertexBuffers              pCmdBindVb;

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
    // Фаза 5.2: прокси-рендер из PM4.
    LOAD_D(pCreateShader,     vkCreateShaderModule);
    LOAD_D(pDestroyShader,    vkDestroyShaderModule);
    LOAD_D(pCreatePass,       vkCreateRenderPass);
    LOAD_D(pDestroyPass,      vkDestroyRenderPass);
    LOAD_D(pCreateFb,         vkCreateFramebuffer);
    LOAD_D(pDestroyFb,        vkDestroyFramebuffer);
    LOAD_D(pCreatePipeLayout, vkCreatePipelineLayout);
    LOAD_D(pDestroyPipeLayout,vkDestroyPipelineLayout);
    LOAD_D(pCreatePipelines,  vkCreateGraphicsPipelines);
    LOAD_D(pDestroyPipeline,  vkDestroyPipeline);
    LOAD_D(pCmdBeginPass,     vkCmdBeginRenderPass);
    LOAD_D(pCmdEndPass,       vkCmdEndRenderPass);
    LOAD_D(pCmdBindPipe,      vkCmdBindPipeline);
    LOAD_D(pCmdDraw,          vkCmdDraw);
    LOAD_D(pCmdSetViewport,   vkCmdSetViewport);
    LOAD_D(pCmdSetScissor,    vkCmdSetScissor);
    LOAD_D(pCmdBindVb,        vkCmdBindVertexBuffers);

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
static bool EnsurePm4Fb();   // определён в блоке фазы 5.2 (ниже)

static void DestroyFrame() {
    g_stageMap = nullptr;   // vkFreeMemory неявно снимает мап
    if (g_stage)    { pDestroyBuffer(g_dev, g_stage, nullptr); g_stage = VK_NULL_HANDLE; }
    if (g_stageMem) { pFreeMem(g_dev, g_stageMem, nullptr); g_stageMem = VK_NULL_HANDLE; }
    if (g_offFb)    { pDestroyFb(g_dev, g_offFb, nullptr); g_offFb = VK_NULL_HANDLE; }
    if (g_offView)  { pDestroyView(g_dev, g_offView, nullptr); g_offView = VK_NULL_HANDLE; }
    if (g_off)      { pDestroyImage(g_dev, g_off, nullptr); g_off = VK_NULL_HANDLE; }
    if (g_offMem)   { pFreeMem(g_dev, g_offMem, nullptr); g_offMem = VK_NULL_HANDLE; }
    g_stageSize = 0;
    g_offLayout = OffLayout::Undefined;
}

static bool CreateFrame(uint32_t w, uint32_t h, uint64_t frameBytes) {
    DestroyFrame();
    g_offW = w;
    g_offH = h;

    // Оффскрин: принимаем копию из буфера, отдаём её в свапчейн И (5.2)
    // принимаем рендер из PM4 — поэтому COLOR_ATTACHMENT_BIT обязателен.
    VkImageCreateInfo ici { VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO };
    ici.imageType = VK_IMAGE_TYPE_2D;
    ici.format = VK_FORMAT_B8G8R8A8_UNORM;
    ici.extent = { w, h, 1 };
    ici.mipLevels = 1;
    ici.arrayLayers = 1;
    ici.samples = VK_SAMPLE_COUNT_1_BIT;
    ici.tiling = VK_IMAGE_TILING_OPTIMAL;
    ici.usage = VK_IMAGE_USAGE_TRANSFER_DST_BIT
              | VK_IMAGE_USAGE_TRANSFER_SRC_BIT
              | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
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

    // View под фреймбуфер PM4-рендера (нужен и CPU-пути — он копирует по image).
    VkImageViewCreateInfo vci { VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO };
    vci.image = g_off;
    vci.viewType = VK_IMAGE_VIEW_TYPE_2D;
    vci.format = VK_FORMAT_B8G8R8A8_UNORM;
    vci.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
    vci.subresourceRange.levelCount = 1;
    vci.subresourceRange.layerCount = 1;
    if (pCreateView(g_dev, &vci, nullptr, &g_offView) != VK_SUCCESS) return false;
    g_offLayout = OffLayout::Undefined;
    if (g_pmReady && !EnsurePm4Fb()) return false;

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

// --- Фаза 5.2: прокси-рендер из PM4 ------------------------------------------
// Компилятора GLSL->SPIR-V у нас нет, поэтому шейдеры собраны ВРУЧНУЮ.
// Каждый опкод и константа сверены с официальной грамматикой SPIR-V
// (spirv.core.grammar.json) и spirv.h — они согласны. Шейдеры БЕЗ арифметики:
// VS протаскивает два vec4-атрибута (позиция/цвет) из вершинного буфера,
// FS протаскивает вход в выход. Геометрия и цвета — на нашей стороне,
// потому что guest-шейдеров ещё нет (фаза 5.3 по RDNA2-доке).

// Опкоды (проверено): Capability=17, MemoryModel=14, EntryPoint=15 (интерфейс —
// IdRef* БЕЗ слова-счётчика), ExecutionMode=16, TypeVoid=19, TypeFloat=22,
// TypeVector=23, TypePointer=32, TypeFunction=33, Constant=43, Function=54,
// FunctionEnd=56, Variable=59, Load=61, Store=62, Decorate=71, Label=248,
// Return=253. StorageClass: Input=1, Output=3. Decoration: Location=30,
// BuiltIn=11 (Position=0). ExecutionMode OriginUpperLeft=7.
static const uint32_t kVsSpirv[] = {
    0x07230203, // магия SPIR-V
    0x00010000, // версия 1.0
    0,          // генератор
    15,         // bound (id 1..13)
    0,          // схема
    0x00010011, 1,                    // OpCapability Shader
    0x0003000E, 0, 1,                 // OpMemoryModel Logical GLSL450
    0x0009000F, 0, 11, 0x6E69616D, 0, // OpEntryPoint Vertex "main", интерфейс
    5, 6, 7, 8,                       //   (vars: pos, col, outColor, Position)
    0x00040047, 5, 30, 0,             // OpDecorate 5 Location 0 (позиция)
    0x00040047, 6, 30, 1,             // OpDecorate 6 Location 1 (цвет)
    0x00040047, 7, 30, 0,             // OpDecorate 7 Location 0 (выход)
    0x00040047, 8, 11, 0,             // OpDecorate 8 BuiltIn Position
    0x00030016, 1, 32,                // OpTypeFloat f32 -> %1
    0x00040017, 2, 1, 4,              // OpTypeVector vec4 -> %2
    0x00040020, 3, 1, 2,              // OpTypePointer Input vec4 -> %3
    0x00040020, 4, 3, 2,              // OpTypePointer Output vec4 -> %4
    0x00020013, 9,                    // OpTypeVoid -> %9
    0x00040021, 10, 9,                // OpTypeFunction void->void -> %10
    0x0004003B, 3, 5, 1,              // OpVariable %5 (Input,  Location 0)
    0x0004003B, 3, 6, 1,              // OpVariable %6 (Input,  Location 1)
    0x0004003B, 4, 7, 3,              // OpVariable %7 (Output, Location 0)
    0x0004003B, 4, 8, 3,              // OpVariable %8 (Output, BuiltIn Pos)
    0x00050036, 9, 0, 10,             // OpFunction void %9 (тип %10)
    0x000200F8, 11,                   // OpLabel %11
    0x0004003D, 2, 12, 5,             // OpLoad %12 = %5 (позиция)
    0x0004003D, 2, 13, 6,             // OpLoad %13 = %6 (цвет)
    0x0003003E, 8, 12,                // OpStore Position <- %12
    0x0003003E, 7, 13,                // OpStore outColor <- %13
    0x000100FD,                       // OpReturn
    0x00010038,                       // OpFunctionEnd
};

static const uint32_t kFsSpirv[] = {
    0x07230203,
    0x00010000,
    0,
    12,         // bound (id 1..11)
    0,
    0x00010011, 1,                    // OpCapability Shader
    0x0003000E, 0, 1,                 // OpMemoryModel Logical GLSL450
    0x0007000F, 4, 9, 0x6E69616D, 0,  // OpEntryPoint Fragment "main", интерфейс
    5, 6,                             //   (vars: inColor, outColor)
    0x00030010, 9, 7,                 // OpExecutionMode OriginUpperLeft
    0x00040047, 5, 30, 0,             // OpDecorate 5 Location 0 (вход)
    0x00040047, 6, 30, 0,             // OpDecorate 6 Location 0 (выход)
    0x00030016, 1, 32,                // OpTypeFloat f32
    0x00040017, 2, 1, 4,              // OpTypeVector vec4
    0x00040020, 3, 1, 2,              // OpTypePointer Input vec4
    0x00040020, 4, 3, 2,              // OpTypePointer Output vec4
    0x00020013, 7,                    // OpTypeVoid
    0x00040021, 8, 7,                 // OpTypeFunction void->void
    0x0004003B, 3, 5, 1,              // OpVariable %5 (Input,  Location 0)
    0x0004003B, 4, 6, 3,              // OpVariable %6 (Output, Location 0)
    0x00050036, 7, 0, 8,              // OpFunction void %9
    0x000200F8, 9,                    // OpLabel %10
    0x0004003D, 2, 11, 5,             // OpLoad %11 = %5
    0x0003003E, 6, 11,                // OpStore outColor <- %11
    0x000100FD,                       // OpReturn
    0x00010038,                       // OpFunctionEnd
};

// Треугольник-прокси: 3 вершины, stride 32 байта (два vec4: позиция, цвет).
static const float kProxyTri[24] = {
    // позиция (clip space)      цвет (r,g,b,a)
    -0.7f, -0.7f, 0.0f, 1.0f,    1.0f, 0.3f, 0.3f, 1.0f,   // низ-лево (красн)
     0.7f, -0.7f, 0.0f, 1.0f,    0.3f, 1.0f, 0.3f, 1.0f,   // низ-право (зелён)
     0.0f,  0.8f, 0.0f, 1.0f,    0.3f, 0.3f, 1.0f, 1.0f,   // верх (синий)
};

static bool InitPm4Pipeline() {
    if (g_pmReady) return true;
    if (g_pmFailed) return false;
    if (!g_dev) { g_pmFailed = true; return false; }

    printf("[GPU] шаг: PM4-пайплайн (прокси-треугольник) — сборка\n"); fflush(stdout);

    VkShaderModuleCreateInfo sci { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
    sci.pCode    = kVsSpirv;
    sci.codeSize = sizeof(kVsSpirv);
    if (pCreateShader(g_dev, &sci, nullptr, &g_pmVs) != VK_SUCCESS) {
        printf("[GPU]   SPIR-V вершинного шейдера отклонён драйвером\n");
        fflush(stdout);
        g_pmFailed = true; return false;
    }
    sci.pCode    = kFsSpirv;
    sci.codeSize = sizeof(kFsSpirv);
    if (pCreateShader(g_dev, &sci, nullptr, &g_pmFs) != VK_SUCCESS) {
        printf("[GPU]   SPIR-V фрагментного шейдера отклонён драйвером\n");
        fflush(stdout);
        g_pmFailed = true; return false;
    }

    // Пустой layout: пока никаких констант/дескрипторов (5.3 добавит).
    VkPipelineLayoutCreateInfo plci { VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO };
    if (pCreatePipeLayout(g_dev, &plci, nullptr, &g_pmLayout) != VK_SUCCESS) {
        g_pmFailed = true; return false;
    }

    // Рендер-пасс: очищает оффскрин тёмно-синим, отдаёт его в TRANSFER_SRC.
    VkAttachmentDescription att {};
    att.format         = VK_FORMAT_B8G8R8A8_UNORM;
    att.samples        = VK_SAMPLE_COUNT_1_BIT;
    att.loadOp         = VK_ATTACHMENT_LOAD_OP_CLEAR;
    att.storeOp        = VK_ATTACHMENT_STORE_OP_STORE;
    att.stencilLoadOp  = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    att.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    att.initialLayout  = VK_IMAGE_LAYOUT_UNDEFINED;
    att.finalLayout    = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;

    VkAttachmentReference aref { 0, VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL };
    VkSubpassDescription sub {};
    sub.pipelineBindPoint       = VK_PIPELINE_BIND_POINT_GRAPHICS;
    sub.colorAttachmentCount    = 1;
    sub.pColorAttachments       = &aref;

    // Явная зависимость: запись цвета -> чтение трансфером (копия в свапчейн).
    VkSubpassDependency deps[2] {};
    deps[0].srcSubpass    = VK_SUBPASS_EXTERNAL;
    deps[0].srcStageMask  = VK_PIPELINE_STAGE_TRANSFER_BIT;
    deps[0].dstSubpass    = 0;
    deps[0].dstStageMask  = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    deps[0].dstAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    deps[1].srcSubpass    = 0;
    deps[1].srcStageMask  = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    deps[1].srcAccessMask = VK_ACCESS_COLOR_ATTACHMENT_WRITE_BIT;
    deps[1].dstSubpass    = VK_SUBPASS_EXTERNAL;
    deps[1].dstStageMask  = VK_PIPELINE_STAGE_TRANSFER_BIT;
    deps[1].dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;

    VkRenderPassCreateInfo rpci { VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO };
    rpci.attachmentCount = 1;
    rpci.pAttachments    = &att;
    rpci.subpassCount    = 1;
    rpci.pSubpasses      = &sub;
    rpci.dependencyCount = 2;
    rpci.pDependencies   = deps;
    if (pCreatePass(g_dev, &rpci, nullptr, &g_pmPass) != VK_SUCCESS) {
        g_pmFailed = true; return false;
    }

    // Графический пайплайн: TRIANGLE_LIST, без отсечения, динамические
    // viewport/scissor, смешивания нет, глубины нет (пустой указатель = нет).
    VkVertexInputBindingDescription bind {};
    bind.binding   = 0;
    bind.stride    = 32;
    bind.inputRate = VK_VERTEX_INPUT_RATE_VERTEX;

    VkVertexInputAttributeDescription attrs[2] {};
    attrs[0].location = 0; attrs[0].binding = 0;
    attrs[0].format   = VK_FORMAT_R32G32B32A32_SFLOAT; attrs[0].offset = 0;
    attrs[1].location = 1; attrs[1].binding = 1;
    attrs[1].format   = VK_FORMAT_R32G32B32A32_SFLOAT; attrs[1].offset = 16;

    VkPipelineVertexInputStateCreateInfo vi {
        VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO };
    vi.vertexBindingDescriptionCount   = 1;
    vi.pVertexBindingDescriptions      = &bind;
    vi.vertexAttributeDescriptionCount = 2;
    vi.pVertexAttributeDescriptions    = attrs;

    VkPipelineInputAssemblyStateCreateInfo ia {
        VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO };
    ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;

    VkPipelineViewportStateCreateInfo vp {
        VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO };
    vp.viewportCount = 1;
    vp.scissorCount  = 1;

    VkPipelineRasterizationStateCreateInfo rs {
        VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO };
    rs.polygonMode = VK_POLYGON_MODE_FILL;
    rs.cullMode    = VK_CULL_MODE_NONE;
    rs.frontFace   = VK_FRONT_FACE_COUNTER_CLOCKWISE;
    rs.lineWidth   = 1.0f;

    VkPipelineMultisampleStateCreateInfo ms {
        VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO };
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;

    VkPipelineColorBlendAttachmentState cba {};
    cba.colorWriteMask = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT
                       | VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT;
    VkPipelineColorBlendStateCreateInfo cb {
        VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO };
    cb.attachmentCount = 1;
    cb.pAttachments    = &cba;

    VkDynamicState dyns[2] = { VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR };
    VkPipelineDynamicStateCreateInfo dyn {
        VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO };
    dyn.dynamicStateCount = 2;
    dyn.pDynamicStates    = dyns;

    VkPipelineShaderStageCreateInfo stages[2] {};
    stages[0].sType  = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage  = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = g_pmVs;
    stages[0].pName  = "main";
    stages[1].sType  = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage  = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = g_pmFs;
    stages[1].pName  = "main";

    VkGraphicsPipelineCreateInfo pci { VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO };
    pci.stageCount          = 2;
    pci.pStages             = stages;
    pci.pVertexInputState   = &vi;
    pci.pInputAssemblyState = &ia;
    pci.pViewportState      = &vp;
    pci.pRasterizationState = &rs;
    pci.pMultisampleState   = &ms;
    pci.pDepthStencilState  = nullptr;   // глубинного вложения нет
    pci.pColorBlendState    = &cb;
    pci.pDynamicState       = &dyn;
    pci.layout              = g_pmLayout;
    pci.renderPass          = g_pmPass;
    pci.subpass             = 0;
    if (pCreatePipelines(g_dev, VK_NULL_HANDLE, 1, &pci, nullptr, &g_pmPipe)
            != VK_SUCCESS) {
        printf("[GPU]   vkCreateGraphicsPipelines не удался\n");
        fflush(stdout);
        g_pmFailed = true; return false;
    }

    // Вершинный буфер 96 байт: хост-память, пишем треугольник один раз.
    VkBufferCreateInfo bci { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    bci.size  = sizeof(kProxyTri);
    bci.usage = VK_BUFFER_USAGE_VERTEX_BUFFER_BIT;
    bci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (pCreateBuffer(g_dev, &bci, nullptr, &g_pmVb) != VK_SUCCESS) {
        g_pmFailed = true; return false;
    }
    VkMemoryRequirements rq;
    pBufReqs(g_dev, g_pmVb, &rq);
    if (!AllocFor(rq, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT
                     | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT, &g_pmVbMem)) {
        g_pmFailed = true; return false;
    }
    if (pBindBuffer(g_dev, g_pmVb, g_pmVbMem, 0) != VK_SUCCESS) {
        g_pmFailed = true; return false;
    }
    if (pMapMem(g_dev, g_pmVbMem, 0, VK_WHOLE_SIZE, 0, &g_pmVbMap) != VK_SUCCESS) {
        g_pmFailed = true; return false;
    }
    memcpy(g_pmVbMap, kProxyTri, sizeof(kProxyTri));

    EnsurePm4Fb();
    g_pmReady = true;
    printf("[GPU] шаг: PM4-пайплайн ок (шейдеров гостя нет — прокси, это фаза 5.3)\n");
    fflush(stdout);
    return true;
}

// Фреймбуфер под текущий оффскрин. Создаётся при создании кадра (если пайплайн
// уже жив) или лениво здесь после первой инициализации пайплайна.
static bool EnsurePm4Fb() {
    if (g_offFb || !g_offView || !g_pmPass) return g_offFb != VK_NULL_HANDLE;
    VkFramebufferCreateInfo fci { VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO };
    fci.renderPass      = g_pmPass;
    fci.attachmentCount = 1;
    fci.pAttachments    = &g_offView;
    fci.width  = g_offW;
    fci.height = g_offH;
    fci.layers = 1;
    if (pCreateFb(g_dev, &fci, nullptr, &g_offFb) != VK_SUCCESS) {
        printf("[GPU] vkCreateFramebuffer (оффскрин) не удался\n");
        fflush(stdout);
        return false;
    }
    return true;
}

// Отрисовка PM4-кадра: очистка + прокси-треугольник в оффскрин.
// Инвариант лейаута соблюдён: после render pass оффскрин в TRANSFER_SRC.
bool RenderPm4(uint32_t vertices) {
    if (g_winClosed || g_noDevice || !g_dev) return false;
    if (!g_pmReady && !InitPm4Pipeline()) return false;
    if (!EnsurePm4Fb()) return false;

    PumpMessages();
    if (g_winClosed) return false;

    VkCommandBufferBeginInfo bi { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    pResetCmd(g_cmd, 0);
    if (pBeginCmd(g_cmd, &bi) != VK_SUCCESS) return false;

    VkClearValue clear;
    clear.color = { { 0.02f, 0.02f, 0.06f, 1.0f } };
    VkRenderPassBeginInfo rbi { VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO };
    rbi.renderPass      = g_pmPass;
    rbi.framebuffer     = g_offFb;
    rbi.renderArea.extent = { g_offW, g_offH };
    rbi.clearValueCount = 1;
    rbi.pClearValues    = &clear;
    pCmdBeginPass(g_cmd, &rbi, VK_SUBPASS_CONTENTS_INLINE);

    VkViewport vp { 0.0f, 0.0f, (float)g_offW, (float)g_offH, 0.0f, 1.0f };
    VkRect2D   sc { { 0, 0 }, { g_offW, g_offH } };
    pCmdSetViewport(g_cmd, 0, 1, &vp);
    pCmdSetScissor(g_cmd, 0, 1, &sc);
    pCmdBindPipe(g_cmd, VK_PIPELINE_BIND_POINT_GRAPHICS, g_pmPipe);

    VkDeviceSize off = 0;
    pCmdBindVb(g_cmd, 0, 1, &g_pmVb, &off);

    const uint32_t n = vertices < 3 ? vertices : 3;
    pCmdDraw(g_cmd, n, 1, 0, 0);
    pCmdEndPass(g_cmd);
    if (pEndCmd(g_cmd) != VK_SUCCESS) return false;

    VkSubmitInfo si { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    si.commandBufferCount = 1;
    si.pCommandBuffers    = &g_cmd;
    if (pSubmit(g_queue, 1, &si, VK_NULL_HANDLE) != VK_SUCCESS) return false;
    pQueueIdle(g_queue);   // фаза 5.0: простота важнее скорости

    g_offLayout = OffLayout::TransferSrc;
    printf("[GPU]   PM4-рендер: прокси-треугольник (%u вершин запрошено)\n", vertices);
    fflush(stdout);
    return true;
}

// Общий хвост кадра (CPU-путь и PM4-путь): оффскрин (уже в TRANSFER_SRC)
// -> картинка свапчейна -> PRESENT_SRC. КБ должен быть в записи.
static void CmdOffToSwap(VkCommandBuffer cb, uint32_t idx, uint32_t cw, uint32_t ch) {
    Barrier(cb, g_swImg[idx],
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
    pCmdCopyImg(cb, g_off, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                g_swImg[idx], VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &cp);

    Barrier(cb, g_swImg[idx],
            VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,
            VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT,
            VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT, 0);
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
        // 1) буфер -> оффскрин: барьер из ФАКТИЧЕСКОГО текущего лейаута
        //    (инвариант прошлого кадра — TRANSFER_SRC).
        if (g_offLayout == OffLayout::Undefined) {
            Barrier(g_cmd, g_off,
                    VK_IMAGE_LAYOUT_UNDEFINED, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                    VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT, 0,
                    VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT);
            g_offLayout = OffLayout::TransferDst;
        } else if (g_offLayout == OffLayout::TransferSrc) {
            Barrier(g_cmd, g_off,
                    VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                    VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_READ_BIT,
                    VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT);
            g_offLayout = OffLayout::TransferDst;
        }
        VkBufferImageCopy reg;
        memset(&reg, 0, sizeof(reg));
        reg.imageSubresource.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        reg.imageSubresource.layerCount = 1;
        reg.imageExtent = { cw, ch, 1 };
        pCmdCopyBufToImg(g_cmd, g_stage, g_off,
                         VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, 1, &reg);

        // 2) оффскрин в TRANSFER_SRC — инвариант и для CPU, и для PM4-пути
        Barrier(g_cmd, g_off,
                VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_WRITE_BIT,
                VK_PIPELINE_STAGE_TRANSFER_BIT, VK_ACCESS_TRANSFER_READ_BIT);
        g_offLayout = OffLayout::TransferSrc;

        // 3) оффскрин -> картинка свапчейна -> на показ (общий хвост путей)
        CmdOffToSwap(g_cmd, idx, cw, ch);
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

// Показ PM4-кадра: оффскрин уже содержит треугольник (RenderPm4) и лежит в
// TRANSFER_SRC — просто копируем в свапчейн и показываем.
bool PresentPm4(uint32_t w, uint32_t h) {
    if (g_winClosed || g_noDevice || !g_dev || !g_swap) return false;
    if (!g_pmReady || !g_offFb) return false;   // рендера не было — показывать нечего

    PumpMessages();
    if (g_winClosed) return false;

    uint32_t idx = 0;
    VkResult r = pAcquire(g_dev, g_swap, UINT64_MAX, g_semAcq, VK_NULL_HANDLE, &idx);
    if (r == VK_ERROR_OUT_OF_DATE_KHR) {
        if (!RecreateSwapchain()) return false;
        r = pAcquire(g_dev, g_swap, UINT64_MAX, g_semAcq, VK_NULL_HANDLE, &idx);
    }
    if (r != VK_SUCCESS && r != VK_SUBOPTIMAL_KHR) return false;

    const uint32_t cw = w < g_ext.width  ? w : g_ext.width;
    const uint32_t ch = h < g_ext.height ? h : g_ext.height;
    if (cw == 0 || ch == 0) return false;

    VkCommandBufferBeginInfo bi { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    pResetCmd(g_cmd, 0);
    if (pBeginCmd(g_cmd, &bi) != VK_SUCCESS) return false;

    CmdOffToSwap(g_cmd, idx, cw, ch);

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
    if (r == VK_ERROR_OUT_OF_DATE_KHR) RecreateSwapchain();

    pQueueIdle(g_queue);
    return true;
}

void Shutdown() {
    if (g_dev) pDevIdle(g_dev);
    DestroyFrame();   // фреймбуфер+view оффскрина — вместе с image
    if (g_pmPipe)   { pDestroyPipeline(g_dev, g_pmPipe, nullptr); g_pmPipe = VK_NULL_HANDLE; }
    if (g_pmLayout) { pDestroyPipeLayout(g_dev, g_pmLayout, nullptr); g_pmLayout = VK_NULL_HANDLE; }
    if (g_pmPass)   { pDestroyPass(g_dev, g_pmPass, nullptr); g_pmPass = VK_NULL_HANDLE; }
    if (g_pmVs)     { pDestroyShader(g_dev, g_pmVs, nullptr); g_pmVs = VK_NULL_HANDLE; }
    if (g_pmFs)     { pDestroyShader(g_dev, g_pmFs, nullptr); g_pmFs = VK_NULL_HANDLE; }
    if (g_pmVb)     { pDestroyBuffer(g_dev, g_pmVb, nullptr); g_pmVb = VK_NULL_HANDLE; }
    if (g_pmVbMem)  { pFreeMem(g_dev, g_pmVbMem, nullptr); g_pmVbMem = VK_NULL_HANDLE; }
    g_pmVbMap = nullptr;
    g_pmReady = false;
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
bool RenderPm4(uint32_t) { SayOnce(); return false; }
bool PresentPm4(uint32_t, uint32_t) { return false; }
void Shutdown() {}
bool DeviceAlive() { return false; }
void SetPreferredDevice(int) {}
int Probe(int) { SayOnce(); return -1; }

#endif

} } // namespace zrx::gpu_vk
