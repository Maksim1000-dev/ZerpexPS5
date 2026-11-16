// ============================================================================
// ZerpexPS5 — фаза 5: GPU HLE (реализация: маршрутизация имён импортов)
//
// Имена импортов приходят из заглушек (dyn.cpp). Реализовано честно:
//   sceVideoOut*   — окно/буферы/флипы (пиксели берём ИЗ ПАМЯТИ ГОСТЯ);
//   sceGnmMap/UnmapMemory — лог + 0 (память у нас и так гостевая);
//   sceGnmSubmit*  — разведка: лог содержимого, возврат 0 (фаза 5.1).
// Всё остальное — лог одного раза + 0.
// ============================================================================
#include "gpu.h"
#include "gpu_vk.h"
#include "pm4.h"   // фаза 5.1: разбор PM4-потока гостя

#include <windows.h>   // Sleep() в sceVideoOutWaitVblank

#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace zrx {
namespace gpu {

static Memory* g_mem = nullptr;

// --- Учёт вызовов (для итоговой сводки) -------------------------------------
static std::map<std::string, int> g_hits;
static std::set<std::string>      g_once;      // лог "один раз" для заглушек
static int g_opens = 0, g_regs = 0, g_flips = 0;

void AttachMemory(Memory* mem) { g_mem = mem; }

bool Handles(const char* name) {
    if (!name) return false;
    return strncmp(name, "sceVideoOut", 11) == 0
        || strncmp(name, "sceGnm", 6) == 0;
}

static void LogCall(const char* name, const uint64_t args[8], int n) {
    printf("[GPU] %-40s (0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX)%s\n",
           name,
           (unsigned long long)args[0], (unsigned long long)args[1],
           (unsigned long long)args[2], (unsigned long long)args[3],
           (unsigned long long)args[4], (unsigned long long)args[5],
           n > 50 ? "  (повторы...)" : "");
    fflush(stdout);
}

// Кап лога на вызов: обычные — 50, покадровые (каждый кадр) — 8, иначе
// консоль тонет в повторах. Итог всё равно честный — в PrintRunSummary.
static int LogCapFor(const char* name) {
    if (strcmp(name, "sceVideoOutSubmitFlip") == 0 ||
        strcmp(name, "sceVideoOutWaitVblank") == 0 ||
        strcmp(name, "sceVideoOutGetResolutionStatus") == 0 ||
        strcmp(name, "sceVideoOutIsProcessingFlip") == 0)
        return 8;
    return 50;
}

// --- Зарегистрированные кадровые буферы -------------------------------------
struct RegBuffer {
    uint64_t guestAddr = 0;   // где гость рисует кадр
    uint32_t width = 0, height = 0;
    uint64_t bytes = 0;       // размер кадра (pitch*height*4)
};
static std::vector<RegBuffer> g_bufs;

// --- Фаза 5.2: режим рендера из PM4 -----------------------------------------
// После submit с DRAW_INDEX_AUTO первый флип показывает прокси-треугольник,
// а дальше — этот же PM4-кадр, ПОКА гость не перепишет свои буферы
// (обнаружение — FNV-1a 64 по содержимому). Тогда возвращаемся к CPU-копии.
static bool     g_pm4Mode    = false;   // флипы показывают PM4-кадр
static bool     g_pm4Pending = false;   // в последнем submit был DRAW
static uint32_t g_pm4Verts   = 0;       // вершин в последнем DRAW
static std::vector<uint64_t> g_bufHash; // базовые хэши буферов (на 1-м PM4-флипе)

static uint64_t BufHash(const uint8_t* p, uint64_t n) {
    uint64_t h = 0xCBF29CE484222325ull;   // FNV-1a 64
    for (uint64_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 0x100000001B3ull;
    }
    return h;
}

// --- sceVideoOut* -----------------------------------------------------------
static int64_t VideoOutOpen(const uint64_t args[8]) {
    ++g_opens;
    const int64_t handle = g_opens;    // PS5 даёт дескриптор >= 0
    printf("[GPU]   sceVideoOutOpen: user=%llu type=%llu idx=%llu -> хэндл %lld\n"
           "          (окно 1280x720 + свапчейн создадутся при RegisterBuffers)\n",
           (unsigned long long)args[0], (unsigned long long)args[1],
           (unsigned long long)args[2], handle);
    fflush(stdout);
    return handle;
}

static int64_t VideoOutGetResolutionStatus(const uint64_t args[8]) {
    // SceVideoOutResolutionStatus: width, height, pixelDensity,
    // refreshRate (0.001 Гц), screenSizeInInch — по 4 байта.
    if (!g_mem) return -14;
    uint8_t* p = g_mem->Ptr(args[1]);
    if (!p) return -14;
    const uint32_t w = 1280, h = 720, density = 1, rate = 60000;
    const float inch = 27.0f;
    memcpy(p + 0,  &w, 4);
    memcpy(p + 4,  &h, 4);
    memcpy(p + 8,  &density, 4);
    memcpy(p + 12, &rate, 4);
    memcpy(p + 16, &inch, 4);
    printf("[GPU]   GetResolutionStatus -> 1280x720 @ 60 Гц\n");
    fflush(stdout);
    return 0;
}

static int64_t VideoOutRegisterBuffers(const uint64_t args[8]) {
    ++g_regs;
    const uint64_t addrsPtr   = args[2];
    const uint32_t numBuffers = (uint32_t)args[3];
    const uint64_t attrPtr    = args[4];

    if (!g_mem || !addrsPtr || numBuffers == 0 || numBuffers > 8) {
        printf("[GPU]   RegisterBuffers: странные аргументы — отказываю "
               "(bufs=0x%llX n=%u)\n",
               (unsigned long long)addrsPtr, numBuffers);
        fflush(stdout);
        return -22;
    }

    // SceVideoOutBufferAttribute (PS4/PS5): pixelFormat@0, tilingMode@4,
    // aspectRatio@8, width@12, height@16, pitchInPixel@20, option@24,
    // (пад @28), memorySize@32.
    uint32_t fmt = 0, width = 0, height = 0, pitch = 0;
    uint64_t memSize = 0;
    if (attrPtr) {
        const uint8_t* a = g_mem->Ptr(attrPtr);
        if (a) {
            memcpy(&fmt, a, 4);
            memcpy(&width, a + 12, 4);
            memcpy(&height, a + 16, 4);
            memcpy(&pitch, a + 20, 4);
            memcpy(&memSize, a + 32, 8);
        }
    }
    if (!width  || width  > 4096) {
        printf("[GPU]   атрибут без внятного размера (%u) — считаю 1280\n", width);
        width = 1280;
    }
    if (!height || height > 4096) {
        printf("[GPU]   атрибут без внятной высоты (%u) — считаю 720\n", height);
        height = 720;
    }
    if (pitch < width) pitch = width;
    uint64_t bytes = (uint64_t)pitch * height * 4;   // формат BGRA8 — 4 б/пикс
    if (memSize && memSize < bytes) bytes = memSize; // честно берём меньше

    const uint8_t* ap = g_mem->Ptr(addrsPtr);
    if (!ap) {
        printf("[GPU]   RegisterBuffers: таблица адресов не мапнута\n");
        fflush(stdout);
        return -14;
    }
    printf("[GPU]   RegisterBuffers: формат 0x%08X, %ux%u, pitch=%u, буферов %u:\n",
           fmt, width, height, pitch, numBuffers);
    for (uint32_t i = 0; i < numBuffers; ++i) {
        uint64_t ga = 0;
        memcpy(&ga, ap + (size_t)i * 8, 8);
        RegBuffer b;
        b.guestAddr = ga;
        b.width = width;
        b.height = height;
        b.bytes = bytes;
        g_bufs.push_back(b);
        printf("[GPU]     буфер[%u] guest 0x%llX (%llu байт)\n",
               i, (unsigned long long)ga, (unsigned long long)bytes);
    }
    g_bufHash.assign(g_bufs.size(), 0);   // базы заполнятся на 1-м PM4-флипе
    fflush(stdout);

    if (!gpu_vk::Prepare(width, height, bytes)) {
        // Окно может открыться даже без устройства; гость продолжит,
        // но кадров не увидит — честно написано в логе gpu_vk.
        printf("[GPU]   (Vulkan-слой не готов — кадры выводиться не будут)\n");
        fflush(stdout);
    }
    return 0;
}

static int64_t VideoOutSubmitFlip(const uint64_t args[8]) {
    ++g_flips;
    const int64_t bufIndex = (int64_t)args[1];

    if (bufIndex < 0 || (size_t)bufIndex >= g_bufs.size()) {
        const bool first = g_once.insert("flip-диапазон").second;
        if (first) {
            printf("[GPU]   SubmitFlip: буфер #%lld вне диапазона (%u зарегистр.)"
                   " — кадр пропускаю\n", bufIndex, (unsigned)g_bufs.size());
            fflush(stdout);
        }
        return 0;
    }

    const RegBuffer& b = g_bufs[(size_t)bufIndex];
    uint8_t* src = g_mem ? g_mem->Ptr(b.guestAddr) : nullptr;
    if (!src) {
        const bool first = g_once.insert("flip-память").second;
        if (first) {
            printf("[GPU]   SubmitFlip: память буфера 0x%llX не мапнута — пропускаю\n",
                   (unsigned long long)b.guestAddr);
            fflush(stdout);
        }
        return 0;
    }

    // --- Фаза 5.2: рендер из PM4 --------------------------------------------
    // Рисуем и/или показываем PM4-кадр, пока содержимое буфера не изменилось.
    const uint64_t h = BufHash(src, b.bytes);
    uint64_t& base = g_bufHash[(size_t)bufIndex];

    if (g_pm4Mode) {
        if (base != 0 && h != base) {
            // Гость переписал буфер своими руками — честно возвращаемся к CPU-копии.
            printf("[GPU]   PM4: буфер #%lld переписан гостем — возврат к CPU-копии\n",
                   bufIndex);
            fflush(stdout);
            g_pm4Mode = false;
            base = 0;
        } else if (gpu_vk::PresentPm4(b.width, b.height)) {
            return 0;   // PM4-кадр показан
        }
        // PresentPm4 не удался — упадём ниже на CPU-путь (он сам отчитается)
    } else if (g_pm4Pending) {
        // Первый флип после submit с DRAW: рисуем прокси и запоминаем базы.
        g_pm4Pending = false;
        if (gpu_vk::RenderPm4(g_pm4Verts)) {
            if (gpu_vk::PresentPm4(b.width, b.height)) {
                g_pm4Mode = true;
                base = h;
                for (size_t i = 0; i < g_bufs.size(); ++i) {
                    const uint8_t* p = g_mem->Ptr(g_bufs[i].guestAddr);
                    g_bufHash[i] = p ? BufHash(p, g_bufs[i].bytes) : 0;
                }
                printf("[GPU]   PM4: режим включён — флипы показывают PM4-кадр, "
                       "пока гость не перепишет буферы\n");
                fflush(stdout);
                return 0;
            }
        }
        // Не удалось — CPU-путь продолжит как раньше, режим не включаем.
    }

    uint64_t stageSize = 0;
    void* dst = gpu_vk::StagePtr(&stageSize);
    if (!dst) return 0;    // Vulkan не готов — уже отчитались

    const uint64_t n = b.bytes < stageSize ? b.bytes : stageSize;
    memcpy(dst, src, (size_t)n);
    gpu_vk::Present(b.width, b.height, n);
    return 0;
}

static int64_t VideoOutSetFlipRate(const uint64_t args[8]) {
    printf("[GPU]   SetFlipRate: rate=%llu (vsync оставляю как есть)\n",
           (unsigned long long)args[1]);
    fflush(stdout);
    return 0;
}

static int64_t VideoOutWaitVblank(const uint64_t args[8]) {
    Sleep(16);                                  // ~1 кадр при 60 Гц
    return 0;
}

static int64_t VideoOutClose(const uint64_t args[8]) {
    printf("[GPU]   VideoOutClose: хэндл %llu (окно оставляю — закроется при выходе)\n",
           (unsigned long long)args[0]);
    fflush(stdout);
    return 0;
}

// --- sceGnm* ----------------------------------------------------------------
static int64_t GnmMapMemory(const uint64_t args[8]) {
    printf("[GPU]   gnmMapMemory: addr=0x%llX size=%llu type=%llu -> 0\n",
           (unsigned long long)args[0], (unsigned long long)args[1],
           (unsigned long long)args[2]);
    fflush(stdout);
    return 0;
}

static int64_t GnmUnmapMemory(const uint64_t args[8]) {
    printf("[GPU]   gnmUnmapMemory: addr=0x%llX size=%llu -> 0\n",
           (unsigned long long)args[0], (unsigned long long)args[1]);
    fflush(stdout);
    return 0;
}

// Достаём хост-указатель гостевой памяти для вложенных INDIRECT_BUFFER.
static const uint32_t* Pm4Resolve(uint64_t addr, uint64_t bytes, void*) {
    return g_mem ? reinterpret_cast<const uint32_t*>(g_mem->Ptr(addr)) : nullptr;
}

// Разобрать и напечатать один командный буфер (фаза 5.1/5.2).
// frame (если не nullptr) — сводка для режима рендера из PM4.
static void Pm4DumpOne(uint32_t idx, uint64_t guestAddr, uint64_t bytes,
                       pm4::Frame* frame) {
    printf("[GPU]     буфер[%u]: guest 0x%llX, %llu байт\n", idx,
           (unsigned long long)guestAddr, (unsigned long long)bytes);
    if (!bytes) return;
    if (bytes > (1ull << 22)) {           // > 4 МБ — не читаем чужой мусор
        printf("[GPU]     буфер[%u]: слишком большой для разбора (> 4 МБ)\n", idx);
        return;
    }
    const uint32_t* d = Pm4Resolve(guestAddr, bytes, nullptr);
    if (!d) {
        printf("[GPU]     буфер[%u]: память не мапнута — разбора нет\n", idx);
        return;
    }
    pm4::DumpStream("командный буфер", d, (uint32_t)(bytes / 4), 0,
                    &Pm4Resolve, nullptr, frame);
}

// Суммарная сводка всех буферов submit'а (что парсер увидел).
static void Pm4PrintFrame(const pm4::Frame& f) {
    if (f.hasDraw)
        printf("[GPU]     PM4-сводка: DRAW есть, вершин (последний) %u\n", f.drawCount);
    else
        printf("[GPU]     PM4-сводка: DRAW не было\n");
}

static int64_t GnmSubmitCommandBuffers(const uint64_t args[8]) {
    // Раскладка по Orbis (подтвердится на реальном дампе): логично
    // (queue, count, cmdBufs[], sizes[], флаги в хвосте).
    const uint32_t queue  = (uint32_t)args[0];
    const uint32_t n      = (uint32_t)args[1];
    const uint64_t cmdsP  = args[2];
    const uint64_t sizesP = args[3];
    printf("[GPU]   gnmSubmitCommandBuffers: queue=%u, буферов %u (фаза 5.1: разбор PM4)\n",
           queue, n);
    pm4::Frame frame;
    if (n && n <= 8 && cmdsP && sizesP) {
        for (uint32_t b = 0; b < n; ++b) {
            const uint8_t* ap = g_mem ? g_mem->Ptr(cmdsP + b * 8)  : nullptr;
            const uint8_t* sp = g_mem ? g_mem->Ptr(sizesP + b * 4) : nullptr;
            if (!ap || !sp) {
                printf("[GPU]     буфер[%u]: нет памяти под дескриптор — пропуск\n", b);
                continue;
            }
            uint64_t addr = 0;
            uint32_t bytes = 0;
            memcpy(&addr, ap, 8);
            memcpy(&bytes, sp, 4);
            Pm4DumpOne(b, addr, bytes, &frame);
        }
    } else {
        printf("[GPU]     count=%u или указатели 0 — разбора нет\n", n);
    }
    Pm4PrintFrame(frame);
    if (frame.hasDraw && frame.drawCount) {
        // Кэш-линия в байтах для прокси-рендера не важна: рисуем свою геометрию.
        g_pm4Pending = true;
        g_pm4Verts   = frame.drawCount;
    }
    fflush(stdout);
    return 0;
}

static int64_t GnmSubmitAndFlip(const uint64_t args[8]) {
    // (queue, count, cmdBufs[], sizes[], flipMode, flipArg, ...) — флип в хвосте;
    // пока НЕ флипаем: командный буфер разбираем честно, кадр гостя не подменяем.
    const uint32_t queue  = (uint32_t)args[0];
    const uint32_t n      = (uint32_t)args[1];
    const uint64_t cmdsP  = args[2];
    const uint64_t sizesP = args[3];
    printf("[GPU]   gnmSubmitAndFlipCommandBuffers: queue=%u, буферов %u, "
           "flipMode=%llu flipArg=%llu (фаза 5.1: разбор PM4)\n",
           queue, n, (unsigned long long)args[4], (unsigned long long)args[5]);
    pm4::Frame frame;
    if (n && n <= 8 && cmdsP && sizesP) {
        for (uint32_t b = 0; b < n; ++b) {
            const uint8_t* ap = g_mem ? g_mem->Ptr(cmdsP + b * 8)  : nullptr;
            const uint8_t* sp = g_mem ? g_mem->Ptr(sizesP + b * 4) : nullptr;
            if (!ap || !sp) {
                printf("[GPU]     буфер[%u]: нет памяти под дескриптор — пропуск\n", b);
                continue;
            }
            uint64_t addr = 0;
            uint32_t bytes = 0;
            memcpy(&addr, ap, 8);
            memcpy(&bytes, sp, 4);
            Pm4DumpOne(b, addr, bytes, &frame);
        }
    } else {
        printf("[GPU]     count=%u или указатели 0 — разбора нет\n", n);
    }
    Pm4PrintFrame(frame);
    if (frame.hasDraw && frame.drawCount) {
        g_pm4Pending = true;
        g_pm4Verts   = frame.drawCount;
    }
    fflush(stdout);
    return 0;
}

static int64_t GnmSubmitDone(const uint64_t args[8]) {
    printf("[GPU]   gnmSubmitDone: queue=%llu -> 0\n",
           (unsigned long long)args[0]);
    fflush(stdout);
    return 0;
}

// --- Диспетчер ---------------------------------------------------------------
int64_t Execute(const char* name, const uint64_t args[8]) {
    if (!name || !name[0]) return 0;
    const int n = ++g_hits[name];
    const int cap = LogCapFor(name);
    if (n <= cap || (n % 200) == 0) {
        LogCall(name, args, n);
    } else if (n == cap + 1) {
        // Один раз честно объясняем молчание: полностью — в итоговой сводке.
        printf("[GPU] %-40s — дальше не печатаю каждый вызов (x%d), итог в сводке\n",
               name, n);
        fflush(stdout);
    }

    if (strcmp(name, "sceVideoOutOpen") == 0)                      return VideoOutOpen(args);
    if (strcmp(name, "sceVideoOutGetResolutionStatus") == 0)       return VideoOutGetResolutionStatus(args);
    if (strcmp(name, "sceVideoOutRegisterBuffers") == 0)           return VideoOutRegisterBuffers(args);
    if (strcmp(name, "sceVideoOutSubmitFlip") == 0)                return VideoOutSubmitFlip(args);
    if (strcmp(name, "sceVideoOutSetFlipRate") == 0)               return VideoOutSetFlipRate(args);
    if (strcmp(name, "sceVideoOutWaitVblank") == 0)                return VideoOutWaitVblank(args);
    if (strcmp(name, "sceVideoOutIsProcessingFlip") == 0)          return 0;
    if (strcmp(name, "sceVideoOutClose") == 0)                     return VideoOutClose(args);
    if (strcmp(name, "sceGnmMapMemory") == 0)                      return GnmMapMemory(args);
    if (strcmp(name, "sceGnmUnmapMemory") == 0)                    return GnmUnmapMemory(args);
    if (strcmp(name, "sceGnmSubmitCommandBuffers") == 0)           return GnmSubmitCommandBuffers(args);
    if (strcmp(name, "sceGnmSubmitAndFlipCommandBuffers") == 0)    return GnmSubmitAndFlip(args);
    if (strcmp(name, "sceGnmSubmitDone") == 0)                     return GnmSubmitDone(args);

    // Неизвестный GPU-импорт: имя в лог один раз, гостю 0.
    const bool first = g_once.insert(std::string(name)).second;
    if (first) {
        printf("[GPU]   %-40s — заглушка фазы 5.1 (разведка скажет, что он делает)\n", name);
        fflush(stdout);
    }
    return 0;
}

void PrintRunSummary() {
    printf("[GPU] Итог прогона:\n");
    if (g_hits.empty()) {
        printf("[GPU]   GPU-вызовов не было\n");
        return;
    }
    int total = 0;
    for (const auto& kv : g_hits) {
        printf("[GPU]   %-40s x%d\n", kv.first.c_str(), kv.second);
        total += kv.second;
    }
    printf("[GPU]   всего: %d вызовов (open=%d, register=%d, флипов=%d)\n",
           total, g_opens, g_regs, g_flips);
    printf("[GPU]   PM4-рендер: %s\n",
           g_pm4Mode ? "прокси-треугольник показывался (фаза 5.2)"
                     : "не активирован (CPU-копия кадра, как в 5.0)");
}

void Shutdown() { gpu_vk::Shutdown(); }

} } // namespace zrx::gpu
