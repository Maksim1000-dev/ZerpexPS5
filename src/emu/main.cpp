// ============================================================================
// ZerpexPS5 — ядро эмулятора · v0.8.2
// (фазы: 2.5 анализ · 4 исполнение · 5.2 PM4-рендер · 5.3 транслятор RDNA2 ·
//        7.1–7.7.2 запуск ELF: VEH-bail без longjmp, куча, TLS, kernel-args)
//
// ЧТО ЕСТЬ:  парсер ELF64 + SELF PS5, память на VirtualAlloc, HLE-диспетчер,
//            НАТИВНОЕ ИСПОЛНЕНИЕ гостевого x86-64 с перехватом syscall'ов
//            (патч syscall->UD2 + VEH), релокации PT_DYNAMIC с импорт-заглушками,
//            ПОТОКИ гостя, ФАЙЛЫ (/app0 -> папка игры), ПЕРВЫЙ ПИКСЕЛЬ и
//            PM4-кадр (прокси-треугольник), транслятор RDNA2->SPIR-V (5.3),
//            сплаш "иконка игры + RUNNED WITH ZerpexPS5" до первого кадра.
// ЧЕГО НЕТ:  полного GNM-пайплайна (импорты добираются итерациями),
//            дешифровки retail SELF (фаза 7, только там нужны ключи).
//
// Использование:
//   ZerpexPS5.exe <файл eboot.bin/eboot.elf | папка игры>   — анализ или запуск
//   ZerpexPS5.exe --gpu-demo [путь к игре]                  — окно+сплаш+треугольник
//   ZerpexPS5.exe --corpus <папка с дампами>                — корпус-сравнение
//
// Правила хозяина: ничего не скачивать; собранный EXE не запускать самому.
// ============================================================================
#include <windows.h>
#include <shellapi.h>
#include <io.h>            // _dup/_dup2/_open_osfhandle (фаз 7.5.1: файловый лог)
#include <fcntl.h>         // _O_WRONLY

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "../core/elf.h"
#include "../core/mem.h"
#include "../core/hle.h"
#include "../core/dyn.h"
#include "../version.h"
#include "exec.h"
#include "gpu.h"
#include "gpu_vk.h"   // приоритет видеокарты (--gpu N из лаунчера)
#include "analyze.h"

namespace fs = std::filesystem;

// Папка, откуда взят запускаемый ELF (корень игры для /app0; фаза 4)
static std::wstring g_ebootDir;

// ----------------------------------------------------------------------------
// Утилиты
// ----------------------------------------------------------------------------
static std::string Utf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)(n > 0 ? n : 0), '\0');
    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::string HumanSize(uint64_t b) {
    char buf[64];
    if (b >= 1024ull * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.2f GB", (double)b / (1024.0 * 1024 * 1024));
    else if (b >= 1024ull * 1024)
        snprintf(buf, sizeof(buf), "%.2f MB", (double)b / (1024.0 * 1024));
    else if (b >= 1024)
        snprintf(buf, sizeof(buf), "%.2f KB", (double)b / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%u B", (unsigned)b);
    return buf;
}

static std::wstring FindEboot(const std::wstring& dir) {
    std::wstring elf;
    std::error_code ec;
    for (fs::directory_iterator it(fs::path(dir), fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        const std::wstring name = it->path().filename().wstring();
        if (_wcsicmp(name.c_str(), L"eboot.bin") == 0)
            return it->path().wstring();
        if (_wcsicmp(name.c_str(), L"eboot.elf") == 0)
            elf = it->path().wstring();
    }
    return elf;
}

static std::vector<uint8_t> ReadAll(const std::wstring& path) {
    std::vector<uint8_t> data;
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) return data;
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string s = ss.str();
    data.assign(s.begin(), s.end());
    return data;
}

static void Line() { printf("------------------------------------------------------------\n"); }

// ----------------------------------------------------------------------------
// Пауза: окно консоли не закрывается само — вывод можно дочитать/скопировать.
// ----------------------------------------------------------------------------
static void PauseBeforeExit() {
    printf("\n[Нажми Enter, чтобы закрыть окно]\n");
    fflush(stdout);
    char buf[16];
    if (fgets(buf, sizeof(buf), stdin)) {
        // что-то ввели — просто выходим
    }
    // Фаза 7.6.1: даём фоновому тиру добить хвост лога перед смертью процесса.
    fflush(nullptr);
    Sleep(300);
}

// Последний шанс: жёсткий краш мимо нашего VEH (баг хоста, а не гостя).
// Печатаем что произошло, держим окно открытым и выходим с кодом 2.
static bool g_probeAny = false;   // --vkprobe: не ставим паузу (дети-процессы)

static LONG WINAPI LastChanceFilter(LPEXCEPTION_POINTERS ep) {
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const uintptr_t addr = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;

    // Модуль по адресу краша: видно, чей это код — наш EXE, vulkan-1.dll
    // или драйвер ICD (nvoglv64 и т.п.).
    HMODULE mod = nullptr;
    char modName[MAX_PATH] = "(модуль не определён)";
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)addr, &mod) && mod)
        GetModuleFileNameA(mod, modName, sizeof(modName));

    printf("\n[КРАШ] необработанное исключение 0x%08lX по адресу 0x%llX\n",
           (unsigned long)code, (unsigned long long)addr);
    printf("[КРАШ] модуль: %s\n", modName);
    if (code == 0xC0000005) {   // AV: читали/писали/исполняли и по какому адресу
        const ULONG_PTR m = ep->ExceptionRecord->ExceptionInformation[0];
        const ULONG_PTR d = ep->ExceptionRecord->ExceptionInformation[1];
        printf("[КРАШ] операция: %s, адрес данных 0x%llX\n",
               m == 1 ? "запись" : (m == 8 ? "исполнение (плохой call/jmp?)" : "чтение"),
               (unsigned long long)d);
    }

    // Стек вызовов: фильтр работает на упавшей нити, поэтому RtlCaptureStack
    // BackTrace даёт именно её цепочку. Для каждого кадра — модуль + офсет.
    void* fr[20] = {};
    const USHORT nf = RtlCaptureStackBackTrace(0, 20, fr, nullptr);
    printf("[КРАШ] стек (%u):\n", (unsigned)nf);
    for (USHORT k = 0; k < nf; ++k) {
        const uintptr_t a = (uintptr_t)fr[k];
        HMODULE m = nullptr;
        char mn[MAX_PATH] = "?";
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)a, &m) && m) {
            GetModuleFileNameA(m, mn, sizeof(mn));
            const char* slash = strrchr(mn, '\\');
            printf("  %2u %s+0x%llX\n", (unsigned)(k + 1), slash ? slash + 1 : mn,
                   (unsigned long long)(a - (uintptr_t)m));
        } else {
            printf("  %2u 0x%llX\n", (unsigned)(k + 1), (unsigned long long)a);
        }
    }

    fflush(stdout);
    if (!g_probeAny) PauseBeforeExit();
    ExitProcess(2);
    return EXCEPTION_EXECUTE_HANDLER; // не достижимо, но компилятор доволен
}

// ----------------------------------------------------------------------------
// Отчёт по program headers (общий для открытого ELF и вложенного ELF в SELF)
// ----------------------------------------------------------------------------
static void PrintPhdrs(const zrx::ElfImage& e, uint64_t baseOffset) {
    printf("  program headers (%u):\n", (unsigned)e.phdrs.size());
    printf("     #  type       prot  offset          vaddr            filesz      memsz\n");
    for (size_t i = 0; i < e.phdrs.size(); ++i) {
        const zrx::ElfSegment& p = e.phdrs[i];
        char tname[32];
        if (p.type <= 7) {
            static const char* kn[] = { "NULL", "LOAD", "DYNAMIC", "INTERP", "NOTE", "SHLIB", "PHDR", "TLS" };
            snprintf(tname, sizeof(tname), "%s", kn[p.type]);
        } else if (p.type >= 0x61000000u && p.type <= 0x61FFFFFFu) {
            snprintf(tname, sizeof(tname), "SCE?(%08X)", p.type);
        } else {
            snprintf(tname, sizeof(tname), "0x%08X", p.type);
        }
        printf("   %3u  %-10s %-4s  0x%08llX    0x%012llX   %-10llu  %llu\n",
               (unsigned)i, tname, zrx::ProtStr(p.flags).c_str(),
               (unsigned long long)(baseOffset + p.offset),
               (unsigned long long)p.vaddr,
               (unsigned long long)p.filesz, (unsigned long long)p.memsz);
    }
    for (const std::string& n : e.dynNotes)
        printf("  [динамика] %s\n", n.c_str());
    for (const std::string& n : e.needed)
        printf("  [динамика] зависимость: %s\n", n.c_str());
}

// ----------------------------------------------------------------------------
// Иконка игры для сплаша: <игра>\sce_sys\icon0.png (как у PS5-дампов).
// path пуст -> автопоиск в decomp (локальные дампы рядом с ядром, gitignore).
// ----------------------------------------------------------------------------
static std::wstring FindGameIcon(const std::wstring& path) {
    std::error_code ec;
    auto isFile = [](const std::wstring& p) {
        std::error_code e2;
        return !p.empty() && fs::is_regular_file(fs::path(p), e2);
    };
    if (!path.empty()) {
        fs::path d = fs::is_directory(fs::path(path), ec) ? fs::path(path)
                                                          : fs::path(path).parent_path();
        for (int up = 0; up < 3 && !d.empty(); ++up) {
            const std::wstring c1 = (d / L"sce_sys" / L"icon0.png").wstring();
            if (isFile(c1)) return c1;
            const std::wstring c2 = (d / L"icon0.png").wstring();
            if (isFile(c2)) return c2;
            const fs::path parent = d.parent_path();
            if (parent.empty() || parent == d) break;
            d = parent;
        }
        return L"";
    }
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const fs::path base = fs::path(exe).parent_path();
    const fs::path roots[] = { base, base.parent_path(), fs::current_path(ec) };
    for (const fs::path& root : roots) {
        if (root.empty()) continue;
        const fs::path decomp = root / L"decomp";
        if (!fs::is_directory(decomp, ec)) continue;
        std::error_code e3;
        fs::recursive_directory_iterator it(decomp, fs::directory_options::skip_permission_denied, e3), end;
        for (; it != end; it.increment(e3)) {
            if (e3) { e3.clear(); continue; }
            std::error_code e4;
            if (it->is_regular_file(e4) && it->path().filename() == L"icon0.png" &&
                it->path().parent_path().filename() == L"sce_sys")
                return it->path().wstring();
        }
    }
    return L"";
}

// ----------------------------------------------------------------------------
// Путь ELF: разбор + маппинг + релокации + НАТИВНЫЙ ЗАПУСК (фаза 4)
// ----------------------------------------------------------------------------
static void RunElfProgram(const std::vector<uint8_t>& data) {
    zrx::ElfImage e;
    if (!zrx::ParseElf(data.data(), data.size(), &e)) {
        printf("  ОШИБКА разбора ELF: %s\n", e.error.c_str());
        return;
    }

    // --- Фаза 7.1: базо-относительный ELF ------------------------------------
    // PS5-игры (SCE_EXEC) держат все p_vaddr от нуля: реальный лоадер сам
    // выбирает базу. Наш identity-маппинг не может жить по адресу 0, поэтому
    // выбираем базу сами и прибавляем ко всем vaddr + entry. Абсолютные ELF
    // (hello3/hello4, vaddr 0x400000) базу не получают — поведение прежнее.
    uint64_t loadBase = 0;
    {
        uint64_t minV = ~0ull;
        for (size_t idx : e.loadIdx) {
            const zrx::ElfSegment& p = e.phdrs[idx];
            if (p.memsz && p.vaddr < minV) minV = p.vaddr;
        }
        if (!e.loadIdx.empty() && minV == 0) {
            loadBase = 0x400000;
            for (zrx::ElfSegment& p : e.phdrs) {
                if (p.type == zrx::PT_LOAD || p.vaddr != 0) p.vaddr += loadBase;
            }
            e.entry += loadBase;
            printf("  [база] PS5 ELF базо-относительный (vaddr от нуля) — "
                   "выбрана база 0x%llX, entry -> 0x%llX\n",
                   (unsigned long long)loadBase, (unsigned long long)e.entry);
        }
    }

    printf("  Тип: %s | CPU: %s | entry=0x%llX | OSABI=%u\n",
           zrx::ElfTypeName(e.type), zrx::MachineName(e.machine),
           (unsigned long long)e.entry, (unsigned)e.eiOsabi);
    PrintPhdrs(e, 0);

    printf("\n  [память] маппинг %u сегментов PT_LOAD:\n", (unsigned)e.loadIdx.size());
    zrx::Memory mem;
    // Фаза 7.2: резерв СПАН-а всего образа одним блоком. Сегменты PS5
    // примыкают внутри гранулы 64К (seg0 кончается на 0x1B47000, seg1
    // запрашивает 0x1B40000) — по отдельности они наезжали друг на друга
    // и «переезжали» на чужие адреса.
    {
        uint64_t lo = ~0ull, hi = 0;
        for (size_t idx : e.loadIdx) {
            const zrx::ElfSegment& p = e.phdrs[idx];
            if (!p.memsz) continue;
            const uint64_t b = p.vaddr & ~0xFFFull;
            const uint64_t e2 = (p.vaddr + p.memsz + 0xFFF) & ~0xFFFull;
            if (b < lo) lo = b;
            if (e2 > hi) hi = e2;
        }
        if (hi > lo && mem.ReserveSpan(lo, hi - lo)) {
            printf("  [память] резерв образа: 0x%llX .. 0x%llX (%.1f МБ)\n",
                   (unsigned long long)lo, (unsigned long long)hi,
                   (double)(hi - lo) / 1048576.0);
            fflush(stdout);
        }
    }
    for (size_t idx : e.loadIdx) {
        const zrx::ElfSegment& p = e.phdrs[idx];
        // Фаза 7.2: LOAD без прав (---) у Dead Cells содержит .dynamic —
        // лоадер обязан его ЧИТАТЬ (крэш чтения 0x2D4F478). Даём RW.
        const uint32_t mprot = p.flags ? p.flags : (zrx::PF_R | zrx::PF_W);
        const uint8_t* fileData = nullptr;
        if (p.filesz && p.offset + p.filesz <= data.size())
            fileData = data.data() + p.offset;
        else if (p.filesz) {
            printf("    ! сегмент #%u: данные вне файла (offset=0x%llX filesz=%llu) — пропускаю содержимое\n",
                   (unsigned)idx, (unsigned long long)p.offset, (unsigned long long)p.filesz);
        }
        const uint64_t actual = mem.Map(p.vaddr, fileData, p.filesz, p.memsz, mprot);
        if (!actual) {
            printf("    ! сегмент #%u: VirtualAlloc не удался\n", (unsigned)idx);
            continue;
        }
        printf("    vaddr 0x%012llX -> 0x%012llX  %-4s  filesz=%llu memsz=%llu%s\n",
               (unsigned long long)p.vaddr, (unsigned long long)actual,
               zrx::ProtStr(p.flags).c_str(),
               (unsigned long long)p.filesz, (unsigned long long)p.memsz,
               mem.Segments().back().relocated ? "  (перенесён — адрес занят)" : "");
        fflush(stdout);   // фаза 7.2: видно место крэша, если грохнем дальше
    }

    // --- Фаза 4: релокации ДО исполнения (патч сканирует уже исправленный код),
    // корень игры для /app0, потом HLE/запуск ---
    zrx::dyn::AttachMemory(&mem);
    zrx::dyn::SetLoadBase(loadBase);   // фаза 7.1: адреса динамики базо-относительные
    zrx::dyn::ResetStubs();
    zrx::dyn::ApplyRelocations(e);

    zrx::hle::AttachMemory(&mem);
    zrx::hle::SetGameRoot(g_ebootDir);
    zrx::gpu::AttachMemory(&mem);
    printf("\n[ФС] /app0 -> %s\n", Utf8(g_ebootDir).c_str());
    printf("[GPU] фазы 5.0–5.3: sceVideoOut*/sceGnm* через импорт-заглушки -> Vulkan\n");
    printf("\n");
    zrx::hle::PrintSummary();
    printf("\n  [фаза 4] перехват: syscall (0F 05) -> UD2 (0F 0B) + VEH, потоки, файлы.\n");
    printf("  Конвенция: rax=номер, аргументы rdi,rsi,rdx,r10,r8,r9 (+хвост на стеке).\n\n");

    // --- Сплаш "как у Unity": иконка игры + RUNNED WITH ZerpexPS5 --------------
    // Окно ОДНО: до GPU-init гостя показывается сплаш, Prepare() сам сменит
    // содержимое на вывод игры (без второго окна и мигания).
    {
        const std::wstring icon = FindGameIcon(g_ebootDir);
        if (!zrx::gpu_vk::SplashOpen(icon, L"RUNNED WITH ZerpexPS5 v" ZERPEX_CORE_VERSION_W))
            printf("[GPU] сплаш: окно не открылось (гость продолжит без него)\n");
    }

    zrx::exec::RunResult rr = zrx::exec::Run(mem, e.entry, e);
    Line();
    if (!rr.started) {
        printf("[ИТОГ] запуск НЕ состоялся: %s\n", rr.status.c_str());
        zrx::gpu::Shutdown();
        return;
    }
    printf("[ИТОГ] %s\n", rr.status.c_str());
    {   // 7.7: дубль [ИТОГ] в файл мимо пайпа — итог виден даже при мёртвом тире
        char ib[256];
        snprintf(ib, sizeof(ib), "[ИТОГ-FILE] %s", rr.status.c_str());
        zrx::exec::AppendLogDirect(ib);
    }
    printf("       exited=%s  код=%d\n", rr.exited ? "true" : "false", rr.exitCode);
    zrx::hle::PrintRunSummary();
    zrx::gpu::PrintRunSummary();
    zrx::gpu::Shutdown();

    if (rr.exited)
        printf("\n  ГОСТЬ ОТРАБОТАЛ ЧЕСТНО — фаза 4 (исполнение+ФС+потоки).\n");
    else
        printf("\n  Краш гостя — это тоже результат: видно, каких syscall'ов/фич не хватает.\n");
}

// ----------------------------------------------------------------------------
// Путь SELF: анализ фазы 2.5 + ПОПЫТКА запуска (фаза 7, шаг 1)
// ----------------------------------------------------------------------------
static void AnalyzeSelfReport(const zrx::analyze::SelfReport& r) {
    if (!r.ok) {
        printf("  ОШИБКА анализа SELF: %s\n", r.error.c_str());
        return;
    }

    printf("  Размер (заявлен / факт): %s / %s\n",
           HumanSize(r.fileSizeField).c_str(), HumanSize(r.actualSize).c_str());
    if (r.tailExtra)
        printf("  Хвост дампера: +%llu байт после заявленного размера\n",
               (unsigned long long)r.tailExtra);
    printf("  Константы заголовка: 0x%08X 0x%08X 0x%08X | word@0x1A: 0x%04X\n",
           (unsigned)r.word04, (unsigned)r.word08, (unsigned)r.word0C, (unsigned)r.headerWord);

    printf("\n  Таблица сегментов (%u) — открыта; энтропия скажет, что внутри:\n",
           (unsigned)r.segs.size());
    printf("     #  flags       offset       store        mem          ent    zeros   класс\n");
    for (size_t i = 0; i < r.segs.size(); ++i) {
        const zrx::analyze::SegInfo& s = r.segs[i];
        printf("   %3u  0x%08llX  0x%08llX   %-10llu  %-10llu  %5.2f  %5.1f%%  %s\n",
               (unsigned)i,
               (unsigned long long)s.flags, (unsigned long long)s.off,
               (unsigned long long)s.store, (unsigned long long)s.mem,
               s.ent, s.zeroPct, s.cls);
    }

    if (r.nestedElf) {
        printf("\n  Вложенный ELF @0x%llX: type=0x%04X, entry=0x%llX, phnum=%u, OSABI=%u (9=FreeBSD)\n",
               (unsigned long long)r.elfOffset, (unsigned)r.elfType,
               (unsigned long long)r.elfEntry, (unsigned)r.elfPhnum, (unsigned)r.elfOsabi);
    } else {
        printf("\n  Вложенный ELF: не найден\n");
    }

    if (!r.modules.empty()) {
        printf("\n  Import-модули libSce* (%u):\n    ", (unsigned)r.modules.size());
        size_t i = 0;
        for (const std::string& m : r.modules) {
            printf("%s%s", i ? ", " : "", m.c_str());
            ++i;
            if ((i % 8) == 0) printf("\n    ");
        }
        if ((i % 8) != 0) printf("\n");
    }

    printf("\n  БЕЙДЖ: %s\n",
           r.open ? "SELF (данные открыты) -> путь фазы 3/4 (запуск без ключей)"
                  : "SELF (зашифрован) -> фаза 7 (нужны ключи сцены)");
}

// Фаза 7, шаг 1: попытка запуска SELF БЕЗ ключей.
// SELF-контейнер = заголовок + таблица сегментов + payload. Если payload —
// открытый ELF (домашние/расшифрованные дампы), его можно исполнять тем же
// нативным путём, что и ELF (фаза 4). Зашифрованный retail — честная стена.
// ----------------------------------------------------------------------------
// Фаза 7.2.1: ВНУТРЕННИЙ ОБРАЗ из SELF-сегментов.
//
// PS5 SELF хранит контент LOAD-сегментов В СВОИХ сегментах (storeSize ровно
// равен filesz LOAD-а), а вложенный ELF даёт только РАСКЛАДКУ (p_offset /
// p_vaddr). Чтение по сырым ELF-оффсетам даёт нули/мусор: entry Dead Cells
// читался как "00 00 ..." -> add [rax],al -> краш "запись в 0x0 @ 0x400070".
//
// Собираем образ так: [0..firstLoadOffset) — заголовки из SELF (elfOffset),
// каждый PT_LOAD кладётся по СВОЕМУ p_offset, контент — из парного
// SELF-сегмента. Пара ищется по точному совпадению размеров
// (storeSize==filesz && memSize==memsz); у Dead Cells все 5 размеров
// различны, пары однозначны. Если пара не нашлась — честный отказ.
// ----------------------------------------------------------------------------
static bool BuildInnerElf(const std::vector<uint8_t>& self, const zrx::SelfImage& si,
                          std::vector<uint8_t>* out) {
    if (!out || self.size() <= si.elfOffset || !si.ok || !si.hasElf) {
        printf("  ! ВНУТРЕННИЙ ОБРАЗ: SELF/ELF не разобран — запуск невозможен\n");
        return false;
    }
    const zrx::ElfImage& e = si.elf;

    // firstLoadOffset: от нуля до него лежат заголовки (e_phoff внутри).
    // maxEnd: сколько байт реально нужно под контент LOAD-ов.
    uint64_t firstOff = ~0ull, maxEnd = 0;
    for (const zrx::ElfSegment& p : e.phdrs) {
        if (p.type != zrx::PT_LOAD || !p.filesz) continue;
        if (p.offset < firstOff) firstOff = p.offset;
        const uint64_t end = p.offset + p.filesz;
        if (end > maxEnd) maxEnd = end;
    }
    if (firstOff == ~0ull || firstOff > self.size()) {
        printf("  ! ВНУТРЕННИЙ ОБРАЗ: нет PT_LOAD с контентом\n");
        return false;
    }
    if (firstOff >= 0x10000000 || maxEnd >= 0x100000000ull) {
        printf("  ! ВНУТРЕННИЙ ОБРАЗ: подозрительные размеры (first=0x%llX maxEnd=0x%llX)\n",
               (unsigned long long)firstOff, (unsigned long long)maxEnd);
        return false;
    }

    out->assign((size_t)((maxEnd > firstOff ? maxEnd : firstOff) + 64), 0);
    // Заголовки: ELF header + program headers (+ что между) — верbatim из SELF.
    memcpy(out->data(), self.data() + si.elfOffset, (size_t)firstOff);

    printf("\n  [7.2.1] внутренний образ: %s, заголовки SELF @0x%llX -> inner [0..0x%llX)\n",
           HumanSize(out->size()).c_str(),
           (unsigned long long)si.elfOffset, (unsigned long long)firstOff);

    for (size_t k = 0; k < e.phdrs.size(); ++k) {
        const zrx::ElfSegment& p = e.phdrs[k];
        if (p.type != zrx::PT_LOAD || !p.filesz) continue;
        int match = -1;
        for (size_t i = 0; i < si.segments.size(); ++i) {
            const zrx::SelfSegment& s = si.segments[i];
            // SELF не кодирует bss-хвост LOAD-а (memsz > filesz): у контейнера
            // mem == store, и это ФАЙЛОВЫЙ размер (Dead Cells LOAD#7:
            // filesz=5979728 memsz=8689488, SELF seg#7 store=mem=5979728).
            if (s.storeSize == p.filesz && s.memSize == p.filesz) { match = (int)i; break; }
        }
        if (match < 0) {
            printf("    ! LOAD#%u filesz=%llu memsz=%llu: нет парного SELF-сегмента — отказ\n",
                   (unsigned)k, (unsigned long long)p.filesz, (unsigned long long)p.memsz);
            out->clear();
            return false;
        }
        const zrx::SelfSegment& s = si.segments[(size_t)match];
        if (s.offset + s.storeSize > self.size()) {
            printf("    ! LOAD#%u: SELF-сегмент #%d вне файла — отказ\n", (unsigned)k, match);
            out->clear();
            return false;
        }
        memcpy(out->data() + p.offset, self.data() + s.offset, (size_t)p.filesz);
        printf("    LOAD#%u inner@0x%llX filesz=%llu  <-  SELF seg#%d @0x%llX\n",
               (unsigned)k, (unsigned long long)p.offset, (unsigned long long)p.filesz,
               match, (unsigned long long)s.offset);
    }

    // Честный контроль: байты по entry (vaddr ещё без базы).
    for (const zrx::ElfSegment& p : e.phdrs) {
        if (p.type != zrx::PT_LOAD || !p.filesz) continue;
        if (e.entry >= p.vaddr && e.entry < p.vaddr + p.filesz) {
            const size_t at = (size_t)(p.offset + (e.entry - p.vaddr));
            printf("    entry 0x%llX -> inner @0x%llX: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                   (unsigned long long)e.entry, (unsigned long long)at,
                   (*out)[at], (*out)[at + 1], (*out)[at + 2], (*out)[at + 3],
                   (*out)[at + 4], (*out)[at + 5], (*out)[at + 6], (*out)[at + 7]);
            break;
        }
    }
    return true;
}

static void TryRunSelf(const std::wstring& path, const zrx::analyze::SelfReport& r) {
    if (!r.ok) return;

    if (!r.nestedElf) {
        printf("\n[3] Попытка запуска: НЕВОЗМОЖНА честно — открытого вложенного ELF нет.\n");
        printf("    Payload зашифрован (retail): дешифровка = фаза 7, нужны ключи сцены\n");
        printf("    (ключи живут только локально, в репо не попадут). Анализ выше — тоже результат.\n");
        return;
    }

    printf("\n[3] Попытка запуска (фаза 7, шаг 1): вложенный ELF @0x%llX "
           "(type=0x%04X, entry=0x%llX, OSABI=%u)\n\n",
           (unsigned long long)r.elfOffset, (unsigned)r.elfType,
           (unsigned long long)r.elfEntry, (unsigned)r.elfOsabi);
    if (!r.open)
        printf("  ! Сегменты выглядят зашифрованными — попытка будет честной,\n"
               "    ожидаем крах: он покажет, каких syscall'ов не хватает.\n\n");

    const std::vector<uint8_t> all = ReadAll(path);
    if (all.size() <= r.elfOffset) {
        printf("  Файл не прочитался или ELF за границей — запуска не будет\n");
        return;
    }
    std::vector<uint8_t> data(all.begin() + (size_t)r.elfOffset, all.end());
    if (data.size() < 64) {
        printf("  Вложенный ELF слишком мал — запуска не будет\n");
        return;
    }

    // Корень игры = папка с eboot (для /app0) — как у обычного ELF-пути.
    g_ebootDir = fs::path(path).parent_path().wstring();
    if (g_ebootDir.empty()) g_ebootDir = L".";

    // Фаза 7.2.1: запуск из ВНУТРЕННЕГО образа (контент — из SELF-сегментов).
    zrx::SelfImage si;
    std::vector<uint8_t> inner;
    if (zrx::ParseSelf(all.data(), all.size(), &si) && BuildInnerElf(all, si, &inner)) {
        RunElfProgram(inner);
    } else {
        printf("  Запуск отложен: без корректного внутреннего образа entry — нули.\n");
    }
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// Фаза 7.5.1: файловый лог. Весь stdout идёт и в консоль, и в
// zerpex_log.txt рядом с EXE (перезаписывается при каждом старте).
// Механика: fd 1 подменяется на пайп (_dup2), фоновая нить читает пайп
// и пишет в сохранённый консольный хэндл + файл. stdout без буфера,
// чтобы консоль оставалась «живой».
// ----------------------------------------------------------------------------
static HANDLE g_logConsole = nullptr;
static HANDLE g_logPipeRd   = nullptr;
static FILE*  g_logFile     = nullptr;

static DWORD WINAPI LogTeeProc(LPVOID) {
    char buf[4096];
    DWORD n = 0;
    for (;;) {
        if (!ReadFile(g_logPipeRd, buf, sizeof(buf), &n, nullptr) || !n) {
            // Фаза 7.6.1: краткий сбой чтения не должен замораживать файловый
            // лог (в прогоне 7.6 ти умер и хвост лога потерялся). Живём дальше.
            Sleep(20);
            continue;
        }
        if (g_logConsole) {
            DWORD w = 0;
            WriteFile(g_logConsole, buf, n, &w, nullptr);
        }
        if (g_logFile) {
            fwrite(buf, 1, n, g_logFile);
            fflush(g_logFile);
        }
    }
    return 0;
}

static void StartLogTee() {
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring dir = exe;
    const size_t s = dir.find_last_of(L"\\/");
    dir = (s == std::wstring::npos) ? std::wstring(L".") : dir.substr(0, s);
    const std::wstring path = dir + L"\\zerpex_log.txt";

    const int realFd = _dup(1);     // консольное stdout дублируем на свой fd
    g_logConsole = (realFd >= 0) ? (HANDLE)(uintptr_t)_get_osfhandle(realFd) : nullptr;

    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE wr = nullptr;
    // Фаза 7.6.2: буфер 1 МБ — если фоновый ти встанет, writer не заблокируется
    // на первых же килобайтах (прогон 7.6.1: обрыв посреди строки).
    if (!CreatePipe(&g_logPipeRd, &wr, &sa, 1u << 20)) return;
    const int pipeFd = _open_osfhandle((intptr_t)wr, _O_WRONLY);
    if (pipeFd < 0) { CloseHandle(g_logPipeRd); CloseHandle(wr); return; }
    _dup2(pipeFd, 1);
    _close(pipeFd);
    setvbuf(stdout, nullptr, _IONBF, 0);

    g_logFile = _wfopen(path.c_str(), L"w");
    if (g_logFile) {
        setvbuf(g_logFile, nullptr, _IONBF, 0);   // без буфера: хвост лога не теряется
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(g_logFile, "ZerpexPS5 v" ZERPEX_CORE_VERSION " log | %04u-%02u-%02u %02u:%02u:%02u\r\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        fflush(g_logFile);
    }
    CreateThread(nullptr, 0, &LogTeeProc, nullptr, 0, nullptr);
}

// ----------------------------------------------------------------------------
// --gpu-demo [путь к игре]: витрина слоя 5 без гостя.
// Сплаш (иконка игры + RUNNED WITH ZerpexPS5) -> Prepare -> PM4-треугольник,
// шейдеры которого собраны ТРАНСЛЯТОРОМ RDNA2->SPIR-V (5.3).
// ----------------------------------------------------------------------------
static int RunGpuDemo(const std::wstring& gamePath) {
    const std::wstring icon = FindGameIcon(gamePath);
    printf("[DEMO] сплаш: иконка %s\n", icon.empty() ? "(не найдена)" : Utf8(icon).c_str());
    fflush(stdout);
    if (!zrx::gpu_vk::SplashOpen(icon, L"RUNNED WITH ZerpexPS5 v" ZERPEX_CORE_VERSION_W)) {
        printf("[DEMO] окно не открылось — демо невозможно\n");
        return 1;
    }

    const ULONGLONG t0 = GetTickCount64();
    while (GetTickCount64() - t0 < 2400) {
        if (!zrx::gpu_vk::SplashActive()) {
            printf("[DEMO] окно закрыто пользователем до старта Vulkan\n");
            zrx::gpu_vk::Shutdown();
            return 0;
        }
        zrx::gpu_vk::SplashPump();
        Sleep(16);
    }

    const uint32_t W = 1280, H = 720;
    if (!zrx::gpu_vk::Prepare(W, H, (uint64_t)W * H * 4)) {
        printf("[DEMO] Vulkan не поднялся (причина выше) — закрываю окно\n");
        zrx::gpu_vk::Shutdown();
        return 1;
    }
    if (!zrx::gpu_vk::RenderPm4(3))
        printf("[DEMO] PM4-кадр не отрисован (причина выше)\n");

    int fails = 0;
    while (zrx::gpu_vk::WindowOpen()) {
        if (!zrx::gpu_vk::PresentPm4(W, H)) {
            if (++fails > 180) {   // ~3 с подряд отказов — дальше смысла нет
                printf("[DEMO] показ 3 с подряд отказывает — выхожу\n");
                break;
            }
        } else {
            fails = 0;
        }
        Sleep(16);
    }
    zrx::gpu_vk::Shutdown();
    printf("[DEMO] окно закрыто — демо завершено честно\n");
    return 0;
}

static int RealMain() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleW(L"ZerpexPS5 v" ZERPEX_CORE_VERSION_W L" — ядро");
    zrx::exec::OpenCrashLog();   // 7.7: append-хэндл лога ДО тира — без sharing-рисков
    StartLogTee();
    printf("[ЛОГ] вывод дублируется в файл: zerpex_log.txt (рядом с EXE)\n");

    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    if (!argvW) { printf("Ошибка: не получить аргументы\n"); return 1; }

    // Аргументы: первый позиционный — путь; --corpus <dir>; --gpu <N> (лаунчер);
    // --gpu-demo [путь] (витрина слоя 5 без гостя);
    // --vkprobe [N] (диагностика Vulkan, N=1..5; без N — прогон всех);
    // хвост передаётся как есть, ядро честно пишет, что не знает параметр.
    std::wstring arg1, corpusDir, demoPath;
    bool demoMode = false;
    int gpuPref  = -1;
    int probeExp = -1;
    for (int i = 1; i < argcW; ++i) {
        const std::wstring a = argvW[i];
        if (a == L"--corpus" && i + 1 < argcW) { corpusDir = argvW[++i]; continue; }
        if (a == L"--gpu"    && i + 1 < argcW) { gpuPref = _wtoi(argvW[++i]); continue; }
        if (a == L"--gpu-demo") {
            demoMode = true;
            if (i + 1 < argcW && argvW[i + 1][0] != L'-')
                demoPath = argvW[++i];
            continue;
        }
        if (a == L"--vkprobe") {
            // с числом — один эксперимент (ребёнок); без — прогон 1..5 (родитель)
            if (i + 1 < argcW && argvW[i + 1][0] != L'-')
                probeExp = _wtoi(argvW[++i]);
            else
                probeExp = 0;
            continue;
        }
        if (arg1.empty())                      arg1 = a;
        else printf("[ARG] лишний параметр (игнорирую): %s\n", Utf8(a).c_str());
    }
    LocalFree(argvW);

    printf("================================================================\n");
    printf("  ZerpexPS5 v%s — ядро | фазы: 2.5 · 4 · 5.2 · 5.3 · 7.1–7.7.2\n",
           ZERPEX_CORE_VERSION);
    printf("================================================================\n");

    if (gpuPref >= 0) {
        zrx::gpu_vk::SetPreferredDevice(gpuPref);
        printf("[GPU] приоритет видеокарты №%d — из параметров запуска (лаунчер)\n", gpuPref);
    }

    // --- диагностика Vulkan: изолированные эксперименты в отдельных процессах ---
    if (probeExp >= 0) {
        g_probeAny = true;
        if (probeExp == 0) {
            wchar_t self[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, self, MAX_PATH);
            for (int n = 1; n <= 5; ++n) {
                wchar_t args[MAX_PATH + 32];
                swprintf(args, MAX_PATH + 32, L"\"%ls\" --vkprobe %d", self, n);
                printf("\n=== [PROBE] эксперимент %d ===\n", n);
                fflush(stdout);
                STARTUPINFOW si = {};
                si.cb = sizeof(si);
                PROCESS_INFORMATION pi = {};
                if (CreateProcessW(nullptr, args, nullptr, nullptr, FALSE, 0,
                                   nullptr, nullptr, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, 120000);
                    DWORD code = 0;
                    GetExitCodeProcess(pi.hProcess, &code);
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    printf("=== [PROBE] эксперимент %d: код выхода %lu%s ===\n",
                           n, (unsigned long)code,
                           code == 0 ? " (успех)"
                                     : (code == 2 ? " (КРАШ — см. лог выше)" : ""));
                } else {
                    printf("=== [PROBE] эксперимент %d: запуск не удался (код %lu) ===\n",
                           n, (unsigned long)GetLastError());
                }
                fflush(stdout);
            }
            printf("\n[PROBE] все эксперименты завершены\n");
            return 0;
        }
        printf("=== [PROBE] эксперимент %d ===\n", probeExp);
        fflush(stdout);
        const int r = zrx::gpu_vk::Probe(probeExp);
        printf("=== [PROBE] эксперимент %d завершён штатно, код %d ===\n", probeExp, r);
        return r;
    }

    // --- витрина слоя 5: окно + сплаш + PM4-треугольник (без гостя) ---
    if (demoMode) {
        if (demoPath.empty()) demoPath = arg1;   // допускаем и "<игра> --gpu-demo"
        return RunGpuDemo(demoPath);
    }

    // --- корпус-режим ---
    if (!corpusDir.empty()) {
        zrx::analyze::CorpusAnalyze(corpusDir);
        return 0;
    }

    if (arg1.empty()) {
        printf("Использование: ZerpexPS5.exe <eboot.bin | eboot.elf | папка игры>\n");
        printf("               [--gpu <N> — приоритет видеокарты, из лаунчера]\n");
        printf("               ZerpexPS5.exe --gpu-demo [путь к игре] — окно+сплаш+треугольник\n");
        printf("               ZerpexPS5.exe --corpus <папка с дампами>\n");
        return 1;
    }

    // --- резолв пути ---
    std::wstring path = arg1;
    std::error_code ec;
    if (fs::is_directory(fs::path(path), ec)) {
        const std::wstring eboot = FindEboot(path);
        if (eboot.empty()) {
            printf("В папке нет eboot.bin / eboot.elf: %s\n", Utf8(path).c_str());
            return 1;
        }
        path = eboot;
    }
    if (!fs::is_regular_file(fs::path(path), ec)) {
        printf("Файл не найден: %s\n", Utf8(path).c_str());
        return 1;
    }

    printf("Файл: %s\n", Utf8(path).c_str());

    uint8_t head[4] = {};
    {
        std::ifstream f(path.c_str(), std::ios::binary);
        if (!f || !f.read(reinterpret_cast<char*>(head), 4)) {
            printf("Файл не читается\n");
            return 1;
        }
    }
    uint32_t magic = 0;
    memcpy(&magic, head, 4);
    const bool isSelf = (magic == zrx::SELF_MAGIC_PS5);
    const bool isElf  = (head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F');

    printf("Размер: %s\n\n", HumanSize(fs::file_size(fs::path(path), ec)).c_str());
    Line();

    if (isSelf) {
        printf("[1] Магия: 54 14 F5 EE -> SELF-контейнер PS5\n");
        printf("[2] Умный анализ (фаза 2.5):\n\n");
        const zrx::analyze::SelfReport rep = zrx::analyze::AnalyzeFile(path);
        AnalyzeSelfReport(rep);
        TryRunSelf(path, rep);   // фаза 7, шаг 1: запуск только если ELF открыт
    } else if (isElf) {
        printf("[1] Магия: 7F 45 4C 46 -> открытый ELF\n");
        printf("[2] Загрузка + релокации + нативный запуск (фазы 4-5):\n\n");
        const std::vector<uint8_t> data = ReadAll(path);
        if (data.size() < 64) {
            printf("Файл слишком мал для ELF\n");
            return 1;
        }
        // Корень игры = папка с запускаемым файлом (для /app0)
        g_ebootDir = fs::path(path).parent_path().wstring();
        if (g_ebootDir.empty()) g_ebootDir = L".";
        RunElfProgram(data);
    } else {
        printf("[1] Неизвестная магия: %02X %02X %02X %02X — это не ELF и не SELF PS5\n",
               head[0], head[1], head[2], head[3]);
        return 1;
    }

    Line();
    printf("ZerpexPS5 v%s: фазы 2.5 (анализ) · 4 (исполнение) · 5.2 (рендер из PM4) · "
           "5.3 (RDNA2->SPIR-V) · 7.1–7.7.2 (запуск ELF).\n", ZERPEX_CORE_VERSION);
    printf("Сплаш: иконка игры + RUNNED WITH ZerpexPS5; окно сменяется на вывод игры при GPU-init.\n");
    printf("SELF: попытка запуска открытого вложенного ELF (фаза 7, шаг 1; retail — после дешифровки).\n");
    printf("Дальше: GPU-init гостя (первый настоящий кадр) — недостающие импорты добираются итерациями.\n");
    return 0;
}

int main() {
    SetUnhandledExceptionFilter(&LastChanceFilter);
    const int rc = RealMain();
    PauseBeforeExit();   // окно остаётся открытым, даже если гость крашнулся
    return rc;
}
