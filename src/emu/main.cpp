// ============================================================================
// ZerpexPS5 — ядро эмулятора · фаза 5.0 (+ фаза 4, фаза 2.5)
//
// ЧТО ЕСТЬ:  парсер ELF64 + SELF PS5, память на VirtualAlloc, HLE-диспетчер,
//            НАТИВНОЕ ИСПОЛНЕНИЕ гостевого x86-64 с перехватом syscall'ов
//            (патч syscall->UD2 + VEH), релокации PT_DYNAMIC с импорт-заглушками,
//            ПОТОКИ гостя, ФАЙЛЫ (/app0 -> папка игры), ПЕРВЫЙ ПИКСЕЛЬ
//            (sceVideoOut* -> окно Win32 + Vulkan-свапчейн, без шейдеров),
//            умный анализ SELF, корпус-режим.
// ЧЕГО НЕТ:  PM4/шейдеров/растеризации GPU (фаза 5.1+),
//            дешифровки retail SELF (фаза 7, только там нужны ключи).
//
// Использование:
//   ZerpexPS5.exe <файл eboot.bin/eboot.elf | папка игры>   — анализ или запуск
//   ZerpexPS5.exe --corpus <папка с дампами>                — корпус-сравнение
//
// Правила хозяина: ничего не скачивать; собранный EXE не запускать самому.
// ============================================================================
#include <windows.h>
#include <shellapi.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "../core/elf.h"
#include "../core/mem.h"
#include "../core/hle.h"
#include "../core/dyn.h"
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
    for (size_t idx : e.loadIdx) {
        const zrx::ElfSegment& p = e.phdrs[idx];
        const uint8_t* fileData = nullptr;
        if (p.filesz && p.offset + p.filesz <= data.size())
            fileData = data.data() + p.offset;
        else if (p.filesz) {
            printf("    ! сегмент #%u: данные вне файла (offset=0x%llX filesz=%llu) — пропускаю содержимое\n",
                   (unsigned)idx, (unsigned long long)p.offset, (unsigned long long)p.filesz);
        }
        const uint64_t actual = mem.Map(p.vaddr, fileData, p.filesz, p.memsz, p.flags);
        if (!actual) {
            printf("    ! сегмент #%u: VirtualAlloc не удался\n", (unsigned)idx);
            continue;
        }
        printf("    vaddr 0x%012llX -> 0x%012llX  %-4s  filesz=%llu memsz=%llu%s\n",
               (unsigned long long)p.vaddr, (unsigned long long)actual,
               zrx::ProtStr(p.flags).c_str(),
               (unsigned long long)p.filesz, (unsigned long long)p.memsz,
               mem.Segments().back().relocated ? "  (перенесён — адрес занят)" : "");
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
    printf("[GPU] фаза 5.0: sceVideoOut*/sceGnm* через импорт-заглушки -> Vulkan\n");
    printf("\n");
    zrx::hle::PrintSummary();
    printf("\n  [фаза 4] перехват: syscall (0F 05) -> UD2 (0F 0B) + VEH, потоки, файлы.\n");
    printf("  Конвенция: rax=номер, аргументы rdi,rsi,rdx,r10,r8,r9 (+хвост на стеке).\n\n");

    zrx::exec::RunResult rr = zrx::exec::Run(mem, e.entry);
    Line();
    if (!rr.started) {
        printf("[ИТОГ] запуск НЕ состоялся: %s\n", rr.status.c_str());
        zrx::gpu::Shutdown();
        return;
    }
    printf("[ИТОГ] %s\n", rr.status.c_str());
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
    RunElfProgram(data);
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------
static int RealMain() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    if (!argvW) { printf("Ошибка: не получить аргументы\n"); return 1; }

    // Аргументы: первый позиционный — путь; --corpus <dir>; --gpu <N> (лаунчер);
    // --vkprobe [N] (диагностика Vulkan, N=1..5; без N — прогон всех);
    // хвост передаётся как есть, ядро честно пишет, что не знает параметр.
    std::wstring arg1, corpusDir;
    int gpuPref  = -1;
    int probeExp = -1;
    for (int i = 1; i < argcW; ++i) {
        const std::wstring a = argvW[i];
        if (a == L"--corpus" && i + 1 < argcW) { corpusDir = argvW[++i]; continue; }
        if (a == L"--gpu"    && i + 1 < argcW) { gpuPref = _wtoi(argvW[++i]); continue; }
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
    printf("  ZerpexPS5 — ядро | ФАЗА 5.0: первый пиксель + ФАЗА 4 + ФАЗА 2.5\n");
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

    // --- корпус-режим ---
    if (!corpusDir.empty()) {
        zrx::analyze::CorpusAnalyze(corpusDir);
        return 0;
    }

    if (arg1.empty()) {
        printf("Использование: ZerpexPS5.exe <eboot.bin | eboot.elf | папка игры>\n");
        printf("               [--gpu <N> — приоритет видеокарты, из лаунчера]\n");
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
    printf("ZerpexPS5: фаза 5.2 (рендер из PM4: прокси-треугольник) + фаза 4 (исполнение) + фаза 2.5.\n");
    printf("SELF: попытка запуска открытого вложенного ELF (фаза 7, шаг 1; retail — после дешифровки).\n");
    printf("Дальше: фаза 5.3 (настоящая трансляция GCN-шейдеров).\n");
    return 0;
}

int main() {
    SetUnhandledExceptionFilter(&LastChanceFilter);
    const int rc = RealMain();
    PauseBeforeExit();   // окно остаётся открытым, даже если гость крашнулся
    return rc;
}
