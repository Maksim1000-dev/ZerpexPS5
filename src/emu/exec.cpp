// ============================================================================
// ZerpexPS5 — фаза 4: исполнение (реализация: патч syscall + VEH + потоки)
// ============================================================================
#include "exec.h"

#include "../core/dyn.h"   // TryResolveStub (импорт-заглушки)
#include "../core/elf.h"   // PF_X, ElfImage (фаза 7.3: PT_TLS)
#include "../core/hle.h"
#include "gpu.h"           // GPU-модули (фаза 5): sceVideoOut*/sceGnm*

#include <windows.h>
#include <process.h>       // _beginthreadex
#include <cpuid.h>         // __get_cpuid_count (детект FSGSBASE, фаза 7.3)

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace zrx {
namespace exec {

// --- Патчи syscall'ов --------------------------------------------------------
struct Patch {
    uint64_t host  = 0;   // адрес UD2 в памяти
    uint64_t guest = 0;   // соответствующий гостевой vaddr
    uint8_t  orig[2] = { 0x0F, 0x05 };
};

static std::vector<Patch> g_patches;
static std::unordered_map<uint64_t, size_t> g_byHost;
static Memory* g_mem = nullptr;

// Фаза 7.3: флаг активного теста wrfsbase (см. DetectFsBase).
static std::atomic<bool> g_fsTest{false};

// Фаза 7.3: детект FSGSBASE. GCC не даёт __try в C++, поэтому тест под
// СОБСТВЕННЫМ VEH (зарегистрирован в Run до вызова): при #UD обработчик
// пропустит 5 байт инструкции. Прошла запись = fs-базу ставить умеем.
// Вызывается ДО t_armed — VEH-ветка с g_fsTest стоит выше проверки t_armed.
static void DetectFsBase() {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (!__get_cpuid_count(7, 0, &a, &b, &c, &d) || !(b & 1u)) {
        hle::SetFsBaseSupported(false);
        printf("[7.3] FSGSBASE: CPU не умеет — fs-база недоступна\n");
        fflush(stdout);
        return;
    }
    g_fsTest.store(true);
    __builtin_ia32_wrfsbase64(0);
    g_fsTest.store(false);
    hle::SetFsBaseSupported(true);
    printf("[7.3] FSGSBASE: доступен (CPU+ОС) — fs-базу ставить умеем\n");
    fflush(stdout);
}
static void*   g_veh = nullptr;                   // живёт весь процесс
static std::atomic<uint64_t> g_nextTid { 2 };
static std::atomic<int> g_threadsSpawned { 0 };

// --- Состояние НА ПОТОК (гость многопоточный) --------------------------------
static __thread volatile bool t_armed = false;
static __thread char t_fault[256] = { 0 };
static __thread int t_exitCode = 0;
static __thread uint64_t t_tid = 0;

static const DWORD EXC_ILLEGAL = 0xC000001D;  // EXCEPTION_ILLEGAL_INSTRUCTION
static const DWORD EXC_PRIV    = 0xC0000096;  // STATUS_PRIVILEGED_INSTRUCTION
static const DWORD EXC_ACCESS  = 0xC0000005;  // STATUS_ACCESS_VIOLATION
static const DWORD EXC_BREAK   = 0x80000003;  // STATUS_BREAKPOINT

static const int JMPL_EXIT        = 777;   // sys_exit (процесс)
static const int JMPL_THREAD_EXIT = 888;   // sys_thr_exit (нить)
static const int JMPL_FAULT       = -1;    // краш гостя (текст в t_fault)

// Фаза 7.6.2/7.7: запись в файл лога МИМО stdout-пайпа (только kernel32 —
// безопасно и из контекста исключения). Лог лежит рядом с EXE (как StartLogTee
// в main.cpp). Хэндл открывается ЗАРАНЕЕ (OpenCrashLog — main.cpp зовёт его
// ДО StartLogTee): открытие в момент краша не сработало в прогоне 7.6.2
// ([CRASH-FILE] отсутствовал при живом printf рядом — вероятен sharing
// violation с хэндлом тира), поэтому открытие в момент краша больше не нужно.
static HANDLE g_logDirect = nullptr;

void OpenCrashLog() {
    if (g_logDirect) return;
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring dir = exe;
    const size_t sl = dir.find_last_of(L"\\/");
    dir = (sl == std::wstring::npos) ? std::wstring(L".") : dir.substr(0, sl);
    g_logDirect = CreateFileW((dir + L"\\zerpex_log.txt").c_str(), FILE_APPEND_DATA,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (g_logDirect == INVALID_HANDLE_VALUE) g_logDirect = nullptr;
}

void AppendLogDirect(const char* text) {
    if (!text || !text[0]) return;
    if (!g_logDirect) OpenCrashLog();
    if (!g_logDirect) return;
    char buf[560];
    const int k = snprintf(buf, sizeof(buf), "%s\r\n", text);
    DWORD w = 0;
    if (k > 0) WriteFile(g_logDirect, buf, (DWORD)k, &w, nullptr);
}

// Диагноз краша: СНАЧАЛА файл (мимо пайпа), потом stdout — если пайп встанет
// и printf заблокирует нить, диагноз уже лежит в zerpex_log.txt.
static void CrashReport(const char* text) {
    if (!text || !text[0]) return;
    snprintf(t_fault, sizeof(t_fault), "%s", text);
    char line[600];
    snprintf(line, sizeof(line), "[CRASH-FILE] %s", t_fault);
    AppendLogDirect(line);
    printf("[EXEC] КРАШ ГОСТЯ: %s\n", t_fault);
    fflush(stdout);
}

// --- Фаза 7.7: аварийный выход БЕЗ longjmp ------------------------------------
// GuestLaunch (launch.S) спилит callee-saved и запомнит блок в t_bailPtr.
// VEH при краше в госте ПОДМЕНЯЕТ контекст (rsp/regs/rip) и возвращает
// CONTINUE_EXECUTION: диспетчер завершается штатно (NtContinue), раскрутка
// Windows по гостевым кадрам (без SEH-метаданных) не выполняется — именно
// она роняла процесс в ntdll с 0xC00000FF (WER прогона 21:44 2026-11-17).
// setjmp/longjmp из exec.cpp убраны полностью.
static __thread void* t_bailPtr = nullptr;        // спил GuestLaunch
static __thread volatile bool t_bailed = false;   // выход уже оформлен

extern "C" void BailSaveBlock(void* p) { t_bailPtr = p; }

extern "C" uint64_t GuestLaunch(uint64_t entry, uint64_t a1, uint64_t a2);

// Подмена контекста на "GuestLaunch вернул code". Возвращает LONG для VEH.
static LONG BailPatchContext(PCONTEXT c, int code) {
    uint64_t* b = (uint64_t*)t_bailPtr;   // [r15 r14 r13 r12 rdi rsi rbp rbx ret]
    c->R15 = b[0]; c->R14 = b[1]; c->R13 = b[2]; c->R12 = b[3];
    c->Rdi = b[4]; c->Rsi = b[5]; c->Rbp = b[6]; c->Rbx = b[7];
    c->Rip = b[8];                        // адрес возврата в Run/ThreadProc
    c->Rsp = (DWORD64)t_bailPtr + 72;     // спил 8*8 + съеденный ret-адрес
    c->Rax = (DWORD64)(int64_t)code;
    t_armed = false;
    t_bailed = true;
    {
        char line[80];
        snprintf(line, sizeof(line), "[BAILOUT] контекст подменён, код %d", code);
        AppendLogDirect(line);
    }
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Аргументы гостевого вызова (FreeBSD x64 / SysV): rdi,rsi,rdx,r10,r8,r9;
// хвост (args 6..7) лежит на стеке гостя: rsp+8, rsp+16 (после ret-адреса).
static void ReadGuestArgs(PCONTEXT c, uint64_t args[8]) {
    args[0] = c->Rdi;
    args[1] = c->Rsi;
    args[2] = c->Rdx;
    args[3] = c->R10;
    args[4] = c->R8;
    args[5] = c->R9;
    args[6] = 0;
    args[7] = 0;
    if (g_mem) {
        const uint8_t* s1 = g_mem->Ptr(c->Rsp + 8);
        const uint8_t* s2 = g_mem->Ptr(c->Rsp + 16);
        if (s1) memcpy(&args[6], s1, 8);
        if (s2) memcpy(&args[7], s2, 8);
    }
}

// --- GPU-работник: Vulkan живёт НЕ в VEH-нити --------------------------------
// Гость зовёт GPU-импорт из VEH (ud2 -> обработчик исключения). Драйверы
// (nvoglv64 и т.п.) не рассчитаны на вызов из контекста обработки исключения:
// у NVIDIA падала внутренняя инициализация первого командного объекта
// (запись по 0x0 в vkCreateCommandPool). Поэтому VEH только маршалит вызов и
// ждёт результат, а всю работу делает выделенная хост-нить.
struct GpuJob {
    char     name[64];
    uint64_t args[8];
    int64_t  ret = 0;
    bool     done = false;
};
static std::mutex g_gwMx;
static std::condition_variable g_gwJobCv, g_gwDoneCv;
static GpuJob* g_gwJob = nullptr;          // активное задание (или null)

static unsigned __stdcall GpuWorkerProc(void*) {
    for (;;) {
        GpuJob* job = nullptr;
        {
            std::unique_lock<std::mutex> lk(g_gwMx);
            g_gwJobCv.wait(lk, [] { return g_gwJob != nullptr; });
            job = g_gwJob;
        }
        job->ret = gpu::Execute(job->name, job->args);   // единственный исполнитель
        {
            std::lock_guard<std::mutex> lk(g_gwMx);
            job->done = true;
            g_gwJob = nullptr;
        }
        g_gwDoneCv.notify_all();
    }
}

// Вызов из VEH: маршалинг + ожидание выполнения на worker-нити.
// Стек гостя и контекст исключения в Vulkan не попадают.
static int64_t GpuExecuteOffVeh(const char* name, const uint64_t args[8]) {
    static bool started = false;
    if (!started) {
        started = true;
        const uintptr_t h = _beginthreadex(nullptr, 4u << 20, &GpuWorkerProc,
                                           nullptr, 0, nullptr);
        if (h) CloseHandle((HANDLE)h);
        printf("[EXEC] GPU-работник запущен: Vulkan живёт вне VEH-нити\n");
        fflush(stdout);
    }

    GpuJob job;
    strncpy(job.name, name ? name : "", sizeof(job.name) - 1);
    job.name[sizeof(job.name) - 1] = 0;
    memcpy(job.args, args, sizeof(job.args));

    std::unique_lock<std::mutex> lk(g_gwMx);
    g_gwJobCv.wait(lk, [] { return g_gwJob == nullptr; });   // свободный слот
    g_gwJob = &job;
    g_gwJobCv.notify_one();
    g_gwDoneCv.wait(lk, [&job] { return job.done; });        // результат
    return job.ret;
}

// --- VEH-обработчик ----------------------------------------------------------
// Один на весь процесс; каждая гостевая нить фильтруется своим t_armed.
// --- Фаза 7.6: гостевая куча -------------------------------------------------
// Импорты libc malloc/calloc/realloc/free обслуживает СУБАЛЛОКАТОР: один
// регион гостевой памяти + bump-выделение. Заголовок 16 байт (размер + магия)
// нужен realloc'у; free — честный no-op (память не переиспользуется: для
// этапа запуска утечки не страшны).
static constexpr uint64_t kHeapSize  = 256ull << 20;
static constexpr uint32_t kHeapMagic = 0x5A52584B;   // "ZRXK"
static uint64_t g_heapBase = 0, g_heapOff = 0, g_heapCap = 0;
static uint8_t* g_heapHost = nullptr;
static std::mutex g_heapMx;

static bool HeapInit(Memory& m) {
    if (g_heapHost) return true;
    const uint64_t sizes[3] = { kHeapSize, kHeapSize >> 2, kHeapSize >> 4 };
    for (const uint64_t sz : sizes) {
        const uint64_t b = m.AllocGuest(sz, zrx::PF_R | zrx::PF_W);
        if (b) {
            g_heapBase = b;
            g_heapHost = (uint8_t*)(uintptr_t)m.Ptr(b);
            g_heapCap  = sz;
            printf("[7.6] куча гостя: регион guest 0x%llX, %llu МБ, bump (free = no-op)\n",
                   (unsigned long long)g_heapBase, (unsigned long long)(sz >> 20));
            fflush(stdout);
            return g_heapHost != nullptr;
        }
    }
    printf("[7.6] кучу гостя выделить не удалось — libc-импорты останутся заглушками\n");
    fflush(stdout);
    return false;
}

// Выделение с ВЫРАВНИВАНИЕМ. Заголовок {size, magic} лежит в 16 байтах ПЕРЕД
// возвращаемым указателем (для align > 16 он прячется в паддинге). Выравнивание
// критично: гостевой libc зовёт memalign(0x1000/0x80, ...) и на невыровненных
// ответах его метаданные портятся (прогон 7.6: malloc с размером = указателю).
static uint64_t HeapAllocAligned(uint64_t align, uint64_t n, const char* what) {
    if (!g_heapHost) return 0;
    if (!n) n = 1;
    if (align < 16) align = 16;
    if (align & (align - 1)) {
        printf("[7.6] %s: выравнивание 0x%llX не степень двойки — беру 16\n",
               what ? what : "?", (unsigned long long)align);
        align = 16;
    }
    std::lock_guard<std::mutex> lk(g_heapMx);
    const uint64_t payload = (n + 0xF) & ~0xFull;
    uint64_t start = (g_heapOff + align - 1) & ~(align - 1);
    if (start < 16) start = align;      // под заголовок (ptr-16) нужно место
    const uint64_t end  = start + payload;
    if (n > (512ull << 20) || end > g_heapCap) {
        printf("[7.6] %s: ОТКАЗ size=0x%llX align=0x%llX (off=0x%llX) — верну 0\n",
               what ? what : "?", (unsigned long long)n, (unsigned long long)align,
               (unsigned long long)g_heapOff);
        fflush(stdout);
        return 0;
    }
    uint8_t* h = g_heapHost + (start - 16);
    *(uint64_t*)h     = n;              // запрошенный размер (для realloc)
    *(uint32_t*)(h+8) = kHeapMagic;
    g_heapOff = end;
    return g_heapBase + start;
}

static bool HeapOwns(uint64_t p) {
    return g_heapBase && p >= g_heapBase + 16 && p < g_heapBase + g_heapCap;
}

static uint64_t HeapCalloc(uint64_t n) {
    const uint64_t p = HeapAllocAligned(16, n, "calloc");
    if (p && g_mem) {
        void* h = (void*)(uintptr_t)g_mem->Ptr(p);
        if (h) memset(h, 0, (size_t)n);
    }
    return p;
}

[[maybe_unused]] static uint64_t HeapRealloc(uint64_t p, uint64_t n) {
    if (!p) return HeapAllocAligned(16, n, "realloc");
    if (!HeapOwns(p)) {
        static bool said = false;
        if (!said) {
            said = true;
            printf("[7.6] realloc: указатель 0x%llX не из нашей кучи — новый блок без копии\n",
                   (unsigned long long)p);
            fflush(stdout);
        }
        return HeapAllocAligned(16, n, "realloc");
    }
    uint64_t old = 0;
    if (g_mem) {
        const uint8_t* h = (const uint8_t*)(uintptr_t)g_mem->Ptr(p - 16);
        if (h && *(const uint32_t*)(h+8) == kHeapMagic) old = *(const uint64_t*)h;
    }
    const uint64_t q = HeapAllocAligned(16, n, "realloc");
    if (q && old && g_mem) {
        void* d = (void*)(uintptr_t)g_mem->Ptr(q);
        const void* s = (const void*)(uintptr_t)g_mem->Ptr(p);
        if (d && s) memcpy(d, s, (size_t)(old < n ? old : n));
    }
    return q;
}

// [7.7.2] Адрес памяти гостя в хосте: сначала сегменты гостя (образ/куча/
// заглушки), иначе — прямой хостовый диапазон (стек гостя = стек хоста: гость
// исполняется нативно), если VirtualQuery подтверждает доступ на весь диапазон.
static uint8_t* HostPtr(uint64_t addr, uint64_t n, bool wr) {
    if (!addr || addr + n < addr || !n) return nullptr;
    if (uint8_t* p = g_mem ? g_mem->Ptr(addr) : nullptr) return p;
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)(uintptr_t)addr, &mbi, sizeof(mbi))) return nullptr;
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) || mbi.Protect == PAGE_NOACCESS)
        return nullptr;
    if (mbi.RegionSize < n) return nullptr;   // диапазон должен лежать в одном регионе
    const DWORD w = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    const DWORD r = w | PAGE_READONLY | PAGE_EXECUTE_READ;
    if (!(mbi.Protect & (wr ? w : r))) return nullptr;
    return (uint8_t*)(uintptr_t)addr;
}

static uint64_t HeapMemmove(PCONTEXT c, uint64_t dst, uint64_t src, uint64_t n) {
    if (!g_mem || !n) return dst;
    void* d = HostPtr(dst, n, true);
    void* s = HostPtr(src, n, false);
    if (!d || !s) {
        char buf[192];
        snprintf(buf, sizeof(buf),
                 "memcpy: недоступная память dst=0x%llX src=0x%llX len=%llu",
                 (unsigned long long)dst, (unsigned long long)src, (unsigned long long)n);
        CrashReport(buf);
        if (t_bailPtr) {
            BailPatchContext(c, JMPL_FAULT);   // дальше код не пойдёт
            return 0;
        }
        return 0;
    }
    memmove(d, s, (size_t)n);
    return dst;
}

// [7.7.2] PLT[192] 8zTFvBIAIN8 = memset(dst, val, n). Опознан по поведению
// (tools/scan3.c): единственный вызов внутри хелпера alloc+zero — 
//   movsxd rdx,r14d(len); mov rdi,rbx(alloc); xor esi,esi; call memset
// и сайты вида (ptr, 0, 0x1200). Вставки хеш-таблиц (SwissTable) полагаются на
// него: контрольные байты 0xFF. Без реализации таблицы оставались "пустыми по
// нулям" и поиск уходил в мусор (краш 7.7: mov rbx,[rax=0x200] @0x1A2C9D3).
static uint64_t HeapMemset(PCONTEXT c, uint64_t dst, uint64_t val, uint64_t n) {
    if (!g_mem || !n) return dst;
    void* d = HostPtr(dst, n, true);
    if (!d) {
        char buf[192];
        snprintf(buf, sizeof(buf), "memset: недоступная память dst=0x%llX len=%llu",
                 (unsigned long long)dst, (unsigned long long)n);
        CrashReport(buf);
        if (t_bailPtr) {
            BailPatchContext(c, JMPL_FAULT);
            return 0;
        }
        return 0;
    }
    memset(d, (int)(val & 0xFF), (size_t)n);
    return dst;
}

// Имена импортов (скремблированы SCE) — опознаны ПО ПОВЕДЕНИЮ вызовов;
// индексы PLT подтверждены полной картой: tools/import_map.txt.
//   PLT[261] malloc(size)         — звался из libc-аллокатора 0x1b458d0 (size=0x40...)
//   PLT[194] calloc(nmemb, size)  — звался как (1, 0x8a0) из 0x1a2ab80 (крэш 0x1A2ABD6)
//   PLT[195] free(p)              — парный к calloc в коде роста массива
//   PLT[193] memcpy(dst, src, n)  — звался как (dst, r12, r15*8)
//   PLT[210] malloc-подобный, ОДИН аргумент rdi; rsi — мусор-остаток регистра.
//     Офлайн-разбор строк вызовов (tools/scan_calls): 0x1A2AA5D lea rdi,[r13*8]
//     (рост массива), 0x1A1C613 mov edi,0x70 при ЖИВОМ r14=rsi. Гипотезы
//     realloc/memalign сняты: пара (0x80,0x8A0) — это 0x8A0 хвост rsi от
//     calloc(1,0x8A0); отказ malloc(0x10) из-за rsi=0x700000065100 дал
//     memcpy(dst=0) и краш (прогон 7.6.1).
static const char* kImpMalloc  = "fJnpuVVBbKk#W#W";
static const char* kImpCalloc  = "2X5agFjKxMc#W#W";
static const char* kImpFree    = "tIhsqj0qsFE#W#W";
static const char* kImpAligned = "gQX+4GDQjpM#W#W";
static const char* kImpMemcpy  = "Q3VBxCXhUHs#W#W";
// [7.7.2] Опознаны по поведению (tools/scan3.c):
//   PLT[192] 8zTFvBIAIN8 = memset(dst, val, n)  — alloc+zero хелпер: (ptr, 0, len)
//   PLT[222] +P6FRGH4LfA = memmove(dst, src, n) — сдвиг записей таблицы на 16Б
//     (lea rdi,[r12+r15+0x10]; lea rsi,[r12+r15]; rdx=count*16), и сдвиги массива.
static const char* kImpMemset  = "8zTFvBIAIN8#W#W";
static const char* kImpMemmove = "+P6FRGH4LfA#W#W";

// Фаза 7.6: последняя надежда. Сюда попадают исключения, которые не перехватил
// VEH (чужие нити, код вне гостя). Раньше они убивали процесс МОЛЧА — без
// итога в логе. Теперь: диагноз в лог, потом цепочка к фильтру из main.cpp.
static LPTOP_LEVEL_EXCEPTION_FILTER s_prevUef = nullptr;

static LONG WINAPI LastChanceFilter(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord) return EXCEPTION_EXECUTE_HANDLER;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const uint64_t rip = ep->ContextRecord ? ep->ContextRecord->Rip : 0;
    uint64_t guestRip = 0;
    const bool inG = g_mem && g_mem->GuestForHost(rip, &guestRip);
    const uint64_t fa = ep->ExceptionRecord->NumberParameters >= 2
                            ? ep->ExceptionRecord->ExceptionInformation[1] : 0;
    printf("[CRASH] НЕПЕРЕХВАЧЕННОЕ исключение 0x%08X @ host RIP 0x%llX "
           "(guest 0x%llX %s), адрес 0x%llX\n",
           (unsigned)code, (unsigned long long)rip, (unsigned long long)guestRip,
           inG ? "В ГОСТЕ" : "не в госте", (unsigned long long)fa);
    if (ep->ContextRecord)
        printf("[CRASH] RAX=0x%llX RBX=0x%llX RCX=0x%llX RDX=0x%llX RSP=0x%llX RBP=0x%llX\n",
               (unsigned long long)ep->ContextRecord->Rax,
               (unsigned long long)ep->ContextRecord->Rbx,
               (unsigned long long)ep->ContextRecord->Rcx,
               (unsigned long long)ep->ContextRecord->Rdx,
               (unsigned long long)ep->ContextRecord->Rsp,
               (unsigned long long)ep->ContextRecord->Rbp);
    printf("[CRASH] лог сохранён в build\\zerpex_log.txt\n");
    fflush(stdout);
    {
        char cbuf[208];
        snprintf(cbuf, sizeof(cbuf),
                 "[CRASH-FILE] НЕПЕРЕХВАЧЕННОЕ 0x%08X @ host RIP 0x%llX (guest 0x%llX), адрес 0x%llX",
                 (unsigned)code, (unsigned long long)rip,
                 (unsigned long long)guestRip, (unsigned long long)fa);
        AppendLogDirect(cbuf);   // дубль в файл мимо пайпа
    }
    Sleep(400);   // дать фоновому тиру дописать хвост лога
    // Цепочка: дальше работает фильтр из main.cpp — он держит окно открытым.
    if (s_prevUef) return s_prevUef(ep);
    return EXCEPTION_EXECUTE_HANDLER;
}

static LONG NTAPI VehHandler(PEXCEPTION_POINTERS ep) {
    // Фаза 7.3: активен тест wrfsbase (DetectFsBase, до t_armed)? #UD значит
    // "ОС не включила CR4.FSGSBASE": пропускаем инструкцию (5 байт) — это
    // сам ответ теста, а не краш гостя.
    if (g_fsTest.load()) {
        g_fsTest.store(false);
        ep->ContextRecord->Rip += 5;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (!t_armed) return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT c = ep->ContextRecord;
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    const uint64_t rip = c->Rip;

    uint64_t guestRip = 0;
    const bool inGuest = g_mem && g_mem->GuestForHost(rip, &guestRip);

    if (code == EXC_ILLEGAL) {
        const auto it = g_byHost.find(rip);
        if (it != g_byHost.end()) {
            // Наш патч: настоящий syscall. Конвенция FreeBSD x64:
            // rax=номер; args 0..5 в rdi,rsi,rdx,r10,r8,r9; args 6..7 на стеке
            // гостя (rsp+8, rsp+16 — SysV-раскладка хвоста аргументов).
            uint64_t args[8];
            ReadGuestArgs(c, args);

            // Диспетчер пока не потокобезопасен — серилизуем syscalls.
            static std::mutex mx;
            hle::HleResult r;
            { std::lock_guard<std::mutex> lk(mx); r = hle::Execute((uint32_t)c->Rax, args); }

            if (r.status == hle::HleStatus::Exit) {
                t_exitCode = r.exitCode;
                if (t_tid == 1) {
                    // Фаза 7.7: выход БЕЗ longjmp — подмена контекста, GuestLaunch
                    // "вернёт" JMPL_EXIT в Run().
                    printf("[EXEC] sys_exit(%d) из главного потока\n", r.exitCode);
                    fflush(stdout);
                    if (t_bailPtr) return BailPatchContext(c, JMPL_EXIT);
                    ExitProcess((UINT)r.exitCode);
                }
                // sys_exit из нити: FreeBSD завершает весь процесс — честно.
                printf("[EXEC] sys_exit(%d) из потока %llu — FreeBSD: завершаю процесс\n",
                       r.exitCode, (unsigned long long)t_tid);
                fflush(stdout);
                ExitProcess((UINT)r.exitCode);
            }
            if (r.status == hle::HleStatus::ThreadExit) {
                t_exitCode = (int)r.ret;             // код sys_thr_exit
                if (t_bailPtr) return BailPatchContext(c, JMPL_THREAD_EXIT);
                ExitProcess((UINT)(int)r.ret);
            }
            c->Rax = (DWORD64)r.ret;
            c->Rip += 2;                             // syscall и UD2 — обе по 2 байта
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        // Диагностическая заглушка импорта? (mov eax, idx; ud2; ret)
        const char* sym = nullptr;
        if (dyn::TryResolveStub(rip, &sym)) {
            // GPU-модули (фаза 5): честный HLE по имени символа.
            // Выполнение уходит на выделенную worker-нить — из контекста
            // обработки исключения драйверам делать нечего (см. GpuJob выше).
            if (sym && gpu::Handles(sym)) {
                uint64_t gargs[8];
                ReadGuestArgs(c, gargs);
                c->Rax = (DWORD64)GpuExecuteOffVeh(sym, gargs);
                c->Rip += 2;             // ud2 — 2 байта; дальше в слоте стоит ret
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            // Фаза 7.6: нормальные обработчики libc-импортов (опознаны по
            // поведению вызовов; полная карта PLT->имя: tools/import_map.txt).
            if (sym && g_heapHost == nullptr && g_mem) HeapInit(*g_mem);
            if (sym && g_heapHost) {
                uint64_t a[8];
                t_bailed = false;    // 7.7: флаг "выход оформлен" живёт один вызов
                ReadGuestArgs(c, a);
                uint64_t res = 0;
                bool hit = true;
                if      (!std::strcmp(sym, kImpMalloc))  res = HeapAllocAligned(16, a[0], "malloc");
                else if (!std::strcmp(sym, kImpCalloc))  res = HeapCalloc(a[0] * a[1]);
                else if (!std::strcmp(sym, kImpFree))    res = 0;      // no-op, честно
                else if (!std::strcmp(sym, kImpAligned)) {
                    // PLT[210] = malloc(rdi); rsi — мусор-остаток (см. kImp*-комментарий).
                    // Офлайн-разбор строк вызовов снял гипотезы realloc/memalign.
                    res = HeapAllocAligned(16, a[0], "malloc");
                }
                else if (!std::strcmp(sym, kImpMemcpy))  res = HeapMemmove(c, a[0], a[1], a[2]);
                else if (!std::strcmp(sym, kImpMemset))  res = HeapMemset(c, a[0], a[1], a[2]);
                else if (!std::strcmp(sym, kImpMemmove)) res = HeapMemmove(c, a[0], a[1], a[2]);
                else hit = false;
                if (hit) {
                    static std::atomic<uint32_t> nH{0};
                    if (nH.fetch_add(1) < 14)
                        printf("[EXEC] libc %s(0x%llX, 0x%llX, 0x%llX) -> 0x%llX\n",
                               sym, (unsigned long long)a[0], (unsigned long long)a[1],
                               (unsigned long long)a[2], (unsigned long long)res);
                    fflush(stdout);
                    if (t_bailed) {
                        // Аварийный выход уже оформлен (memcpy по нулевому dst) —
                        // контекст больше НЕ трогаем.
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                    c->Rax = (DWORD64)res;
                    c->Rip += 2;             // ud2 — 2 байта; дальше в слоте ret
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
            static std::mutex smx;
            static std::set<std::string> once;
            bool first = false;
            {
                std::lock_guard<std::mutex> lk(smx);
                first = once.insert(std::string(sym ? sym : "?")).second;
            }
            if (first) {
                // Фаза 7.5: адрес возврата ([rsp]) — чтобы мапить вызов на
                // место в коде гостя (PLT-слот -> анализ оффлайн).
                uint64_t ra = 0, retG = 0;
                if (c->Rsp) memcpy(&ra, (const void*)(uintptr_t)c->Rsp, 8);
                if (g_mem) g_mem->GuestForHost(ra, &retG);
                printf("[EXEC] ВЫЗОВ ИМПОРТА-ЗАГЛУШКИ: %s (ret guest 0x%llX; реализации нет, гостю верну 0)\n",
                       sym ? sym : "?", (unsigned long long)retG);
                fflush(stdout);
            }
            c->Rax = 0;
            c->Rip += 2;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (inGuest) {
            char buf[160];
            snprintf(buf, sizeof(buf),
                     "гостевой UD2 (assert?) @ guest 0x%llX (поток %llu) — краш гостя",
                     (unsigned long long)guestRip, (unsigned long long)t_tid);
            CrashReport(buf);
            if (t_bailPtr) return BailPatchContext(c, JMPL_FAULT);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXC_ACCESS) {
        const uint64_t faultAddr = ep->ExceptionRecord->ExceptionInformation[1];

        // [7.7.1] Компат-хук u16-strcmp гостя (0x1A55450): таблицы имён содержат
        // записи с name == NULL (не заполнены; анализ tools/scan_bail.c, scan2.c).
        // Первый movzx [rdi] / [rsi] уходит в AV по адресу ~0. Точки входа:
        // 0x1A55450 (movzx eax,[rdi]) и 0x1A55453 (movzx ecx,[rsi]); общая точка
        // выхода 0x1A55486 (movzx ecx,cx; movzx eax,ax; sub eax,ecx; ret).
        // Подменяем контекст: rax=1, rcx=0 -> возврат 1 = "не совпало". Все 5
        // вызывающих после compare делают test eax; jz found; иначе идут к
        // следующей записи цепочки — то есть NULL-запись просто не матчится,
        // поиск вернёт not-found, и гость продолжит работу. Без патчей кода.
        if (inGuest && faultAddr < 0x10000ull &&
            (guestRip == 0x1A55450ull || guestRip == 0x1A55453ull)) {
            static std::atomic<uint64_t> s_nullHits{0};
            const uint64_t n = s_nullHits.fetch_add(1) + 1;
            if (n <= 8 || (n % 1000) == 0) {
                char pb[192];
                snprintf(pb, sizeof(pb),
                         "[COMPAT] u16-strcmp @0x1A55450: NULL-имя, пропуск записи #%llu (rdi=0x%llX rsi=0x%llX)\n",
                         (unsigned long long)n,
                         (unsigned long long)c->Rdi, (unsigned long long)c->Rsi);
                AppendLogDirect(pb);
            }
            c->Rax = 1;
            c->Rcx = 0;
            c->Rip = 0x1A55486ull;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        uint64_t guestAddr = 0;
        const bool addrInGuest = g_mem && g_mem->GuestForHost(faultAddr, &guestAddr);
        if (inGuest || addrInGuest) {
            const bool isWrite = ep->ExceptionRecord->ExceptionInformation[0] != 0;
            // Фаза 7.5: дамп байтов по guest RIP + регистры — крэш расшифровывается
            // оффлайн (что читало/писало и откуда взялся ноль).
            if (inGuest) {
                const uint8_t* q = (const uint8_t*)(uintptr_t)(g_mem ? g_mem->Ptr(guestRip) : 0);
                if (q)
                    printf("[EXEC] байты @guest RIP: %02X %02X %02X %02X %02X %02X %02X %02X | "
                           "RAX=0x%llX RBX=0x%llX RDX=0x%llX RDI=0x%llX\n",
                           q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7],
                           (unsigned long long)c->Rax, (unsigned long long)c->Rbx,
                           (unsigned long long)c->Rdx, (unsigned long long)c->Rdi);
                fflush(stdout);
            }
            char buf[224];
            snprintf(buf, sizeof(buf),
                     "краш гостя: %s 0x%llX (guest 0x%llX) @ guest RIP 0x%llX (поток %llu)",
                     isWrite ? "запись в" : "чтение по",
                     (unsigned long long)faultAddr,
                     (unsigned long long)(addrInGuest ? guestAddr : 0),
                     (unsigned long long)guestRip, (unsigned long long)t_tid);
            CrashReport(buf);
            if (t_bailPtr) return BailPatchContext(c, JMPL_FAULT);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXC_PRIV && inGuest) {
        char buf[192];
        snprintf(buf, sizeof(buf),
                 "привилегированная инструкция @ guest 0x%llX (поток %llu) — краш гостя",
                 (unsigned long long)guestRip, (unsigned long long)t_tid);
        CrashReport(buf);
        if (t_bailPtr) return BailPatchContext(c, JMPL_FAULT);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXC_BREAK && inGuest) {
        // int3 в гостевом коде (CC-паддинг) — логируем один раз и идём дальше
        static std::mutex bmx;
        static uint64_t last = 0;
        bool show = false;
        { std::lock_guard<std::mutex> lk(bmx); if (rip != last) { last = rip; show = true; } }
        if (show) {
            printf("[EXEC] гостевой int3 @ guest 0x%llX (поток %llu) — пропускаю\n",
                   (unsigned long long)guestRip, (unsigned long long)t_tid);
            fflush(stdout);
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    // Фаза 7.6: последняя линия обороны — ЛЮБОЕ исключение в гостевом коде,
    // которое мы не умеем продолжить (0xC00000FD переполнение стека,
    // 0xC0000409 и прочие), даёт ЧЕСТНЫЙ краш с диагнозом. Раньше такие
    // коды улетали в CONTINUE_SEARCH и процесс умирал МОЛЧА.
    if (inGuest) {
        const uint64_t fa = ep->ExceptionRecord->ExceptionInformation[1];
        uint64_t gfa = 0;
        const bool aInG = g_mem && g_mem->GuestForHost(fa, &gfa);
        (void)aInG;
        char buf[288];
        snprintf(buf, sizeof(buf),
                 "исключение 0x%08X @ guest RIP 0x%llX (поток %llu), адрес 0x%llX (guest 0x%llX) — краш гостя",
                 (unsigned)code, (unsigned long long)guestRip, (unsigned long long)t_tid,
                 (unsigned long long)fa, (unsigned long long)gfa);
        CrashReport(buf);
        if (t_bailPtr) return BailPatchContext(c, JMPL_FAULT);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// --- Патч/восстановление -----------------------------------------------------
static size_t PatchSyscalls(Memory& mem) {
    g_patches.clear();
    g_byHost.clear();
    for (const MemSegment& s : mem.Segments()) {
        if (!(s.protFlags & PF_X) || !s.actual || !s.memsz) continue;
        uint8_t* base = (uint8_t*)(uintptr_t)s.actual;
        for (uint64_t i = 0; i + 1 < s.memsz; ++i) {
            if (base[i] == 0x0F && base[i + 1] == 0x05) {
                Patch p;
                p.host  = s.actual + i;
                p.guest = s.vaddr + i;
                base[i]     = 0x0F;
                base[i + 1] = 0x0B;   // UD2
                g_byHost[p.host] = g_patches.size();
                g_patches.push_back(p);
            }
        }
    }
    return g_patches.size();
}

// --- Гостевые потоки (sys_thr_create -> SpawnThread) --------------------------
struct ThrArg {
    uint64_t entry;   // гостевой vaddr функции start
    uint64_t arg;     // её единственный аргумент
    uint64_t tid;     // гостевой tid
};

// Гостевая функция — SysV ABI (аргумент в rdi). Атрибут говорит GCC
// конвертировать вызов из Windows-конвенции — arg попадёт куда нужно.
using GuestFn = void (__attribute__((sysv_abi)) *)(void *);

static unsigned __stdcall ThreadProc(void* p) {
    ThrArg* a = (ThrArg*)p;
    t_tid = a->tid;
    t_armed = true;
    t_fault[0] = 0;
    t_exitCode = 0;
    t_bailed = false;
    t_bailPtr = nullptr;

    const uint64_t hostEntry = g_mem ? g_mem->Translate(a->entry) : 0;
    uint64_t rc = 0;
    if (hostEntry) {
        printf("[EXEC] поток %llu: entry guest 0x%llX -> host 0x%llX, arg=0x%llX\n",
               (unsigned long long)t_tid,
               (unsigned long long)a->entry,
               (unsigned long long)hostEntry,
               (unsigned long long)a->arg);
        fflush(stdout);
        // Фаза 7.7: тот же трамплин, что у main — без longjmp/раскрутки.
        rc = GuestLaunch(hostEntry, a->arg, 0);
    } else {
        printf("[EXEC] поток %llu: entry 0x%llX не мапнут — нить не запущена\n",
               (unsigned long long)t_tid, (unsigned long long)a->entry);
    }
    t_armed = false;
    t_bailPtr = nullptr;

    if (rc == 0) {
        if (hostEntry)
            printf("[EXEC] поток %llu вернулся через ret — завершаю нить\n",
                   (unsigned long long)t_tid);
    } else if (t_fault[0]) {
        printf("[EXEC] поток %llu остановлен: %s\n",
               (unsigned long long)t_tid, t_fault);
    } else {
        printf("[EXEC] поток %llu остановлен (код %lld)\n",
               (unsigned long long)t_tid, (long long)(int64_t)rc);
    }
    fflush(stdout);

    const unsigned rcv = (unsigned)t_exitCode;
    delete a;
    _endthreadex(rcv);
    return rcv;
}

uint64_t SpawnThread(uint64_t entryVaddr, uint64_t arg, uint64_t* tidOut) {
    if (!g_mem) return 0;

    const uint64_t tid = g_nextTid.fetch_add(1);
    ThrArg* a = new ThrArg{ entryVaddr, arg, tid };

    // Стек нити 4 МБ (как у PS5-потоков по умолчанию, примерно)
    const uintptr_t h = _beginthreadex(nullptr, 4u << 20, &ThreadProc, a, 0, nullptr);
    if (!h) {
        delete a;
        return 0;
    }
    CloseHandle((HANDLE)h);   // нить живёт сама; синхронизации в фазе 4 нет

    if (tidOut) *tidOut = tid;
    g_threadsSpawned.fetch_add(1);
    return tid;
}

uint64_t CurrentTid() { return t_tid; }

// --- Запуск главного потока гостя --------------------------------------------
RunResult Run(Memory& mem, uint64_t entryVaddr, const ElfImage& e) {
    RunResult rr;
    OpenCrashLog();   // 7.7: append-хэндл лога заранее (страховка; main зовёт раньше)

    const uint64_t hostEntry = mem.Translate(entryVaddr);
    if (!hostEntry) {
        rr.status = "entry не ложится ни на один PT_LOAD — запуск невозможен";
        return rr;
    }
    rr.started = true;

    const size_t nPatched = PatchSyscalls(mem);
    printf("[EXEC] сегменты X: патч syscall->UD2: %u сайт(ов)\n", (unsigned)nPatched);
    if (nPatched == 0)
        printf("[EXEC] внимание: syscall'ов не найдено — HLE перехват не сработает\n");
    fflush(stdout);

    g_mem = &mem;

    if (!g_veh) {
        g_veh = AddVectoredExceptionHandler(1, &VehHandler);
        if (!g_veh) {
            rr.status = "AddVectoredExceptionHandler не удался";
            return rr;
        }
    }
    // Фаза 7.6: страховка самого края — исключения, которые не перехватил VEH
    // (чужие нити), больше не убивают процесс молча: LastChanceFilter
    // печатает диагноз в лог перед смертью процесса.
    static bool s_uef = false;
    if (!s_uef) {
        s_uef = true;
        // Сохраняем предыдущий фильтр (main.cpp держит окно открытым) —
        // цепочка вместо затирания.
        s_prevUef = SetUnhandledExceptionFilter(&LastChanceFilter);
    }
    // VEH остаётся на весь процесс: нити гостя живут дольше Run (фаза 4).

    // --- Фаза 7.3: TLS/TCB ------------------------------------------------------
    // Гость (FreeBSD ABI) держит TCB в fs. У x64 Windows fs свободна (TEB в gs),
    // поэтому ставим fs сами — если CPU+ОС дают FSGSBASE. PT_TLS у Dead Cells
    // пустой (filesz=0), но TCB нужен всегда: libc пишет в него ключи/dtv.
    // Раскладка блока: [шаблон .tdata (round 0x40)][TCB 0x400]; self-указатель
    // в TCB+0 (наш TCB — временный: libc обычно пере-ставляет fs через sysarch).
    {
        DetectFsBase();   // фаза 7.3: тест wrfsbase под нашим VEH
        const zrx::ElfSegment* tls = nullptr;
        for (const zrx::ElfSegment& p : e.phdrs)
            if (p.type == zrx::PT_TLS) { tls = &p; break; }
        const uint64_t tmplSz = tls ? ((tls->memsz + 0x3F) & ~0x3Full) : 0;
        const uint64_t blockSz = tmplSz + 0x400;
        const uint64_t blockV = mem.AllocGuest(blockSz, zrx::PF_R | zrx::PF_W);
        if (blockV) {
            const uint64_t tcbV = blockV + tmplSz;      // TCB сразу за шаблоном
            uint8_t* p = (uint8_t*)(uintptr_t)mem.Ptr(blockV);
            if (tls && tls->filesz && mem.Ptr(tls->vaddr))
                memcpy(p, mem.Ptr(tls->vaddr), (size_t)tls->filesz);   // .tdata
            memcpy(p + tmplSz, &tcbV, 8);               // tcb self @+0
            if (hle::SetFsBase(tcbV))
                printf("[7.3] TLS: TCB @guest 0x%llX, fs поставлен (шаблон %llu байт)\n",
                       (unsigned long long)tcbV,
                       (unsigned long long)(tls ? tls->filesz : 0));
            else
                printf("[7.3] TLS: TCB @guest 0x%llX выделен, НО fs поставить нельзя "
                       "(FSGSBASE недоступен) — жду fs-крэш как диагностику\n",
                       (unsigned long long)tcbV);
        } else {
            printf("[7.3] TLS: блок TCB не выделился\n");
        }
        fflush(stdout);
    }

    // --- Фаза 7.4/7.5: блок аргументов ядра (rdi/rsi на входе в entry) ------------
    // Реверс entry (disasm @0x400070): r14d=[rdi] — argc (u32!); r15 = rdi+8 —
    // НАЧАЛО МАССИВА argv (идёт в main как rsi); rsi -> rbx уходит 2-му импорту
    // (смысл неясен — даём пустой envp-массив). Блок: [0..4)=argc; [8)=argv[0];
    // [16)=argv[1]=NULL. argv[0] = "/app0/eboot.bin" — как даёт PS5-ядро.
    // (Старая гипотеза "size/base" врала: гость читал argc=0x100 из size-поля.)
    uint64_t argsV = 0, envpV = 0;
    {
        static const char kArgv0[] = "/app0/eboot.bin";
        const uint64_t strV = mem.AllocGuest(sizeof(kArgv0) + 8, zrx::PF_R | zrx::PF_W);
        if (strV && mem.Ptr(strV))
            memcpy((void*)(uintptr_t)mem.Ptr(strV), kArgv0, sizeof(kArgv0));
        argsV = mem.AllocGuest(0x40, zrx::PF_R | zrx::PF_W);
        envpV = mem.AllocGuest(8, zrx::PF_R | zrx::PF_W);
        if (argsV && mem.Ptr(argsV) && envpV && mem.Ptr(envpV)) {
            uint8_t* p = (uint8_t*)(uintptr_t)mem.Ptr(argsV);
            const uint32_t argc = 1;
            const uint64_t a0 = strV, aEnd = 0, eNull = 0;
            memcpy(p + 0, &argc, 4);          // argc (u32)
            memcpy(p + 8, &a0, 8);            // argv[0] -> строка
            memcpy(p + 16, &aEnd, 8);         // argv[1] = NULL
            memcpy((void*)(uintptr_t)mem.Ptr(envpV), &eNull, 8);   // envp = {NULL}
            printf("[7.4] kernel-args @guest 0x%llX: argc=1, argv[] в блоке (+8), "
                   "argv[0]=0x%llX (\"%s\"), envp @0x%llX = {NULL}\n",
                   (unsigned long long)argsV, (unsigned long long)strV, kArgv0,
                   (unsigned long long)envpV);
        } else {
            printf("[7.4] kernel-args/envp не выделились — entry получит мусор\n");
        }
        fflush(stdout);
    }

    t_tid = 1;
    t_armed = true;
    t_fault[0] = 0;
    t_exitCode = 0;
    t_bailed = false;
    t_bailPtr = nullptr;

    printf("[EXEC] передача управления: entry 0x%llX -> хост 0x%llX (native x86-64)\n",
           (unsigned long long)entryVaddr, (unsigned long long)hostEntry);
    fflush(stdout);
    // Фаза 7.7: гость запускается через трамплин launch.S — спил callee-saved,
    // вызов entry (SysV ABI: rdi = kernel-args фазы 7.5, rsi = envp). При краше
    // VEH подменяет контекст и трамплин "возвращает" код — БЕЗ longjmp и без
    // раскрутки Windows по гостевым кадрам (ntdll 0xC00000FF, WER 21:44).
    const uint64_t v = GuestLaunch(hostEntry, argsV, envpV);
    t_armed = false;
    t_bailPtr = nullptr;

    if (v == 0) {
        rr.exited = true;
        rr.exitCode = 0;
        rr.status = "entry вернулся через ret — гость завершился сам";
    } else if (v == (uint64_t)JMPL_EXIT) {
        rr.exited = true;
        rr.exitCode = t_exitCode;
        char buf[96];
        snprintf(buf, sizeof(buf), "sys_exit(%d) — гость попросил выход", rr.exitCode);
        rr.status = buf;
    } else if (v == (uint64_t)JMPL_THREAD_EXIT) {
        rr.exited = false;
        rr.exitCode = t_exitCode;
        rr.status = "sys_thr_exit из главного потока — нить завершена";
    } else {
        rr.exited = false;
        rr.exitCode = (int)v;
        rr.status = t_fault[0] ? t_fault : "остановка без описания";
    }
    // ПАТЧИ НЕ ВОССТАНАВЛИВАЕМ и VEH НЕ СНИМАЕМ: нити гостя продолжают работу.

    if (g_threadsSpawned.load() > 0)
        printf("[EXEC] гостевых нитей создано: %d — работают после выхода main\n",
               g_threadsSpawned.load());
    return rr;
}

} } // namespace zrx::exec
