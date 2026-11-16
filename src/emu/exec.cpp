// ============================================================================
// ZerpexPS5 — фаза 4: исполнение (реализация: патч syscall + VEH + потоки)
// ============================================================================
#include "exec.h"

#include "../core/dyn.h"   // TryResolveStub (импорт-заглушки)
#include "../core/elf.h"   // PF_X
#include "../core/hle.h"
#include "gpu.h"           // GPU-модули (фаза 5): sceVideoOut*/sceGnm*

#include <windows.h>
#include <process.h>       // _beginthreadex
#include <setjmp.h>

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
static void*   g_veh = nullptr;                   // живёт весь процесс
static std::atomic<uint64_t> g_nextTid { 2 };
static std::atomic<int> g_threadsSpawned { 0 };

// --- Состояние НА ПОТОК (гость многопоточный) --------------------------------
static __thread jmp_buf t_jmp;
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

[[noreturn]] static void BailOut(int code, const char* text) {
    t_fault[0] = 0;
    if (text) snprintf(t_fault, sizeof(t_fault), "%s", text);
    t_armed = false;
    longjmp(t_jmp, code);
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
static LONG NTAPI VehHandler(PEXCEPTION_POINTERS ep) {
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
                if (t_tid == 1)
                    BailOut(JMPL_EXIT, nullptr);     // к setjmp в Run()
                // sys_exit из нити: FreeBSD завершает весь процесс — честно.
                printf("[EXEC] sys_exit(%d) из потока %llu — FreeBSD: завершаю процесс\n",
                       r.exitCode, (unsigned long long)t_tid);
                fflush(stdout);
                ExitProcess((UINT)r.exitCode);
            }
            if (r.status == hle::HleStatus::ThreadExit) {
                t_exitCode = (int)r.ret;             // код sys_thr_exit
                BailOut(JMPL_THREAD_EXIT, nullptr);  // вернёт в ThreadProc
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
            static std::mutex smx;
            static std::set<std::string> once;
            bool first = false;
            {
                std::lock_guard<std::mutex> lk(smx);
                first = once.insert(std::string(sym ? sym : "?")).second;
            }
            if (first) {
                printf("[EXEC] ВЫЗОВ ИМПОРТА-ЗАГЛУШКИ: %s (реализации нет, гостю верну 0)\n",
                       sym ? sym : "?");
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
            BailOut(JMPL_FAULT, buf);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXC_ACCESS) {
        const uint64_t faultAddr = ep->ExceptionRecord->ExceptionInformation[1];
        uint64_t guestAddr = 0;
        const bool addrInGuest = g_mem && g_mem->GuestForHost(faultAddr, &guestAddr);
        if (inGuest || addrInGuest) {
            const bool isWrite = ep->ExceptionRecord->ExceptionInformation[0] != 0;
            char buf[224];
            snprintf(buf, sizeof(buf),
                     "краш гостя: %s 0x%llX (guest 0x%llX) @ guest RIP 0x%llX (поток %llu)",
                     isWrite ? "запись в" : "чтение по",
                     (unsigned long long)faultAddr,
                     (unsigned long long)(addrInGuest ? guestAddr : 0),
                     (unsigned long long)guestRip, (unsigned long long)t_tid);
            BailOut(JMPL_FAULT, buf);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (code == EXC_PRIV && inGuest) {
        char buf[192];
        snprintf(buf, sizeof(buf),
                 "привилегированная инструкция @ guest 0x%llX (поток %llu) — краш гостя",
                 (unsigned long long)guestRip, (unsigned long long)t_tid);
        BailOut(JMPL_FAULT, buf);
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

    const uint64_t hostEntry = g_mem ? g_mem->Translate(a->entry) : 0;

    if (setjmp(t_jmp) == 0) {
        if (hostEntry) {
            printf("[EXEC] поток %llu: entry guest 0x%llX -> host 0x%llX, arg=0x%llX\n",
                   (unsigned long long)t_tid,
                   (unsigned long long)a->entry,
                   (unsigned long long)hostEntry,
                   (unsigned long long)a->arg);
            fflush(stdout);
            ((GuestFn)(uintptr_t)hostEntry)((void*)(uintptr_t)a->arg);
            printf("[EXEC] поток %llu вернулся через ret — завершаю нить\n",
                   (unsigned long long)t_tid);
            fflush(stdout);
        } else {
            printf("[EXEC] поток %llu: entry 0x%llX не мапнут — нить не запущена\n",
                   (unsigned long long)t_tid, (unsigned long long)a->entry);
            fflush(stdout);
        }
    } else {
        // longjmp: краш нити (sys_thr_exit приходит через JMPL_THREAD_EXIT)
        if (t_fault[0]) {
            printf("[EXEC] поток %llu остановлен: %s\n",
                   (unsigned long long)t_tid, t_fault);
            fflush(stdout);
        }
    }

    const unsigned rc = (unsigned)t_exitCode;
    delete a;
    t_armed = false;
    _endthreadex(rc);
    return rc;
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
RunResult Run(Memory& mem, uint64_t entryVaddr) {
    RunResult rr;

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
    // VEH остаётся на весь процесс: нити гостя живут дольше Run (фаза 4).

    t_tid = 1;
    t_armed = true;
    t_fault[0] = 0;
    t_exitCode = 0;

    const int v = setjmp(t_jmp);
    if (v == 0) {
        printf("[EXEC] передача управления: entry 0x%llX -> хост 0x%llX (native x86-64)\n",
               (unsigned long long)entryVaddr, (unsigned long long)hostEntry);
        fflush(stdout);
        // Гостевой entry — SysV ABI: rdi=argc, rsi=argv, rdx=envp.
        using GuestMain = void (__attribute__((sysv_abi)) *)(uint64_t, void *);
        ((GuestMain)(uintptr_t)hostEntry)(0, nullptr);
        rr.exited = true;
        rr.exitCode = 0;
        rr.status = "entry вернулся через ret — гость завершился сам";
    } else if (v == JMPL_EXIT) {
        rr.exited = true;
        rr.exitCode = t_exitCode;
        char buf[96];
        snprintf(buf, sizeof(buf), "sys_exit(%d) — гость попросил выход", rr.exitCode);
        rr.status = buf;
    } else if (v == JMPL_THREAD_EXIT) {
        rr.exited = false;
        rr.exitCode = t_exitCode;
        rr.status = "sys_thr_exit из главного потока — нить завершена";
    } else {
        rr.exited = false;
        rr.exitCode = v;
        rr.status = t_fault[0] ? t_fault : "остановка без описания";
    }

    t_armed = false;
    // ПАТЧИ НЕ ВОССТАНАВЛИВАЕМ и VEH НЕ СНИМАЕМ: нити гостя продолжают работу.

    if (g_threadsSpawned.load() > 0)
        printf("[EXEC] гостевых нитей создано: %d — работают после выхода main\n",
               g_threadsSpawned.load());
    return rr;
}

} } // namespace zrx::exec
