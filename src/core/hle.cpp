// ============================================================================
// ZerpexPS5 — ядро: HLE (таблица + диспетчер исполнения)
//
// Реально работают (фаза 3): sys_write(stdout/stderr), sys_exit, sys_mmap,
// sys_munmap, sys_mprotect, sys_clock_gettime, sys_gettimeofday,
// sys_nanosleep, sys_sched_yield, getpid/uid-ы, thr_self, __syscall.
// Реально работают (фаза 4): sys_open/read/write(файлы)/close/lseek/pread,
// sys_fstat/stat (layout FreeBSD x64, 144 байта), sys___getcwd,
// sys_thr_create (нить Windows), sys_thr_exit, sys_cpumode_yield.
// Остальные из таблицы — заглушки: логируют вызов и возвращают 0.
//
// Файлы: путь гостя маппится в корень игры (SetGameRoot):
//   /app0/... и /data/... -> <корень игры>, /dev/null -> NUL,
//   "X:\..." -> как есть, относительный путь -> <корень игры>\...
// ============================================================================
#include "hle.h"

#include "elf.h"           // PF_R/PF_W/PF_X
#include "../emu/exec.h"   // SpawnThread/CurrentTid (потоки гостя, фаза 4)

#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>

#include <windows.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>

namespace zrx {
namespace hle {

// Все номера сверены с psdevwiki /ps5/Syscalls (PS5 = нумерация PS4 + свои)
static const SyscallInfo kAll[] = {
    // --- proc ---
    { 1,   "sys_exit",                       "proc" },
    { 2,   "sys_fork",                       "proc" },
    { 20,  "sys_getpid",                     "proc" },
    { 24,  "sys_getuid",                     "proc" },
    { 25,  "sys_geteuid",                    "proc" },
    { 37,  "sys_kill",                       "proc" },
    { 39,  "sys_getppid",                    "proc" },
    { 59,  "sys_execve",                     "proc" },
    { 165, "sys_sysarch",                    "proc" },
    { 251, "sys_rfork",                      "proc" },
    { 532, "sys_regmgr_call",                "proc" },
    { 585, "sys_is_in_sandbox",              "proc" },
    { 587, "sys_get_authinfo",               "proc" },
    { 647, "sys_get_sdk_compiled_version",   "proc" },
    { 652, "sys_process_terminate",          "proc" },
    { 676, "sys_cpumode_yield",              "proc" },
    // --- fs ---
    { 3,   "sys_read",                       "fs" },
    { 4,   "sys_write",                      "fs" },
    { 5,   "sys_open",                       "fs" },
    { 6,   "sys_close",                      "fs" },
    { 10,  "sys_unlink",                     "fs" },
    { 33,  "sys_access",                     "fs" },
    { 54,  "sys_ioctl",                      "fs" },
    { 92,  "sys_fcntl",                      "fs" },
    { 128, "sys_rename",                     "fs" },
    { 136, "sys_mkdir",                      "fs" },
    { 137, "sys_rmdir",                      "fs" },
    { 138, "sys_utimes",                     "fs" },
    { 188, "sys_stat",                       "fs" },
    { 189, "sys_fstat",                      "fs" },
    { 190, "sys_lstat",                      "fs" },
    { 196, "sys_getdirentries",              "fs" },
    { 272, "sys_getdents",                   "fs" },
    { 326, "sys___getcwd",                   "fs" },
    { 475, "sys_pread",                      "fs" },
    { 476, "sys_pwrite",                     "fs" },
    { 478, "sys_lseek",                      "fs" },
    { 479, "sys_truncate",                   "fs" },
    { 480, "sys_ftruncate",                  "fs" },
    { 493, "sys_fstatat",                    "fs" },
    { 499, "sys_openat",                     "fs" },
    // --- mem ---
    { 65,  "sys_msync",                      "mem" },
    { 73,  "sys_munmap",                     "mem" },
    { 74,  "sys_mprotect",                   "mem" },
    { 75,  "sys_madvise",                    "mem" },
    { 78,  "sys_mincore",                    "mem" },
    { 203, "sys_mlock",                      "mem" },
    { 204, "sys_munlock",                    "mem" },
    { 477, "sys_mmap",                       "mem" },
    { 482, "sys_shm_open",                   "mem" },
    { 483, "sys_shm_unlink",                 "mem" },
    { 533, "sys_jitshm_create",              "mem" },
    { 534, "sys_jitshm_alias",               "mem" },
    { 547, "sys_query_memory_protection",    "mem" },
    { 548, "sys_batch_map",                  "mem" },
    { 572, "sys_virtual_query",              "mem" },
    { 674, "sys_virtual_query_all",          "mem" },
    // --- thread ---
    { 340, "sys_sigprocmask",                "thread" },
    { 430, "sys_thr_create",                 "thread" },
    { 431, "sys_thr_exit",                   "thread" },
    { 432, "sys_thr_self",                   "thread" },
    { 433, "sys_thr_kill",                   "thread" },
    { 442, "sys_thr_suspend",                "thread" },
    { 443, "sys_thr_wake",                   "thread" },
    { 452, "sys__umtx_op",                   "thread" },
    { 455, "sys_thr_new",                    "thread" },
    { 464, "sys_thr_set_name",               "thread" },
    { 481, "sys_thr_kill2",                  "thread" },
    { 616, "sys_thr_get_name",               "thread" },
    // --- time ---
    { 116, "sys_gettimeofday",               "time" },
    { 232, "sys_clock_gettime",              "time" },
    { 234, "sys_clock_getres",               "time" },
    { 240, "sys_nanosleep",                  "time" },
    { 331, "sys_sched_yield",                "time" },
    // --- dynlib (загрузчик модулей PS5) ---
    { 589, "sys_dynlib_dlopen",              "dynlib" },
    { 590, "sys_dynlib_dlclose",             "dynlib" },
    { 591, "sys_dynlib_dlsym",               "dynlib" },
    { 592, "sys_dynlib_get_list",            "dynlib" },
    { 593, "sys_dynlib_get_info",            "dynlib" },
    { 594, "sys_dynlib_load_prx",            "dynlib" },
    { 595, "sys_dynlib_unload_prx",          "dynlib" },
    { 596, "sys_dynlib_do_copy_relocations", "dynlib" },
    { 598, "sys_dynlib_get_proc_param",      "dynlib" },
    { 599, "sys_dynlib_process_needed_and_relocate", "dynlib" },
    { 604, "sys_dl_get_metadata",            "dynlib" },
    { 608, "sys_dynlib_get_info_ex",         "dynlib" },
    { 659, "sys_dynlib_get_list2",           "dynlib" },
    { 660, "sys_dynlib_get_info2",           "dynlib" },
    // --- сигналы ---
    { 53,  "sys_sigaltstack",                "sig" },
    { 343, "sys_sigpending",                 "sig" },
    { 345, "sys_sigtimedwait",               "sig" },
    { 346, "sys_sigwaitinfo",                "sig" },
    { 416, "sys_sigaction",                  "sig" },
    { 417, "sys_sigreturn",                  "sig" },
    { 198, "sys___syscall",                  "sig" },
    // --- сеть ---
    { 29,  "sys_recvfrom",                   "net" },
    { 30,  "sys_accept",                     "net" },
    { 97,  "sys_socket",                     "net" },
    { 98,  "sys_connect",                    "net" },
    { 104, "sys_bind",                       "net" },
    { 105, "sys_setsockopt",                 "net" },
    { 106, "sys_listen",                     "net" },
    { 118, "sys_getsockopt",                 "net" },
    { 133, "sys_sendto",                     "net" },
    { 134, "sys_shutdown",                   "net" },
    // --- PS5-специфика (объекты ядра) ---
    { 538, "sys_evf_create",                 "ps5" },
    { 539, "sys_evf_delete",                 "ps5" },
    { 540, "sys_evf_open",                   "ps5" },
    { 541, "sys_evf_close",                  "ps5" },
    { 542, "sys_evf_wait",                   "ps5" },
    { 543, "sys_evf_trywait",                "ps5" },
    { 544, "sys_evf_set",                    "ps5" },
    { 545, "sys_evf_clear",                  "ps5" },
    { 546, "sys_evf_cancel",                 "ps5" },
    { 549, "sys_osem_create",                "ps5" },
    { 550, "sys_osem_delete",                "ps5" },
    { 551, "sys_osem_open",                  "ps5" },
    { 552, "sys_osem_close",                 "ps5" },
    { 553, "sys_osem_wait",                  "ps5" },
    { 554, "sys_osem_trywait",               "ps5" },
    { 555, "sys_osem_post",                  "ps5" },
    { 556, "sys_osem_cancel",                "ps5" },
    { 557, "sys_namedobj_create",            "ps5" },
    { 558, "sys_namedobj_delete",            "ps5" },
    { 487, "sys_cpuset_getaffinity",         "ps5" },
    { 488, "sys_cpuset_setaffinity",         "ps5" },
    // --- фаза 5+: GPU-пулы, aio, ucontext и прочее (сверено с psdevwiki) ---
    { 653, "sys_blockpool_open",             "ps5" },
    { 654, "sys_blockpool_map",              "ps5" },
    { 655, "sys_blockpool_unmap",            "ps5" },
    { 657, "sys_blockpool_batch",            "ps5" },
    { 673, "sys_blockpool_move",             "ps5" },
    { 658, "sys_fdatasync",                  "fs" },
    { 661, "sys_aio_submit",                 "fs" },
    { 662, "sys_aio_multi_delete",           "fs" },
    { 663, "sys_aio_multi_wait",             "fs" },
    { 664, "sys_aio_multi_poll",             "fs" },
    { 665, "sys_aio_get_data",               "fs" },
    { 666, "sys_aio_multi_cancel",           "fs" },
    { 668, "sys_aio_create",                 "fs" },
    { 669, "sys_aio_submit_cmd",             "fs" },
    { 670, "sys_aio_init",                   "fs" },
    { 632, "sys_thr_suspend_ucontext",       "thread" },
    { 633, "sys_thr_resume_ucontext",        "thread" },
    { 634, "sys_thr_get_ucontext",           "thread" },
    { 635, "sys_thr_set_ucontext",           "thread" },
    { 535, "sys_dl_get_list",                "dynlib" },
    { 536, "sys_dl_get_info",                "dynlib" },
    { 588, "sys_mname",                      "mem" },
    { 600, "sys_sandbox_path",               "proc" },
    { 649, "sys_dynlib_get_obj_member",      "dynlib" },
    { 656, "sys_dynlib_get_info_for_libdbg", "dynlib" },
    { 672, "sys_dynlib_get_list_for_libdbg", "dynlib" },
};

const std::vector<SyscallInfo>& Table() {
    static const std::vector<SyscallInfo> v(kAll, kAll + sizeof(kAll) / sizeof(kAll[0]));
    return v;
}

static const char* NameOf(uint32_t num) {
    for (const SyscallInfo& s : Table())
        if (s.num == num) return s.name;
    return nullptr;
}

// ----------------------------------------------------------------------------
// Состояние диспетчера
// ----------------------------------------------------------------------------
static Memory* g_mem = nullptr;
static std::map<uint32_t, int> g_hits;      // num -> сколько раз
static std::map<uint32_t, int> g_unknown;   // num -> сколько раз

// --- Файловая система (фаза 4) ---
static std::wstring g_root;                  // корень игры (SetGameRoot)
static std::map<int, int> g_files;           // гост fd -> хост fd (CRT)
static int g_nextFd = 3;                     // 0/1/2 — консоль

void AttachMemory(Memory* mem) { g_mem = mem; }

// --- Фаза 7.3: fs-база гостя --------------------------------------------------
// Тест FSGSBASE делаем в exec.cpp (там живёт VEH — GCC не даёт __try в C++).
// Здесь только флаг и сама запись. На x64 Windows fs свободна (TEB в gs).
static int g_fsAvail = 0;   // 0/1; ставится exec::DetectFsBase через SetFsBaseSupported

static void WrFsBaseRaw(uint64_t v) { __builtin_ia32_wrfsbase64(v); }

void SetFsBaseSupported(bool ok) { g_fsAvail = ok ? 1 : 0; }

bool FsBaseAvailable() { return g_fsAvail == 1; }

bool SetFsBase(uint64_t v) {
    if (!FsBaseAvailable()) return false;
    WrFsBaseRaw(v);
    return true;
}

void SetGameRoot(const std::wstring& root) { g_root = root; }

static void LogCall(uint32_t num, const uint64_t args[8], const char* name) {
    const int n = ++g_hits[num];
    if (n > 50 && (n % 200) != 0) return;   // шумные вызовы не спамим
    printf("[HLE] #%-4u %-30s (0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX)%s\n",
           (unsigned)num, name,
           (unsigned long long)args[0], (unsigned long long)args[1],
           (unsigned long long)args[2], (unsigned long long)args[3],
           (unsigned long long)args[4], (unsigned long long)args[5],
           n > 50 ? "  (повторы...)" : "");
    fflush(stdout);
}

// ----------------------------------------------------------------------------
// Маппинг путей гостя (фаза 4)
// ----------------------------------------------------------------------------
static std::wstring WideFromUtf8(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)(n > 0 ? n : 0), L'\0');
    if (n > 0)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// Гостевой путь -> хостовый. /app0 и /data ведут в корень игры,
// /dev/null -> NUL, "X:\..." проходит как есть, относительные — в корень.
// ".." в пути запрещён: песочница не даёт выйти за корень игры.
static bool MapPath(const char* guest, std::wstring* out) {
    char buf[512];
    size_t i = 0;
    while (i + 1 < sizeof(buf) && guest[i]) {
        const unsigned char c = (unsigned char)guest[i];
        if (c < 0x20 || c >= 0x7F) break;      // печатный ASCII — честно
        buf[i] = guest[i];
        ++i;
    }
    buf[i] = 0;
    const std::string s = buf;
    if (s.empty()) return false;
    if (s.find("..") != std::string::npos) return false;

    auto fixSlash = [](std::wstring* w) {
        for (wchar_t& ch : *w) if (ch == L'/') ch = L'\\';
    };

    if (s.rfind("/app0", 0) == 0 || s.rfind("/data", 0) == 0) {
        if (g_root.empty()) return false;
        const std::string rest = s.substr(5);              // "" или "/..."
        std::wstring w = g_root + WideFromUtf8(rest);
        fixSlash(&w);
        *out = w;
        return true;
    }
    if (s == "/dev/null" || s == "/dev/zero") {
        *out = L"NUL";
        return true;
    }
    if (s.size() >= 2 &&
        ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) &&
        s[1] == ':') {
        std::wstring w = WideFromUtf8(s);                  // диск Windows — как есть
        fixSlash(&w);
        *out = w;
        return true;
    }
    if (s[0] != '/' && s[0] != '\\') {                     // относительный
        if (g_root.empty()) return false;
        std::wstring w = g_root + L"\\" + WideFromUtf8(s);
        fixSlash(&w);
        *out = w;
        return true;
    }
    return false;   // прочие POSIX-пути — честный ENOENT
}

// --- Гостевая память: u64 и struct stat (FreeBSD x64) ------------------------
static void NowRealtime(int64_t* sec, int64_t* nsec);   // определение ниже

static bool GuestWriteU64(uint64_t addr, uint64_t val) {
    if (!g_mem) return false;
    uint8_t* p = g_mem->Ptr(addr);
    if (!p) return false;
    memcpy(p, &val, 8);
    return true;
}

// struct stat FreeBSD x64 (наши дампы, amd64): sizeof=144
//   st_dev u64 @0x00, st_ino u64 @0x08, st_nlink u64 @0x10, st_mode u16 @0x18,
//   st_uid u32 @0x1C, st_gid u32 @0x20, st_rdev u64 @0x28, st_atim @0x30,
//   st_mtim @0x40, st_ctim @0x50 (timespec = 2x i64), st_size i64 @0x60,
//   st_blocks i64 @0x68, st_blksize u32 @0x70.
static bool GuestWriteStat(uint64_t ptr, uint16_t mode, uint64_t size) {
    if (!g_mem) return false;
    uint8_t* p = g_mem->Ptr(ptr);
    if (!p) return false;
    memset(p, 0, 144);

    const uint64_t dev = 0x5A00000001ull, ino = 12345, nlink = 1, rdev = 0;
    memcpy(p + 0x00, &dev, 8);
    memcpy(p + 0x08, &ino, 8);
    memcpy(p + 0x10, &nlink, 8);
    memcpy(p + 0x18, &mode, 2);
    const uint32_t uid = 1000, gid = 1000;
    memcpy(p + 0x1C, &uid, 4);
    memcpy(p + 0x20, &gid, 4);
    memcpy(p + 0x28, &rdev, 8);

    int64_t sec = 0, nsec = 0;
    NowRealtime(&sec, &nsec);                 // atime = mtime = ctime = сейчас
    const int64_t ts[2] = { sec, nsec };
    memcpy(p + 0x30, ts, 16);
    memcpy(p + 0x40, ts, 16);
    memcpy(p + 0x50, ts, 16);

    const int64_t sz = (int64_t)size;
    const int64_t blocks = (int64_t)((size + 511) / 512);
    const uint32_t blksize = 4096;
    memcpy(p + 0x60, &sz, 8);
    memcpy(p + 0x68, &blocks, 8);
    memcpy(p + 0x70, &blksize, 4);
    return true;
}

// --- Гостевое время ---------------------------------------------------------
static void NowRealtime(int64_t* sec, int64_t* nsec) {
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    const int64_t w100 = (int64_t)u.QuadPart - 116444736000000000LL; // к эпохе 1970
    *sec  = w100 / 10000000;
    *nsec = (w100 % 10000000) * 100;
}

static void NowMonotonic(int64_t* sec, int64_t* nsec) {
    LARGE_INTEGER f, q;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&q);
    *sec  = q.QuadPart / f.QuadPart;
    *nsec = ((q.QuadPart % f.QuadPart) * 1000000000LL) / f.QuadPart;
}

static bool GuestWriteTimespec(uint64_t ptr, int64_t sec, int64_t nsec) {
    if (!g_mem) return false;
    uint8_t* p = g_mem->Ptr(ptr);
    if (!p) return false;
    memcpy(p, &sec, 8);
    memcpy(p + 8, &nsec, 8);
    return true;
}

static bool GuestReadTimespec(uint64_t ptr, int64_t* sec, int64_t* nsec) {
    if (!g_mem) return false;
    const uint8_t* p = g_mem->Ptr(ptr);
    if (!p) return false;
    memcpy(sec, p, 8);
    memcpy(nsec, p + 8, 8);
    return true;
}

static bool GuestReadStr(uint64_t ptr, char* out, size_t cap) {
    if (!g_mem || cap == 0) return false;
    const uint8_t* p = g_mem->Ptr(ptr);
    if (!p) return false;
    size_t i = 0;
    while (i + 1 < cap) {
        const char c = (char)p[i];
        out[i] = c;
        if (c == 0) return true;
        if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E) { out[i] = 0; return true; }
        ++i;
    }
    out[i] = 0;
    return true;
}

// --- Диспетчер --------------------------------------------------------------
HleResult Execute(uint32_t num, const uint64_t args[8]) {
    const char* known = NameOf(num);
    if (!known) {
        const int n = ++g_unknown[num];
        if (n <= 20)
            printf("[HLE] #%-4u <НЕТ В ТАБЛИЦЕ> — заглушка, верну -78 (ENOSYS)\n",
                   (unsigned)num);
        return { HleStatus::Handled, -78, 0 };
    }

    switch (num) {
    case 1:   // sys_exit(status)
    case 652: // sys_process_terminate(status) — для честности считаем выходом
        LogCall(num, args, known);
        return { HleStatus::Exit, 0, (int)(int64_t)args[0] };

    case 3: { // sys_read(fd, buf, len)
        LogCall(num, args, known);
        const int64_t fd = (int64_t)args[0];
        uint64_t len = args[2];
        if (len > 0x100000) len = 0x100000;
        if (!g_mem) return { HleStatus::Handled, -14, 0 };
        uint8_t* p = g_mem->Ptr(args[1]);
        if (!p) return { HleStatus::Handled, -14, 0 };
        if (fd == 0) {                                  // stdin — консоль
            const size_t got = len ? fread(p, 1, (size_t)len, stdin) : 0;
            return { HleStatus::Handled, (int64_t)got, 0 };
        }
        const auto it = g_files.find((int)fd);
        if (it == g_files.end())
            return { HleStatus::Handled, -9, 0 };       // EBADF
        if (!len) return { HleStatus::Handled, 0, 0 };
        const intptr_t got = _read(it->second, p, (unsigned)len);
        if (got < 0) return { HleStatus::Handled, -5, 0 };   // EIO
        return { HleStatus::Handled, (int64_t)got, 0 };
    }

    case 4: { // sys_write(fd, buf, len)
        LogCall(num, args, known);
        const int64_t fd = (int64_t)args[0];
        uint64_t len = args[2];
        if (len > 0x100000) len = 0x100000;             // разумный потолок
        if (!g_mem) return { HleStatus::Handled, -14, 0 };
        const uint8_t* p = g_mem->Ptr(args[1]);
        if (!p) return { HleStatus::Handled, -14, 0 };  // EFAULT
        if (fd == 1 || fd == 2) {                       // консоль
            FILE* out = (fd == 2) ? stderr : stdout;
            if (len) fwrite(p, 1, (size_t)len, out);
            fflush(out);
            return { HleStatus::Handled, (int64_t)len, 0 };
        }
        const auto it = g_files.find((int)fd);
        if (it == g_files.end())
            return { HleStatus::Handled, -9, 0 };       // EBADF
        if (!len) return { HleStatus::Handled, 0, 0 };
        const intptr_t put = _write(it->second, p, (unsigned)len);
        if (put < 0) return { HleStatus::Handled, -5, 0 };   // EIO
        return { HleStatus::Handled, (int64_t)put, 0 };
    }

    case 5: { // sys_open(path, flags, mode)
        LogCall(num, args, known);
        char gp[512] = { 0 };
        if (!GuestReadStr(args[0], gp, sizeof(gp)) || !gp[0])
            return { HleStatus::Handled, -14, 0 };      // EFAULT
        std::wstring host;
        if (!MapPath(gp, &host)) {
            printf("[HLE]   open: \"%s\" -> путь не маппится (ENOENT)\n", gp);
            fflush(stdout);
            return { HleStatus::Handled, -2, 0 };
        }
        // Флаги FreeBSD: RDONLY=0/WRONLY=1/RDWR=2, APPEND=0x8, CREAT=0x200,
        // TRUNC=0x400, EXCL=0x800
        int hf = 0;
        switch (args[1] & 3) {
        case 0:  hf = _O_RDONLY; break;
        case 1:  hf = _O_WRONLY; break;
        case 2:  hf = _O_RDWR;   break;
        default: return { HleStatus::Handled, -22, 0 }; // доступ 3 — невалиден
        }
        if (args[1] & 0x008) hf |= _O_APPEND;
        if (args[1] & 0x200) hf |= _O_CREAT;
        if (args[1] & 0x400) hf |= _O_TRUNC;
        if (args[1] & 0x800) hf |= _O_EXCL;
        hf |= _O_BINARY;
        const int hfd = _wopen(host.c_str(), hf, (int)(_S_IREAD | _S_IWRITE));
        if (hfd < 0) {
            printf("[HLE]   open: \"%s\" -> файл не открылся (errno %d)\n",
                   gp, errno);
            fflush(stdout);
            return { HleStatus::Handled, -2, 0 };       // честный ENOENT
        }
        const int gfd = g_nextFd++;
        g_files[gfd] = hfd;
        printf("[HLE]   open: \"%s\" -> fd %d\n", gp, gfd);
        fflush(stdout);
        return { HleStatus::Handled, gfd, 0 };
    }

    case 6: { // sys_close(fd)
        LogCall(num, args, known);
        const int64_t fd = (int64_t)args[0];
        if (fd >= 0 && fd <= 2)
            return { HleStatus::Handled, 0, 0 };        // консоль не закрываем
        const auto it = g_files.find((int)fd);
        if (it == g_files.end())
            return { HleStatus::Handled, -9, 0 };
        _close(it->second);
        g_files.erase(it);
        return { HleStatus::Handled, 0, 0 };
    }

    case 477: { // sys_mmap(addr, len, prot, flags, fd, off)
        LogCall(num, args, known);
        if (!g_mem) return { HleStatus::Handled, -12, 0 };
        uint64_t len = args[1];
        if (len == 0 || len > 0x40000000ull)             // <= 1 ГБ за раз
            return { HleStatus::Handled, -22, 0 };
        uint32_t pf = 0;
        if (args[2] & 1) pf |= PF_R;
        if (args[2] & 2) pf |= PF_W;
        if (args[2] & 4) pf |= PF_X;
        if (!pf) pf = PF_R;
        const uint64_t addr = args[0];
        const uint64_t guest = addr ? g_mem->MapAnon(addr, len, pf)
                                    : g_mem->AllocGuest(len, pf);
        if (!guest) return { HleStatus::Handled, -12, 0 };
        return { HleStatus::Handled, (int64_t)guest, 0 };
    }

    case 73: { // sys_munmap(addr, len)
        LogCall(num, args, known);
        if (!g_mem) return { HleStatus::Handled, -12, 0 };
        return { HleStatus::Handled, g_mem->Unmap(args[0]) ? 0 : -22, 0 };
    }

    case 74: { // sys_mprotect(addr, len, prot)
        LogCall(num, args, known);
        if (!g_mem) return { HleStatus::Handled, -12, 0 };
        uint32_t pf = 0;
        if (args[2] & 1) pf |= PF_R;
        if (args[2] & 2) pf |= PF_W;
        if (args[2] & 4) pf |= PF_X;
        return { HleStatus::Handled, g_mem->ProtectRange(args[0], pf) ? 0 : -12, 0 };
    }

    case 232: { // sys_clock_gettime(clk_id, timespec*)
        LogCall(num, args, known);
        int64_t sec = 0, nsec = 0;
        if ((int64_t)args[0] == 0 || (int64_t)args[0] == 1) NowRealtime(&sec, &nsec);
        else NowMonotonic(&sec, &nsec);
        if (!GuestWriteTimespec(args[1], sec, nsec))
            return { HleStatus::Handled, -14, 0 };
        return { HleStatus::Handled, 0, 0 };
    }

    case 116: { // sys_gettimeofday(tv*, tz*)
        LogCall(num, args, known);
        int64_t sec = 0, nsec = 0;
        NowRealtime(&sec, &nsec);
        if (!g_mem) return { HleStatus::Handled, -14, 0 };
        uint8_t* p = g_mem->Ptr(args[0]);
        if (!p) return { HleStatus::Handled, -14, 0 };
        const int64_t usec = nsec / 1000;
        memcpy(p, &sec, 8);
        memcpy(p + 8, &usec, 8);
        return { HleStatus::Handled, 0, 0 };
    }

    case 240: { // sys_nanosleep(req, rem)
        LogCall(num, args, known);
        int64_t sec = 0, nsec = 0;
        if (!GuestReadTimespec(args[0], &sec, &nsec))
            return { HleStatus::Handled, -14, 0 };
        if (sec < 0) sec = 0;
        if (nsec < 0) nsec = 0;
        int64_t ms = sec * 1000 + nsec / 1000000;
        if (ms > 10000) ms = 10000;                       // не даём гостю заморозить нас
        Sleep((DWORD)ms);
        return { HleStatus::Handled, 0, 0 };
    }

    case 331:   // sys_sched_yield
        LogCall(num, args, known);
        SwitchToThread();
        return { HleStatus::Handled, 0, 0 };

    case 20:    // sys_getpid
        LogCall(num, args, known);
        return { HleStatus::Handled, 4242, 0 };

    case 39:    // sys_getppid
        LogCall(num, args, known);
        return { HleStatus::Handled, 1, 0 };

    case 24:    // sys_getuid
    case 25:    // sys_geteuid
        LogCall(num, args, known);
        return { HleStatus::Handled, 1000, 0 };

    case 432:   // sys_thr_self
        LogCall(num, args, known);
        return { HleStatus::Handled, (int64_t)exec::CurrentTid(), 0 };

    case 464: { // sys_thr_set_name(id, name)
        LogCall(num, args, known);
        char name[64];
        if (GuestReadStr(args[1], name, sizeof(name)) && name[0])
            printf("[HLE]   поток %llu зовётся \"%s\"\n",
                   (unsigned long long)args[0], name);
        return { HleStatus::Handled, 0, 0 };
    }

    case 430: { // sys_thr_create — FreeBSD x64:
                // (ctx, tid*, flags, stack, stacksize, start, arg[стек], tid2[стек])
        LogCall(num, args, known);
        const uint64_t start = args[5];
        if (!start)
            return { HleStatus::Handled, -22, 0 };
        uint64_t tid = 0;
        exec::SpawnThread(start, args[6], &tid);   // arg лежит на стеке гостя
        if (!tid)
            return { HleStatus::Handled, -12, 0 };
        if (args[1] && !GuestWriteU64(args[1], tid))
            return { HleStatus::Handled, -14, 0 };
        if (args[7] && !GuestWriteU64(args[7], tid))
            return { HleStatus::Handled, -14, 0 };
        printf("[HLE]   нить создана: tid=%llu, start=0x%llX, arg=0x%llX\n",
               (unsigned long long)tid, (unsigned long long)start,
               (unsigned long long)args[6]);
        fflush(stdout);
        return { HleStatus::Handled, 0, 0 };
    }

    case 431:   // sys_thr_exit(status) — завершить ТОЛЬКО текущую нить
        LogCall(num, args, known);
        return { HleStatus::ThreadExit, (int64_t)args[0], 0 };

    case 676:   // sys_cpumode_yield — гостевая подсказка планировщику
        LogCall(num, args, known);
        SwitchToThread();
        return { HleStatus::Handled, 0, 0 };

    case 326: { // sys___getcwd(buf, len) — честно: cwd гостя это /app0
        LogCall(num, args, known);
        if (!g_mem) return { HleStatus::Handled, -14, 0 };
        uint8_t* p = g_mem->Ptr(args[0]);
        if (!p) return { HleStatus::Handled, -14, 0 };
        const char cwd[] = "/app0";
        if (args[1] < sizeof(cwd))
            return { HleStatus::Handled, -22, 0 };      // ERANGE
        memcpy(p, cwd, sizeof(cwd));
        return { HleStatus::Handled, 0, 0 };
    }

    case 478: { // sys_lseek(fd, off, whence) — whence как в CRT: 0/1/2
        LogCall(num, args, known);
        const auto it = g_files.find((int)args[0]);
        if (it == g_files.end())
            return { HleStatus::Handled, -9, 0 };
        const __int64 off = _lseeki64(it->second, (__int64)args[1], (int)args[2]);
        if (off == -1)
            return { HleStatus::Handled, -29, 0 };      // ESPIPE
        return { HleStatus::Handled, (int64_t)off, 0 };
    }

    case 475: { // sys_pread(fd, buf, len, off)
        LogCall(num, args, known);
        const auto it = g_files.find((int)args[0]);
        if (it == g_files.end())
            return { HleStatus::Handled, -9, 0 };
        if (!g_mem) return { HleStatus::Handled, -14, 0 };
        uint8_t* p = g_mem->Ptr(args[1]);
        if (!p) return { HleStatus::Handled, -14, 0 };
        uint64_t len = args[2];
        if (len > 0x100000) len = 0x100000;
        const __int64 save = _lseeki64(it->second, 0, 1);      // SEEK_CUR
        _lseeki64(it->second, (__int64)args[3], 0);            // SEEK_SET
        const intptr_t got = len ? _read(it->second, p, (unsigned)len) : 0;
        if (save != -1) _lseeki64(it->second, save, 0);
        if (got < 0) return { HleStatus::Handled, -5, 0 };
        return { HleStatus::Handled, (int64_t)got, 0 };
    }

    case 189: { // sys_fstat(fd, stat*) — struct stat FreeBSD x64 (144 байта)
        LogCall(num, args, known);
        if (!g_mem) return { HleStatus::Handled, -14, 0 };
        const int64_t fd = (int64_t)args[0];
        if (fd >= 0 && fd <= 2) {                       // консоль = симв. устройство
            if (!GuestWriteStat(args[1], 0x2000 | 0644, 0))
                return { HleStatus::Handled, -14, 0 };
            return { HleStatus::Handled, 0, 0 };
        }
        const auto it = g_files.find((int)fd);
        if (it == g_files.end())
            return { HleStatus::Handled, -9, 0 };
        struct _stat64 st {};
        if (_fstat64(it->second, &st) != 0)
            return { HleStatus::Handled, -9, 0 };
        const bool isDir = (st.st_mode & _S_IFMT) == _S_IFDIR;
        const uint16_t mode = (uint16_t)((isDir ? 0x4000 : 0x8000) | 0644);
        if (!GuestWriteStat(args[1], mode, (uint64_t)st.st_size))
            return { HleStatus::Handled, -14, 0 };
        return { HleStatus::Handled, 0, 0 };
    }

    case 188: { // sys_stat(path, stat*)
        LogCall(num, args, known);
        char gp[512] = { 0 };
        if (!GuestReadStr(args[0], gp, sizeof(gp)) || !gp[0])
            return { HleStatus::Handled, -14, 0 };
        std::wstring host;
        if (!MapPath(gp, &host))
            return { HleStatus::Handled, -2, 0 };       // ENOENT
        struct _stat64 st {};
        if (_wstat64(host.c_str(), &st) != 0)
            return { HleStatus::Handled, -2, 0 };
        const bool isDir = (st.st_mode & _S_IFMT) == _S_IFDIR;
        const uint16_t mode = (uint16_t)((isDir ? 0x4000 : 0x8000) | 0644);
        if (!GuestWriteStat(args[1], mode, (uint64_t)st.st_size))
            return { HleStatus::Handled, -14, 0 };
        return { HleStatus::Handled, 0, 0 };
    }

    case 165: { // sys_sysarch(op, parms) — FreeBSD amd64: 0=GET_FSBASE, 1=SET_FSBASE,
                // 2=GET_GSBASE, 3=SET_GSBASE. Фаза 7.3: SET_FSBASE работаем честно.
        LogCall(num, args, known);
        if (args[0] == 1) {   // SET_FSBASE
            if (SetFsBase(args[1]))
                return { HleStatus::Handled, 0, 0 };
            printf("[HLE] sysarch(SET_FSBASE, 0x%llX): FSGSBASE недоступен — fs не меняем, "
                   "гость упадёт на первом fs-доступе (это диагностика)\n",
                   (unsigned long long)args[1]);
            return { HleStatus::Handled, 0, 0 };
        }
        if (args[0] == 3)     // SET_GSBASE: у x64 Windows gs занят TEB'ом
            printf("[HLE] sysarch(SET_GSBASE, 0x%llX): gs занят Windows — игнорируем честно\n",
                   (unsigned long long)args[1]);
        return { HleStatus::Handled, 0, 0 };
    }

    case 198: { // sys___syscall(number, arg1..) — косвенный вызов
        LogCall(num, args, known);
        const uint64_t shifted[8] = { args[1], args[2], args[3], args[4],
                                      args[5], args[6], args[7], 0 };
        return Execute((uint32_t)args[0], shifted);
    }

    default:    // известный номер, реализация позже — честная заглушка
        LogCall(num, args, known);
        printf("[HLE]   ^ заглушка: реальное поведение — фаза 5+\n");
        return { HleStatus::Handled, 0, 0 };
    }
}

void PrintRunSummary() {
    printf("[HLE] Итог прогона:\n");
    if (g_hits.empty() && g_unknown.empty()) {
        printf("[HLE]   syscall'ов не было\n");
        return;
    }
    int total = 0;
    for (const auto& kv : g_hits) {
        printf("[HLE]   #%-4u %-30s x%d\n", (unsigned)kv.first,
               NameOf(kv.first) ? NameOf(kv.first) : "?", kv.second);
        total += kv.second;
    }
    for (const auto& kv : g_unknown) {
        printf("[HLE]   #%-4u <нет в таблице>       x%d\n", (unsigned)kv.first, kv.second);
        total += kv.second;
    }
    printf("[HLE]   всего: %d вызовов\n", total);
}

void PrintSummary() {
    const std::vector<SyscallInfo>& t = Table();
    printf("[HLE] Таблица syscall'ов: %u записей (номера из psdevwiki /ps5/Syscalls)\n",
           (unsigned)t.size());
    const char* groups[] = { "fs", "mem", "proc", "thread", "time", "dynlib", "sig", "net", "ps5" };
    for (const char* g : groups) {
        int n = 0;
        for (const SyscallInfo& s : t)
            if (strcmp(g, s.group) == 0) ++n;
        printf("[HLE]   %-7s %d\n", g, n);
    }
}

} } // namespace zrx::hle
