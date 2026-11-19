// ============================================================================
// ZerpexPS5 — ядро: HLE системных вызовов
//
// Номера syscall'ов — из таблицы PS5 на psdevwiki (страница /ps5/Syscalls).
// Конвенция вызова (FreeBSD x64, как у PS4/PS5):
//   rax = номер, аргументы: rdi, rsi, rdx, r10, r8, r9
//
// Фаза 3: ЧАСТЬ syscall'ов реально работает (stdout, mmap, время, сон...),
// остальные — логирующие заглушки с честной пометкой, что реализовать позже.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "mem.h"

namespace zrx {
namespace hle {

struct SyscallInfo {
    uint32_t    num;
    const char* name;
    const char* group;   // fs / mem / proc / thread / time / dynlib / sig / net / ps5
};

// Полная курируемая таблица (номера проверены по вики)
const std::vector<SyscallInfo>& Table();

// --- Диспетчер исполнения (фаза 3, расширена в фазе 4) -----------------------

enum class HleStatus { Handled, Unknown, Exit, ThreadExit };

struct HleResult {
    HleStatus status;
    int64_t   ret;        // значение для RAX гостя
    int       exitCode;   // осмысленно при status == Exit
};

// Связывает диспетчер с памятью эмулируемого процесса (нужно для буферов).
void AttachMemory(Memory* mem);

// Корень игры (папка дампа): /app0 и /data маппятся сюда (фаза 4).
// Пусто = не задан, файлы гостя тогда не открываются (честный ENOENT).
void SetGameRoot(const std::wstring& root);

// [7.8] Тот же маппинг путей, что у syscalls: нужен HLE stdio (fopen и т.п.),
// которые гость зовёт как импорты libc, а не через syscall.
bool MapGuestPath(const char* guest, std::wstring* out);

// Выполнить syscall:
//   args[0..5] = rdi, rsi, rdx, r10, r8, r9  (FreeBSD x64)
//   args[6..7] = хвост аргументов со стека гостя (rsp+8, rsp+16)
HleResult Execute(uint32_t num, const uint64_t args[8]);

// --- Фаза 7.3: база TLS (fs) для гостя ----------------------------------------
// x64 Windows держит TEB в gs, fs у нас свободна — гость (FreeBSD ABI) кладёт
// туда свой TCB. Доступно только при FSGSBASE (CPU умеет И ОС включила CR4 —
// проверяем фактической записью под SEH, без неё wrfsbase = #UD).
bool FsBaseAvailable();          // один раз детектится, дальше кэш
bool SetFsBase(uint64_t v);      // false = недоступно (fs не меняем, честно)
void SetFsBaseSupported(bool ok); // результат VEH-теста из exec (DetectFsBase)

// Сводка после прогона: сколько каких вызовов было, что неизвестно.
void PrintRunSummary();

// Короткая сводка таблицы (для отчёта фазы 2)
void PrintSummary();

} } // namespace zrx::hle
