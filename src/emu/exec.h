// ============================================================================
// ZerpexPS5 — фаза 4: нативное исполнение гостевого кода (теперь с потоками)
//
// Трюк, на котором всё стоит:
//   1. Код PS5 — x86-64, как у нас. Запускаем его НАТИВНО.
//   2. Инструкцию syscall (0F 05) патчим на UD2 (0F 0B) прямо в памяти.
//      Длина совпадает (2 байта) — RIP достаточно сдвинуть на 2.
//   3. VEH-обработчик ловит EXCEPTION_ILLEGAL_INSTRUCTION по адресу патча,
//      читает rax (номер) и rdi,rsi,rdx,r10,r8,r9 (аргументы, FreeBSD x64),
//      диспетчит в HLE, кладёт ответ в rax и продолжает.
//
// Новое в фазе 4:
//   - состояние перехвата на ПОТОК (__thread): гость может быть многопоточным;
//   - sys_thr_create -> SpawnThread: нить Windows (_beginthreadex, стек 4 МБ)
//     вызывает гостевую функцию start(arg) с честным SysV-вызовом;
//   - sys_thr_exit завершает только нить; sys_exit из нити — весь процесс
//     (семантика FreeBSD, честно);
//   - диагностические импорт-заглушки (dyn.h) ловятся VEH'ом: имя символа в
//     лог, гостю 0;
//   - VEH живёт ВЕСЬ ПРОЦЕСС и патчи НЕ восстанавливаются после Run:
//     рабочие нити гостя продолжают работать.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>

#include "../core/mem.h"

namespace zrx {
namespace exec {

struct RunResult {
    bool        started = false;  // удалось передать управление entry
    bool        exited  = false;  // гость завершился сам (ret или sys_exit)
    int         exitCode = 0;     // код sys_exit / thr_exit
    std::string status;           // человекочитаемый итог (честный)
};

// Патчит syscall'ы, ставит VEH, передаёт управление entry и разбирает результат.
RunResult Run(Memory& mem, uint64_t entryVaddr);

// Создать гостевой поток (sys_thr_create): нить Windows исполняет
// start(arg) по гостевому vaddr. Возвращает гостевой tid или 0 при ошибке.
uint64_t SpawnThread(uint64_t entryVaddr, uint64_t arg, uint64_t* tidOut);

// tid текущего гостевого потока (0 = не в госте, 1 = главный поток)
uint64_t CurrentTid();

} } // namespace zrx::exec
