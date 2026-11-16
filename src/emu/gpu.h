// ============================================================================
// ZerpexPS5 — фаза 5: GPU HLE (видеовыход + GNM)
//
// На PS5 sceVideoOut*/sceGnm* — НЕ syscall'ы, а импорты модулей
// (libSceVideoOut.prx, libSceGnm.prx). Доносятся они через импорт-заглушки
// (dyn.cpp): call [GOT] -> "mov eax,idx; ud2; ret" -> VEH -> сюда.
//
// Фаза 5.0 "первый пиксель": гость сам рисует кадр в своей памяти,
// мы регистрируем буферы (sceVideoOutRegisterBuffers), копируем их
// в staging -> оффскрин -> свапчейн и презентуем (sceVideoOutSubmitFlip).
// Vulkan-слой живёт в gpu_vk.cpp (интерфейс gpu_vk.h).
//
// ЧЕГО НЕТ (честно): PM4-команды, шейдеры, растеризация — фаза 5.1+.
//   sceGnmSubmitCommandBuffers логируется (разведка) и возвращает 0.
// ============================================================================
#pragma once

#include <cstdint>

#include "../core/mem.h"

namespace zrx {
namespace gpu {

// Связывает GPU-слой с памятью гостя (читаем буферы/атрибуты по vaddr)
void AttachMemory(Memory* mem);

// Импорт относится к GPU-модулям (sceVideoOut*, sceGnm*)?
bool Handles(const char* name);

// Вызов импорта: args[0..5] = rdi,rsi,rdx,r10,r8,r9;
//                args[6..7] = хвост аргументов со стека гостя (rsp+8/16).
// Возвращает значение для rax гостя.
int64_t Execute(const char* name, const uint64_t args[8]);

// Сводка после прогона (печать в консоль)
void PrintRunSummary();

// Полная уборка Vulkan-объектов и окна (после PrintRunSummary)
void Shutdown();

} } // namespace zrx::gpu
