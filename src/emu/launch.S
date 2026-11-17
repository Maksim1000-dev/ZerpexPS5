# =============================================================================
# ZerpexPS5 — фаза 7.7: трамплин запуска гостя БЕЗ longjmp.
#
# Зачем: гость исполняется нативно, его кадры на хост-стеке не имеют
# SEH-метаданных, и longjmp через них ронял процесс в ntdll с 0xC00000FF
# (WER: прогоны 19:00 / 19:14 / 21:44 2026-11-17; парный код 0xC0000028 был
# у офлайн-теста tools/veh_bail_test.cpp).
#
# Схема аварийного выхода:
#   GuestLaunch спилит callee-saved (блок 8*8 байт) и запомнит его адрес
#   в t_bailPtr (BailSaveBlock). VEH при краше в госте ПОДМЕНЯЕТ контекст:
#     rip = ret-адрес в Run/ThreadProc (блок+64)
#     rsp = блок+72        (ret-адрес "съеден", rsp кратен 16)
#     rax = код выхода (JMPL_*), callee-saved восстановлены из блока
#   и возвращает EXCEPTION_CONTINUE_EXECUTION — диспетчер завершается
#   штатно (NtContinue), раскрутка по гостевым кадрам не выполняется ВОВСЕ.
#
# GuestLaunch(entry, a1, a2) — Windows x64 ABI (rcx, rdx, r8), возврат rax:
#   0  — гость вернулся через ret (нормально);
#   JMPL_EXIT (777) / JMPL_THREAD_EXIT (888) / JMPL_FAULT (-1) — через VEH.
# Гостю вызов уходит в SysV ABI: rdi=a1, rsi=a2.
# =============================================================================
    .intel_syntax noprefix
    .text
    .globl GuestLaunch
GuestLaunch:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15                      # блок спила: [rsp]=r15 ... [rsp+56]=rbx
    sub  rsp, 0x38                # 0x20 shadow + слоты entry/a1/a2
    mov  [rsp+0x20], rcx          # entry
    mov  [rsp+0x28], rdx          # a1
    mov  [rsp+0x30], r8           # a2
    lea  rcx, [rsp+0x38]          # адрес спил-блока
    call BailSaveBlock            # t_bailPtr = блок (C++, thread-local)
    mov  rdi, [rsp+0x28]          # SysV: a1
    mov  rsi, [rsp+0x30]          # SysV: a2
    call qword ptr [rsp+0x20]     # ГОСТЬ
    add  rsp, 0x38
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    xor  eax, eax                 # нормальный возврат гостя
    ret
