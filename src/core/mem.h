// ============================================================================
// ZerpexPS5 — ядро: память эмулируемого процесса
// Простое адресное пространство на VirtualAlloc: сегменты PT_LOAD ложатся
// на свои vaddr; если адрес занят Windows'ом — честно переносим и пишем в лог.
//
// Фаза 3: добавлены анонимные регионы (sys_mmap), обратная трансляция
// host→guest (для VEH-перехвата) и снятие регионов (sys_munmap).
// ============================================================================
#pragma once

#include <cstdint>
#include <vector>

namespace zrx {

struct MemSegment {
    uint64_t vaddr = 0;      // адрес из ELF/запроса mmap
    uint64_t memsz = 0;
    uint64_t actual = 0;     // реальный базовый адрес сегмента
    uint32_t protFlags = 0;  // PF_R/PF_W/PF_X
    bool     relocated = false; // true — Windows не дал сесть на vaddr
    uint64_t allocBase = 0;  // база VirtualAlloc-региона
    uint64_t allocSize = 0;  // размер региона
};

class Memory {
public:
    // Кладёт сегмент: копирует filesz байт (остальное — нули, .bss),
    // ставит защиту по флагам. Возвращает реальный адрес vaddr или 0 при ошибке.
    uint64_t Map(uint64_t vaddr, const uint8_t* data, uint64_t filesz,
                 uint64_t memsz, uint32_t protFlags);

    // Анонимная память без содержимого (sys_mmap). vaddr==0 запрещён —
    // для «где угодно» используй AllocGuest.
    uint64_t MapAnon(uint64_t vaddr, uint64_t size, uint32_t protFlags);

    // sys_mmap(addr=0): подбираем свободный гостевой адрес сами.
    // Гостевые mmap растут от 0x0000700000000000 — там Windows ничего не даёт.
    uint64_t AllocGuest(uint64_t size, uint32_t protFlags);

    // sys_munmap: снимает ЦЕЛЫЙ регион аллока, содержащий vaddr.
    bool Unmap(uint64_t vaddr);

    // sys_mprotect: защита на весь регион аллока, содержащий vaddr.
    bool ProtectRange(uint64_t vaddr, uint32_t protFlags);

    // vaddr → реальный адрес (0 = не мапнуто)
    uint64_t Translate(uint64_t vaddr) const;
    uint8_t* Ptr(uint64_t vaddr) const;

    // host-адрес → гостевой vaddr (для VEH: RIP/указатели внутри гостя)
    bool GuestForHost(uint64_t host, uint64_t* guestOut) const;

    const std::vector<MemSegment>& Segments() const { return segs_; }

private:
    // Общий аллокатор региона. Возвращает базу региона или 0.
    uint64_t AllocRegion(uint64_t alignedBase, uint64_t size, MemSegment* out);
    std::vector<MemSegment> segs_;
    uint64_t nextGuest_ = 0x0000700000000000ull;
};

} // namespace zrx
