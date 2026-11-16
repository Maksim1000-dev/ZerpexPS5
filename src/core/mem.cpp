// ============================================================================
// ZerpexPS5 — ядро: память (реализация на VirtualAlloc)
//
// ВАЖНО (фаза 3): исполняемые сегменты мапятся RWX, а не R-X — мы ПАТЧИМ
// инструкции syscall (0F 05) на UD2 прямо в памяти, чтобы ловить их VEH'ом.
// Это честная плата за нативное исполнение; W^X-переключение — позже.
// ============================================================================
#include "mem.h"
#include "elf.h"   // PF_R/PF_W/PF_X

#include <windows.h>
#include <algorithm>
#include <cstring>

namespace zrx {

static DWORD ProtFromFlags(uint32_t f) {
    const bool r = (f & PF_R) != 0;
    const bool w = (f & PF_W) != 0;
    const bool x = (f & PF_X) != 0;
    if (x) return PAGE_EXECUTE_READWRITE;   // патчим syscall на месте (см. шапку)
    if (w) return PAGE_READWRITE;
    if (r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

uint64_t Memory::AllocRegion(uint64_t alignedBase, uint64_t size, MemSegment* out) {
    const size_t regionSize = (size_t)size;
    LPVOID p = VirtualAlloc((LPVOID)(uintptr_t)alignedBase, regionSize,
                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    bool relocated = false;
    if (!p) {
        p = VirtualAlloc(nullptr, regionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!p) return 0;
        relocated = true;
    }
    out->allocBase = (uint64_t)(uintptr_t)p;
    out->allocSize = size;
    out->relocated = relocated || ((uint64_t)(uintptr_t)p != alignedBase);
    return out->allocBase;
}

uint64_t Memory::Map(uint64_t vaddr, const uint8_t* data, uint64_t filesz,
                     uint64_t memsz, uint32_t protFlags) {
    if (memsz == 0) {
        MemSegment s;
        s.vaddr = vaddr; s.memsz = 0; s.actual = vaddr; s.protFlags = protFlags;
        segs_.push_back(s);
        return vaddr;
    }

    const uint64_t page = 0x1000;
    const uint64_t base = vaddr & ~(page - 1);
    const uint64_t end  = (vaddr + memsz + page - 1) & ~(page - 1);

    MemSegment s;
    s.vaddr = vaddr;
    s.memsz = memsz;
    s.protFlags = protFlags;

    // VirtualAlloc округляет базу ВНИЗ до гранулы 64 КБ: резервируем от
    // округлённой базы весь диапазон, иначе хвост остался бы незакоммиченным.
    const uint64_t gran   = 0x10000;              // гранула выделения Windows
    const uint64_t vkBase = base & ~(gran - 1);
    const uint64_t vkSize = end - vkBase;
    if (!AllocRegion(vkBase, vkSize, &s)) return 0;

    // Хост-адрес гостевого vaddr считается от ФАКТИЧЕСКОЙ базы региона —
    // раньше брали vaddr-base и при округлении вниз получали сдвиг на гранулу.
    const uint64_t offInRegion = vaddr - s.allocBase;
    s.actual = s.allocBase + offInRegion;

    if (data && filesz)
        memcpy((void*)(uintptr_t)(s.allocBase + offInRegion), data, (size_t)filesz);
    // хвост (memsz - filesz) остаётся нулевым — VirtualAlloc даёт нулевые страницы

    DWORD old = 0;
    VirtualProtect((LPVOID)(uintptr_t)s.allocBase, (size_t)s.allocSize,
                   ProtFromFlags(protFlags), &old);

    segs_.push_back(s);
    return s.actual;
}

uint64_t Memory::MapAnon(uint64_t vaddr, uint64_t size, uint32_t protFlags) {
    if (size == 0) return 0;
    const uint64_t page = 0x1000;
    const uint64_t aligned = (size + page - 1) & ~(page - 1);

    MemSegment s;
    s.vaddr = vaddr;
    s.memsz = aligned;
    s.protFlags = protFlags;

    // см. Map(): Windows округляет базу вниз до 64 КБ — резервируем от
    // округлённой базы весь диапазон, чтобы хвост не остался без памяти.
    const uint64_t gran    = 0x10000;                     // гранула Windows
    const uint64_t reqBase = vaddr & ~(page - 1);
    const uint64_t vkBase  = reqBase & ~(gran - 1);
    const uint64_t vkSize  = (reqBase + aligned) - vkBase;
    if (!AllocRegion(vkBase, vkSize, &s)) return 0;

    // Идентичность (гость пишет нативно по vaddr): если регион лёг ровно на
    // vkBase, хост-адрес vaddr == vaddr. При переносе считаем оффсет внутри
    // фактического региона; AllocGuest выбирает базы так, чтобы этого
    // не случалось.
    s.actual = s.relocated ? (s.allocBase + (vaddr - vkBase)) : vaddr;

    DWORD old = 0;
    VirtualProtect((LPVOID)(uintptr_t)s.allocBase, (size_t)s.allocSize,
                   ProtFromFlags(protFlags), &old);

    segs_.push_back(s);
    return s.vaddr;
}

uint64_t Memory::AllocGuest(uint64_t size, uint32_t protFlags) {
    const uint64_t page = 0x1000;
    const uint64_t gran  = 0x10000;    // гранула VirtualAlloc: кратность базы
    const uint64_t aligned = (size + page - 1) & ~(page - 1);
    for (int attempt = 0; attempt < 16; ++attempt) {
        // База кратна 64 КБ — иначе VirtualAlloc молча округлит её вниз и
        // регион наедет на соседний (зазор в страницу это не спасал).
        const uint64_t guest = nextGuest_;
        nextGuest_ = (guest + aligned + gran - 1) & ~(gran - 1);
        if (MapAnon(guest, aligned, protFlags)) return guest;
    }
    return 0;
}

bool Memory::Unmap(uint64_t vaddr) {
    const MemSegment* hit = nullptr;
    for (const MemSegment& s : segs_) {
        if (vaddr >= s.vaddr && vaddr < s.vaddr + s.memsz) { hit = &s; break; }
    }
    if (!hit || !hit->allocBase) return false;
    const uint64_t allocBase = hit->allocBase;
    VirtualFree((LPVOID)(uintptr_t)allocBase, 0, MEM_RELEASE);
    segs_.erase(std::remove_if(segs_.begin(), segs_.end(),
                 [allocBase](const MemSegment& s) { return s.allocBase == allocBase; }),
                segs_.end());
    return true;
}

bool Memory::ProtectRange(uint64_t vaddr, uint32_t protFlags) {
    for (const MemSegment& s : segs_) {
        if (vaddr >= s.vaddr && vaddr < s.vaddr + s.memsz) {
            if (!s.allocBase) return false;
            DWORD old = 0;
            return VirtualProtect((LPVOID)(uintptr_t)s.allocBase,
                                  (size_t)s.allocSize, ProtFromFlags(protFlags), &old) != 0;
        }
    }
    return false;
}

uint64_t Memory::Translate(uint64_t vaddr) const {
    for (const MemSegment& s : segs_) {
        if (vaddr >= s.vaddr && vaddr < s.vaddr + s.memsz)
            return s.actual + (vaddr - s.vaddr);
    }
    return 0;
}

uint8_t* Memory::Ptr(uint64_t vaddr) const {
    const uint64_t a = Translate(vaddr);
    return a ? (uint8_t*)(uintptr_t)a : nullptr;
}

bool Memory::GuestForHost(uint64_t host, uint64_t* guestOut) const {
    for (const MemSegment& s : segs_) {
        if (host >= s.actual && host < s.actual + s.memsz) {
            if (guestOut) *guestOut = s.vaddr + (host - s.actual);
            return true;
        }
    }
    return false;
}

} // namespace zrx
