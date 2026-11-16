// ============================================================================
// ZerpexPS5 — ядро: разбор ELF64 / SELF PS5 (метаданные, без криптографии)
// ============================================================================
#include "elf.h"

#include <cstdio>
#include <cstring>

namespace zrx {

#pragma pack(push, 1)
struct EhdrRaw {
    uint8_t  ident[16];
    uint16_t type;
    uint16_t machine;
    uint32_t version;
    uint64_t entry;
    uint64_t phoff;
    uint64_t shoff;
    uint32_t flags;
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
};
struct PhdrRaw {
    uint32_t type;
    uint32_t flags;
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
};
struct DynRaw { uint64_t tag, val; };
#pragma pack(pop)

const char* ElfTypeName(uint16_t t) {
    switch (t) {
    case 0:     return "ET_NONE";
    case 1:     return "ET_REL";
    case 2:     return "ET_EXEC";
    case 3:     return "ET_DYN";
    case 4:     return "ET_CORE";
    case 0xFE10: return "SCE_EXEC";
    case 0xFE18: return "SCE_DYNAMIC";
    default:    return "ET_?";
    }
}

const char* MachineName(uint16_t m) {
    switch (m) {
    case 62:  return "x86-64";
    case 3:   return "x86";
    case 183: return "AArch64";
    default:  return "?";
    }
}

std::string ProtStr(uint32_t flags) {
    std::string s = "---";
    if (flags & PF_R) s[0] = 'R';
    if (flags & PF_W) s[1] = 'W';
    if (flags & PF_X) s[2] = 'X';
    return s;
}

// Читает C-строку из буфера с ограничением. Возвращает "" при выходе за край.
static std::string ReadCStr(const uint8_t* data, size_t maxLen) {
    std::string s;
    for (size_t i = 0; i < maxLen && data[i]; ++i) {
        const char c = (char)data[i];
        if (c < 0x20 || c > 0x7E) return std::string(); // мусор — не строка
        s += c;
    }
    return s;
}

static bool InRange(uint64_t off, uint64_t len, uint64_t size) {
    return off <= size && len <= size - off;
}

bool ParseElf(const uint8_t* data, size_t size, ElfImage* out) {
    if (!out) return false;
    *out = ElfImage{};
    if (!data || size < sizeof(EhdrRaw)) { out->error = "файл слишком мал для ELF-заголовка"; return false; }
    if (memcmp(data, "\x7F""ELF", 4) != 0) { out->error = "нет ELF-магии"; return false; }
    if (data[4] != 2) { out->error = "не ELF64 (EI_CLASS != 2)"; return false; }
    if (data[5] != 1) { out->error = "не little-endian (EI_DATA != 1)"; return false; }

    EhdrRaw h;
    memcpy(&h, data, sizeof(h));
    out->eiOsabi  = data[7];
    out->type     = h.type;
    out->machine  = h.machine;
    out->entry    = h.entry;
    out->flagsWord = h.flags;
    out->phnum    = h.phnum;
    out->shnum    = h.shnum;

    if (h.phentsize != sizeof(PhdrRaw)) {
        char buf[128];
        snprintf(buf, sizeof(buf), "неожиданный e_phentsize=%u (ожидал %u)",
                 (unsigned)h.phentsize, (unsigned)sizeof(PhdrRaw));
        out->error = buf;
        return false;
    }
    if (!InRange(h.phoff, (uint64_t)h.phnum * sizeof(PhdrRaw), size)) {
        out->error = "таблица program headers вне файла";
        return false;
    }

    for (uint16_t i = 0; i < h.phnum; ++i) {
        PhdrRaw p;
        memcpy(&p, data + h.phoff + (size_t)i * sizeof(PhdrRaw), sizeof(p));
        ElfSegment s;
        s.type = p.type; s.flags = p.flags;
        s.offset = p.offset; s.vaddr = p.vaddr; s.paddr = p.paddr;
        s.filesz = p.filesz; s.memsz = p.memsz; s.align = p.align;
        out->phdrs.push_back(s);
        if (p.type == PT_LOAD) out->loadIdx.push_back(i);
    }

    // PT_DYNAMIC: зависимости (DT_NEEDED) и заметки
    for (size_t i = 0; i < out->phdrs.size(); ++i) {
        const ElfSegment& d = out->phdrs[i];
        if (d.type != PT_DYNAMIC || !InRange(d.offset, d.filesz, size))
            continue;
        const size_t maxEntries = (size_t)(d.filesz / sizeof(DynRaw));
        uint64_t strtabV = 0;
        std::vector<uint64_t> needOffs;
        for (size_t k = 0; k < maxEntries; ++k) {
            DynRaw e;
            memcpy(&e, data + d.offset + k * sizeof(DynRaw), sizeof(e));
            if (e.tag == 0) break; // DT_NULL
            if (e.tag == 1) needOffs.push_back(e.val);      // DT_NEEDED
            if (e.tag == 5) strtabV = e.val;                // DT_STRTAB
        }
        // Резолв строк: ищем PT_LOAD, покрывающий strtab по vaddr
        const ElfSegment* strSeg = nullptr;
        for (const ElfSegment& s : out->phdrs) {
            if (s.type != PT_LOAD || strtabV < s.vaddr) continue;
            if (strtabV - s.vaddr < s.filesz) { strSeg = &s; break; }
        }
        if (strSeg && !needOffs.empty()) {
            const uint8_t* strBase = data + strSeg->offset + (strtabV - strSeg->vaddr);
            const uint64_t strAvail = strSeg->filesz - (strtabV - strSeg->vaddr);
            for (uint64_t off : needOffs) {
                if (off >= strAvail) continue; // кривое смещение — не читаем за край
                const uint64_t avail = strAvail - off;
                std::string name = ReadCStr(strBase + off, avail < 512 ? avail : 512);
                if (!name.empty()) out->needed.push_back(name);
            }
        } else if (!needOffs.empty()) {
            char buf[128];
            snprintf(buf, sizeof(buf),
                     "DT_NEEDED x%u есть, но DT_STRTAB=0x%llX не лежит в PT_LOAD — строки не резолвим",
                     (unsigned)needOffs.size(), (unsigned long long)strtabV);
            out->dynNotes.push_back(buf);
        }
        break; // динамических таблиц обычно одна
    }

    out->ok = true;
    return true;
}

bool ParseSelf(const uint8_t* data, size_t size, SelfImage* out) {
    if (!out) return false;
    *out = SelfImage{};
    if (!data || size < 0x20) { out->error = "файл слишком мал для SELF-заголовка"; return false; }

    uint32_t magic = 0;
    memcpy(&magic, data, 4);
    if (magic != SELF_MAGIC_PS5) { out->error = "нет магии SELF PS5 (54 14 F5 EE)"; return false; }
    out->magic = magic;

    memcpy(&out->word04, data + 0x04, 4);
    memcpy(&out->word08, data + 0x08, 4);
    memcpy(&out->word0C, data + 0x0C, 4);
    memcpy(&out->fileSize, data + 0x10, 8);
    memcpy(&out->segCount, data + 0x18, 2);
    memcpy(&out->headerWord, data + 0x1A, 2);

    if (out->segCount == 0 || out->segCount > 64) {
        char buf[128];
        snprintf(buf, sizeof(buf), "подозрительное число сегментов: %u", (unsigned)out->segCount);
        out->error = buf;
        return false;
    }

    const size_t tableOff = 0x20;
    const size_t tableSize = (size_t)out->segCount * 32;
    if (!InRange(tableOff, tableSize, size)) { out->error = "таблица сегментов вне файла"; return false; }

    for (uint16_t i = 0; i < out->segCount; ++i) {
        const uint8_t* p = data + tableOff + (size_t)i * 32;
        SelfSegment s;
        memcpy(&s.flags,     p,      8);
        memcpy(&s.offset,    p + 8,  8);
        memcpy(&s.storeSize, p + 16, 8);
        memcpy(&s.memSize,   p + 24, 8);
        out->segments.push_back(s);
    }

    // Вложенный ELF: сразу после таблицы сегментов
    const uint64_t elfOff = tableOff + tableSize;
    if (InRange(elfOff, 16, size) && memcmp(data + elfOff, "\x7F""ELF", 4) == 0) {
        out->elfOffset = elfOff;
        out->hasElf = ParseElf(data + elfOff, size - (size_t)elfOff, &out->elf);
        if (!out->hasElf)
            out->error = "вложенный ELF не разобрался: " + out->elf.error;
    }
    out->ok = true;
    return true;
}

} // namespace zrx
