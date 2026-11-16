// ============================================================================
// ZerpexPS5 — ядро: парсер ELF64 и SELF-контейнера PS5 (только метаданные)
//
// Фаза 2. Никакой криптографии: читаем заголовки и таблицы, которые лежат
// в файле открыто. Для SELF это законно: заголовок и таблица сегментов
// не зашифрованы (проверено на дампе Dead Cells), зашифрованы только данные.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace zrx {

// ---- ELF64: константы (самодостаточно, без системных хедеров) ----
enum : uint32_t {
    PT_NULL = 0, PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_NOTE = 4,
    PT_SHLIB = 5, PT_PHDR = 6, PT_TLS = 7,
};
enum : uint32_t {
    PF_X = 1, PF_W = 2, PF_R = 4,
};

struct ElfSegment {
    uint32_t type = 0;
    uint32_t flags = 0;
    uint64_t offset = 0;
    uint64_t vaddr = 0;
    uint64_t paddr = 0;
    uint64_t filesz = 0;
    uint64_t memsz = 0;
    uint64_t align = 0;
};

struct ElfImage {
    bool ok = false;
    std::string error;

    uint8_t  eiOsabi = 0;
    uint16_t type = 0;      // e_type (2=EXEC, 3=DYN, 0xFE10=SCE exec...)
    uint16_t machine = 0;   // 62 = x86-64
    uint64_t entry = 0;
    uint32_t flagsWord = 0;
    uint16_t phnum = 0;
    uint16_t shnum = 0;

    std::vector<ElfSegment>  phdrs;
    std::vector<size_t>      loadIdx;   // индексы PT_LOAD в phdrs
    std::vector<std::string> needed;    // DT_NEEDED (если удалось резолвнуть)
    std::vector<std::string> dynNotes;  // прочее из PT_DYNAMIC для отчёта
};

bool ParseElf(const uint8_t* data, size_t size, ElfImage* out);

const char* ElfTypeName(uint16_t t);
const char* MachineName(uint16_t m);
std::string ProtStr(uint32_t flags);      // "R-X"

// ---- SELF: контейнер PS5 (наблюдаемый формат, по гексдампам наших файлов) ----
// 0x00: u32 magic 0xEEF51454 (байты 54 14 F5 EE)
// 0x04: 3 u32-константы (одинаковые во всех наших дампах)
// 0x10: u64 размер файла
// 0x18: u16 число сегментов, u16 константа 0x32
// 0x20: таблица сегментов: N x { u64 flags, u64 offset, u64 storeSize, u64 memSize }
// далее: вложенный ELF-заголовок (открытый, с program headers)
enum : uint32_t { SELF_MAGIC_PS5 = 0xEEF51454u };

struct SelfSegment {
    uint64_t flags = 0;
    uint64_t offset = 0;      // смещение данных в SELF-файле
    uint64_t storeSize = 0;   // размер в файле
    uint64_t memSize = 0;     // размер в памяти (== storeSize у наших дампов)
};

struct SelfImage {
    bool ok = false;
    std::string error;

    uint32_t magic = 0;
    uint32_t word04 = 0, word08 = 0, word0C = 0;
    uint64_t fileSize = 0;    // заявленный размер
    uint16_t segCount = 0;
    uint16_t headerWord = 0;  // константа 0x32 в наших дампах
    std::vector<SelfSegment> segments;

    bool     hasElf = false;  // вложенный ELF найден и разобран
    uint64_t elfOffset = 0;   // смещение вложенного ELF в файле
    ElfImage elf;             // его заголовок + program headers (открыты!)
};

bool ParseSelf(const uint8_t* data, size_t size, SelfImage* out);

} // namespace zrx
