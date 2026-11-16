// ============================================================================
// ZerpexPS5 — фаза 4: динамические релокации ELF (реализация)
//
// Читаем PT_DYNAMIC уже мапнутого образа: сегменты лежат по своим vaddr,
// база = 0, поэтому адрес символа S = st_value напрямую.
//
// Поддержанные типы RELA (x86-64):
//   R_X86_64_RELATIVE(8)   -> *P = A              (самонастройка PIC)
//   R_X86_64_IRELATIVE(37) -> *P = A              (резолвера нет — честно)
//   R_X86_64_64(1)         -> *P = S + A
//   R_X86_64_GLOB_DAT(6)   -> *P = S + A
//   R_X86_64_JUMP_SLOT(7)  -> *P = S + A (PLT)
//
// Символ не определён в образе (импорт)? В слот кладём адрес ДИАГНОСТИЧЕСКОЙ
// ЗАГЛУШКИ: mov eax, idx; ud2. Вызов такой функции ловит VEH, печатает имя
// символа и возвращает гостю 0 — вместо молчаливого краша.
//
// Запись в страницы с защитой R-X поднимается временно (VirtualProtect).
// ============================================================================
#include "dyn.h"

#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include <windows.h>

namespace zrx {
namespace dyn {

// --- Константы динамики/релокаций ELF64 (самодостаточно) ---
enum : uint64_t {
    DT_PLTRELSZ = 2, DT_HASH = 4, DT_STRTAB = 5, DT_SYMTAB = 6, DT_RELA = 7,
    DT_RELASZ = 8, DT_RELAENT = 9, DT_STRSZ = 10, DT_SYMENT = 11,
    DT_JMPREL = 23,
};
enum : uint64_t {
    R_X86_64_64 = 1, R_X86_64_GLOB_DAT = 6, R_X86_64_JUMP_SLOT = 7,
    R_X86_64_RELATIVE = 8, R_X86_64_IRELATIVE = 37,
};

struct Sym64 {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

struct Rela64 {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

static Memory* g_mem = nullptr;

void AttachMemory(Memory* mem) { g_mem = mem; }

// --- Реестр заглушек --------------------------------------------------------
static const uint64_t kStubPageSize = 0x10000;   // 64 КБ на страницу
static const uint64_t kStubSlotSize = 8;         // слот: mov eax,idx; ud2; ret
static const uint64_t kStubMaxSlots = kStubPageSize / kStubSlotSize;

static uint64_t g_pageBase = 0;                  // гостевой адрес страницы
static uint64_t g_pageUsed = 0;                  // занятых слотов

static std::vector<uint64_t>    g_slotAddr;      // адрес слота каждого импорта
static std::unordered_map<uint64_t, size_t> g_slotByAddr;   // слот -> индекс
static std::map<std::string, size_t> g_nameToSlot;          // дедуп по имени
static std::vector<std::string> g_names;                    // владеем строками
// ВАЖНО: имя всегда берём из g_names на месте (c_str()), а не кэшируем
// указатель: короткие (SSO) строки живут ВНУТРИ объекта std::string, и при
// росте вектора объект переезжает — кэшированный указатель повисает
// (баг фазы 5: sceVideoOutOpen == 15 символов == SSO -> пустое имя в логе).

void ResetStubs() {
    g_slotAddr.clear();
    g_slotByAddr.clear();
    g_nameToSlot.clear();
    g_names.clear();
    g_pageUsed = 0;   // страницу не отдаём — пригодится при повторном прогоне
}

// Кладёт (или находит по дедупликации) заглушку для импорта name.
// Возвращает гостевой адрес кода заглушки (mov eax, idx) или 0.
static uint64_t InstallStub(const char* name) {
    if (!name || !name[0]) name = "<без имени>";
    const std::string key(name);

    const auto dup = g_nameToSlot.find(key);
    if (dup != g_nameToSlot.end())
        return g_slotAddr[dup->second];

    if (!g_mem) return 0;

    // Нужна страница RWX под заглушки
    if (!g_pageBase || g_pageUsed >= kStubMaxSlots) {
        g_pageBase = g_mem->AllocGuest(kStubPageSize, PF_R | PF_W | PF_X);
        if (!g_pageBase) return 0;
        g_pageUsed = 0;
        printf("[DYN] страница заглушек импортов: guest 0x%llX (64 КБ RWX)\n",
               (unsigned long long)g_pageBase);
        fflush(stdout);
    }

    const size_t idx = g_names.size();
    const uint64_t slot = g_pageBase + g_pageUsed * kStubSlotSize;
    ++g_pageUsed;

    uint8_t* p = g_mem->Ptr(slot);
    if (!p) return 0;

    // mov eax, idx (B8 imm32); ud2 (0F 0B); ret (C3) — возврат в гостя.
    // ret обязателен: гость зовёт слот через call [GOT], и без ret исполнение
    // "провалилось" бы в соседние слоты (найдено ревью перед фазой 5).
    const uint8_t code[8] = {
        0xB8,
        (uint8_t)(idx & 0xFF), (uint8_t)((idx >> 8) & 0xFF),
        (uint8_t)((idx >> 16) & 0xFF), (uint8_t)((idx >> 24) & 0xFF),
        0x0F, 0x0B, 0xC3,
    };
    memcpy(p, code, kStubSlotSize);

    g_names.push_back(key);
    g_slotAddr.push_back(slot);
    g_slotByAddr[slot] = idx;
    g_nameToSlot[key] = idx;
    return slot;
}

// VEH: UD2 по адресу rip — хвост нашей заглушки (mov eax, idx; ud2)?
bool TryResolveStub(uint64_t rip, const char** nameOut) {
    if (!g_mem || g_slotByAddr.empty()) return false;

    uint64_t guest = 0;
    if (!g_mem->GuestForHost(rip, &guest)) return false;

    const uint64_t base = guest - 5;    // ud2 стоит на слоте+5
    const auto it = g_slotByAddr.find(base);
    if (it == g_slotByAddr.end()) return false;

    const uint8_t* p = g_mem->Ptr(base);
    if (!p || p[0] != 0xB8 || p[5] != 0x0F || p[6] != 0x0B)
        return false;                   // не наш паттерн — это краш гостя

    if (nameOut) *nameOut = g_names[it->second].c_str();  // владеющий вектор, без кэша
    return true;
}

// --- Чтение/запись гостевой памяти -----------------------------------------
static void GuestReadStr(uint64_t addr, char* out, size_t cap) {
    out[0] = 0;
    if (!g_mem || cap == 0) return;
    const uint8_t* p = g_mem->Ptr(addr);
    if (!p) return;
    size_t i = 0;
    while (i + 1 < cap && p[i]) { out[i] = (char)p[i]; ++i; }
    out[i] = 0;
}

// Запись u64 в гостевую память. Страница может быть R-X — на время записи
// поднимаем защиту и возвращаем как было.
static bool WritableNow(void* p) {
    MEMORY_BASIC_INFORMATION mbi {};
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    switch (mbi.Protect) {
    case PAGE_READWRITE: case PAGE_EXECUTE_READWRITE:
    case PAGE_WRITECOPY: case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

static bool GuestWriteU64(uint64_t addr, uint64_t val) {
    if (!g_mem) return false;
    void* p = (void*)(uintptr_t)g_mem->Translate(addr);
    if (!p) return false;
    if (WritableNow(p)) {
        memcpy(p, &val, 8);
        return true;
    }
    DWORD old = 0;
    if (!VirtualProtect(p, 8, PAGE_READWRITE, &old)) return false;
    memcpy(p, &val, 8);
    VirtualProtect(p, 8, old, &old);
    return true;
}

// --- Таблицы RELA -----------------------------------------------------------
static bool ReadRelaTable(uint64_t addr, uint64_t sizeBytes,
                          std::vector<Rela64>* out) {
    out->clear();
    if (!addr || !sizeBytes) return true;    // пустая таблица — не ошибка
    if (sizeBytes % 24) {
        printf("[DYN] размер RELA (%llu) не кратен 24\n",
               (unsigned long long)sizeBytes);
        return false;
    }
    if (!g_mem) return false;
    const uint8_t* p = g_mem->Ptr(addr);
    if (!p) {
        printf("[DYN] таблица RELA @0x%llX не мапнута\n",
               (unsigned long long)addr);
        return false;
    }
    out->resize((size_t)(sizeBytes / 24));
    memcpy(out->data(), p, (size_t)sizeBytes);
    return true;
}

// --- Основная работа --------------------------------------------------------
bool ApplyRelocations(const ElfImage& elf) {
    if (!g_mem) {
        printf("[DYN] память не подключена (AttachMemory) — релокации пропущены\n");
        return false;
    }

    const ElfSegment* dynSeg = nullptr;
    for (const ElfSegment& p : elf.phdrs)
        if (p.type == PT_DYNAMIC) { dynSeg = &p; break; }

    if (!dynSeg) {
        printf("[DYN] PT_DYNAMIC отсутствует (статический ELF) — релокации не нужны\n");
        return true;
    }

    // Читаем .dynamic: пары (d_tag, d_val) по 16 байт
    uint64_t dtRela = 0, dtRelasz = 0, dtJmprel = 0, dtPltrelsz = 0;
    uint64_t dtSymtab = 0, dtStrtab = 0, dtHash = 0, dtSyment = 24;
    uint64_t dtStrsz = 0;   // (используем для честного отчёта по строкам)
    (void)dtStrsz;

    uint64_t addr = dynSeg->vaddr;
    const uint64_t bytes = dynSeg->filesz ? dynSeg->filesz : dynSeg->memsz;
    const size_t maxEntries = (size_t)(bytes / 16);
    for (size_t i = 0; i < maxEntries; ++i) {
        const uint8_t* p = g_mem->Ptr(addr + i * 16);
        if (!p) break;
        int64_t tag = 0;
        uint64_t val = 0;
        memcpy(&tag, p, 8);
        memcpy(&val, p + 8, 8);
        if (tag == 0) break;      // DT_NULL — конец
        switch (tag) {
        case (int64_t)DT_HASH:     dtHash = val; break;
        case (int64_t)DT_STRTAB:   dtStrtab = val; break;
        case (int64_t)DT_SYMTAB:   dtSymtab = val; break;
        case (int64_t)DT_RELA:     dtRela = val; break;
        case (int64_t)DT_RELASZ:   dtRelasz = val; break;
        case (int64_t)DT_JMPREL:   dtJmprel = val; break;
        case (int64_t)DT_PLTRELSZ: dtPltrelsz = val; break;
        case (int64_t)DT_SYMENT:   dtSyment = val; break;
        case (int64_t)DT_STRSZ:    dtStrsz = val; break;
        default: break;
        }
    }

    if (dtSyment && dtSyment != 24)
        printf("[DYN] внимание: DT_SYMENT=%llu (ожидал 24)\n",
               (unsigned long long)dtSyment);

    // Таблицы релокаций
    std::vector<Rela64> mainRela, pltRela;
    if (!ReadRelaTable(dtRela, dtRelasz, &mainRela)) return false;
    if (!ReadRelaTable(dtJmprel, dtPltrelsz, &pltRela)) return false;

    if (mainRela.empty() && pltRela.empty()) {
        printf("[DYN] динамика есть, но таблиц RELA нет — применять нечего\n");
        return true;
    }

    if (!dtSymtab || !dtStrtab) {
        printf("[DYN] нет DT_SYMTAB/DT_STRTAB — именованные релокации невозможны\n");
        return false;
    }

    // Сколько символов в таблице: честно из DT_HASH (nchain),
    // иначе из самого большого индекса в релокациях.
    uint64_t symcount = 0;
    if (dtHash) {
        const uint8_t* h = g_mem->Ptr(dtHash);
        if (h) {
            uint32_t nbucket = 0, nchain = 0;
            memcpy(&nbucket, h, 4);
            memcpy(&nchain, h + 4, 4);
            symcount = nchain;
        }
    }
    if (!symcount) {
        uint64_t maxSym = 0;
        for (const Rela64& r : mainRela) {
            const uint64_t s = r.r_info >> 32;
            if (s > maxSym) maxSym = s;
        }
        for (const Rela64& r : pltRela) {
            const uint64_t s = r.r_info >> 32;
            if (s > maxSym) maxSym = s;
        }
        symcount = maxSym + 1;
    }
    printf("[DYN] динамика: SYMTAB@0x%llX STRTAB@0x%llX символов=%llu RELA=%u PLT=%u\n",
           (unsigned long long)dtSymtab, (unsigned long long)dtStrtab,
           (unsigned long long)symcount,
           (unsigned)mainRela.size(), (unsigned)pltRela.size());

    // Применяем
    uint64_t nRelative = 0, nIrelative = 0, n64 = 0, nGlobdat = 0, nJmpslot = 0;
    uint64_t nUnknownType = 0, nBadPlace = 0, nBadSym = 0;
    uint64_t nResolved = 0, nStubs = 0;
    std::vector<std::string> firstUnresolved;

    auto processTable = [&](const std::vector<Rela64>& v) {
        for (const Rela64& r : v) {
            const uint32_t type = (uint32_t)(r.r_info & 0xFFFFFFFFu);
            const uint32_t symIdx = (uint32_t)(r.r_info >> 32);

            switch (type) {
            case R_X86_64_RELATIVE:
                if (GuestWriteU64(r.r_offset, (uint64_t)r.r_addend)) ++nRelative;
                else ++nBadPlace;
                break;

            case R_X86_64_IRELATIVE:
                if (GuestWriteU64(r.r_offset, (uint64_t)r.r_addend)) ++nIrelative;
                else ++nBadPlace;
                break;

            case R_X86_64_64:
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT: {
                if (symIdx >= symcount) { ++nBadSym; break; }
                const uint8_t* sp = g_mem->Ptr(dtSymtab + (uint64_t)symIdx * 24);
                if (!sp) { ++nBadSym; break; }
                Sym64 s {};
                memcpy(&s, sp, 24);
                const bool defined = (s.st_shndx != 0) && (s.st_value != 0);
                if (defined) {
                    const uint64_t val = s.st_value + (uint64_t)r.r_addend;
                    if (GuestWriteU64(r.r_offset, val)) ++nResolved;
                    else ++nBadPlace;
                } else {
                    char name[96];
                    GuestReadStr(dtStrtab + s.st_name, name, sizeof(name));
                    const uint64_t stub = InstallStub(name);
                    if (stub && GuestWriteU64(r.r_offset, stub)) {
                        ++nStubs;
                        if (firstUnresolved.size() < 24)
                            firstUnresolved.push_back(name);
                    } else {
                        ++nBadPlace;
                    }
                }
                if (type == R_X86_64_64) ++n64;
                else if (type == R_X86_64_GLOB_DAT) ++nGlobdat;
                else ++nJmpslot;
                break;
            }

            default:
                ++nUnknownType;
                break;
            }
        }
    };

    processTable(mainRela);
    processTable(pltRela);

    printf("[DYN] применено: RELATIVE=%llu IRELATIVE=%llu 64=%llu GLOB_DAT=%llu JUMP_SLOT=%llu\n",
           (unsigned long long)nRelative, (unsigned long long)nIrelative,
           (unsigned long long)n64, (unsigned long long)nGlobdat,
           (unsigned long long)nJmpslot);
    printf("[DYN] свои символы=%llu, импортов(записей)=%llu, неизвестных типов=%llu,\n",
           (unsigned long long)nResolved, (unsigned long long)nStubs,
           (unsigned long long)nUnknownType);
    printf("[DYN] ошибок: место не мапнуто=%llu, символ за границей=%llu\n",
           (unsigned long long)nBadPlace, (unsigned long long)nBadSym);

    if (!firstUnresolved.empty()) {
        printf("[DYN] первые неразрешённые импорты (вызов -> имя в лог + ответ 0):\n");
        for (const std::string& n : firstUnresolved)
            printf("[DYN]   - %s\n", n.c_str());
        if (nStubs > firstUnresolved.size())
            printf("[DYN]   ... и ещё %llu (имена печатаются при вызовах)\n",
                   (unsigned long long)(nStubs - firstUnresolved.size()));
    }

    return true;
}

} } // namespace zrx::dyn
