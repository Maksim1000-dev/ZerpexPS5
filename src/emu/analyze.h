// ============================================================================
// ZerpexPS5 — фаза 2.5: умный анализ SELF-дампов
//
// ЧТО ДЕЛАЕТ:
//   - таблицу сегментов + энтропию каждого (нули / код / шифр);
//   - автопоиск import-модулей libSce* (стримом, без чтения файла в память);
//   - честный бейдж: "данные открыты -> путь фазы 3" vs "зашифрован -> фаза 7";
//   - корпус-режим: несколько дампом рядом -> сводка и диффы API-поверхностей.
// Криптографии нет и не будет: только чтение того, что лежит в файле открыто.
// ============================================================================
#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace zrx {
namespace analyze {

struct SegInfo {
    uint64_t flags = 0;
    uint64_t off = 0;
    uint64_t store = 0;
    uint64_t mem = 0;
    double   ent = 0.0;        // средняя энтропия по пробам, бит/байт
    double   zeroPct = 100.0;  // доля нулей (по первой пробе)
    const char* cls = "";      // человекочитаемый класс
};

struct SelfReport {
    bool     ok = false;
    std::string error;

    uint16_t segCount = 0;
    uint16_t headerWord = 0;
    uint32_t word04 = 0, word08 = 0, word0C = 0;
    uint64_t fileSizeField = 0;   // размер из заголовка
    uint64_t actualSize = 0;      // фактический размер файла

    bool     nestedElf = false;
    uint64_t elfOffset = 0;
    uint16_t elfType = 0;
    uint16_t elfPhnum = 0;
    uint64_t elfEntry = 0;
    uint8_t  elfOsabi = 0;

    std::vector<SegInfo> segs;
    std::set<std::string> modules;

    bool     open = false;       // бейдж: данные открыты (путь фазы 3)
    uint64_t tailExtra = 0;      // фактический размер больше заявленного (хвост дампера)
};

// Потоковый анализ файла (сам файл в память НЕ читается — годится для 250 МБ).
SelfReport AnalyzeFile(const std::wstring& path);

// Классификация одного куска байтов (для точечных проверок)
const char* ClassifyEntropy(double ent);

// Корпус-режим: rootDir + подпапки -> per-game сводка + ядро/уникальные модули.
void CorpusAnalyze(const std::wstring& rootDir);

} } // namespace zrx::analyze
