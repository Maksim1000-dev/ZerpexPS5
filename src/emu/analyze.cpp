// ============================================================================
// ZerpexPS5 — фаза 2.5: умный анализ SELF-дампов (реализация)
// ============================================================================
#include "analyze.h"

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>

namespace zrx {
namespace analyze {

// ----------------------------------------------------------------------------
// Энтропия и классификация
// ----------------------------------------------------------------------------
static double EntropyOf(const uint8_t* p, size_t n) {
    if (!p || n == 0) return 0.0;
    int hist[256] = {};
    for (size_t i = 0; i < n; ++i) ++hist[p[i]];
    double h = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!hist[i]) continue;
        const double pr = (double)hist[i] / (double)n;
        h -= pr * log(pr) / log(2.0);
    }
    return h;
}

const char* ClassifyEntropy(double ent) {
    if (ent < 0.1)  return "нули (bss/паддинг)";
    if (ent >= 7.7) return "ЗАШИФРОВАНО/СЖАТО";
    if (ent >= 4.5) return "код/данные (ОТКРЫТО)";
    return "низкоэнтропийные данные (строки/таблицы)";
}

// Читает до kMaxBytes с позиции off, возвращает энтропию и долю нулей.
static bool Probe(std::ifstream& f, uint64_t off, uint64_t avail,
                  double* ent, double* zeroPct) {
    static const uint64_t kMaxBytes = 32768;
    const uint64_t take = std::min<uint64_t>(avail, kMaxBytes);
    if (take == 0) return false;
    std::vector<uint8_t> buf((size_t)take);
    f.clear();
    f.seekg((std::streamoff)off);
    if (!f.read(reinterpret_cast<char*>(buf.data()), (std::streamsize)take)) return false;
    *ent = EntropyOf(buf.data(), (size_t)take);
    size_t zeros = 0;
    for (uint8_t b : buf) if (b == 0) ++zeros;
    *zeroPct = 100.0 * (double)zeros / (double)take;
    return true;
}

// Проба по сегменту: до 4 точек (0/25/50/75%), усредняем.
static void ProbeSegment(std::ifstream& f, const SegInfo& s, double* ent, double* zeroPct) {
    if (s.store == 0) { *ent = 0.0; *zeroPct = 100.0; return; }
    const double frac[4] = { 0.0, 0.25, 0.5, 0.75 };
    const int nProbes = s.store > 131072 ? 4 : 1;
    double sum = 0.0;
    double zeroFirst = 100.0;
    int done = 0;
    for (int i = 0; i < nProbes; ++i) {
        const uint64_t off = s.off + (uint64_t)(frac[i] * (double)s.store);
        double e = 0.0, z = 100.0;
        if (!Probe(f, off, s.store - (off - s.off), &e, &z)) continue;
        sum += e;
        if (done == 0) zeroFirst = z;
        ++done;
    }
    *ent = done ? sum / done : 0.0;
    *zeroPct = zeroFirst;
}

// ----------------------------------------------------------------------------
// Поиск модулей libSce* (стрим, чанками, без регэкспа)
// ----------------------------------------------------------------------------
static void ScanModulesInChunk(const char* p, size_t n, std::set<std::string>* out) {
    static const char kKey[] = "libSce";
    const size_t kKeyLen = 6;
    for (size_t i = 0; i + kKeyLen <= n; ) {
        if (memcmp(p + i, kKey, kKeyLen) != 0) { ++i; continue; }
        size_t j = i + kKeyLen;
        std::string name;
        while (j < n && name.size() < 64) {
            const char c = p[j];
            const bool alnum = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                               (c >= '0' && c <= '9');
            if (!alnum) break;
            name += c;
            ++j;
        }
        if (name.size() >= 2) out->insert(name);
        i = (j > i + kKeyLen) ? j : i + kKeyLen;
    }
}

static void ScanModulesRange(std::ifstream& f, uint64_t off, uint64_t len,
                             std::set<std::string>* out) {
    static const size_t kChunk = 1 << 20;
    static const size_t kCarry = 16;   // "libSce..." может пересечь границу чанка
    std::vector<char> buf(kChunk + kCarry);
    std::vector<char> carry(kCarry);
    size_t carryLen = 0;

    f.clear();
    f.seekg((std::streamoff)off);
    uint64_t remaining = len;
    while (remaining > 0) {
        const uint64_t want = std::min<uint64_t>(kChunk, remaining);
        if (!f.read(buf.data() + carryLen, (std::streamsize)want)) break;
        const size_t got = (size_t)want;
        const size_t total = carryLen + got;
        ScanModulesInChunk(buf.data(), total, out);
        carryLen = std::min(total, kCarry);
        memcpy(carry.data(), buf.data() + total - carryLen, carryLen);
        memcpy(buf.data(), carry.data(), carryLen);
        remaining -= got;
    }
}

// ----------------------------------------------------------------------------
// Полный анализ файла
// ----------------------------------------------------------------------------
SelfReport AnalyzeFile(const std::wstring& path) {
    SelfReport r;
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) { r.error = "файл не открылся"; return r; }

    f.seekg(0, std::ios::end);
    r.actualSize = (uint64_t)f.tellg();
    f.seekg(0);

    uint8_t hdr[0x300] = {};
    if (r.actualSize < 0x40 || !f.read(reinterpret_cast<char*>(hdr), 0x300) || f.gcount() < 0x40) {
        r.error = "файл слишком мал для SELF-заголовка";
        return r;
    }

    uint32_t magic = 0;
    memcpy(&magic, hdr, 4);
    if (magic != 0xEEF51454u) { r.error = "нет магии SELF PS5"; return r; }

    memcpy(&r.word04, hdr + 0x04, 4);
    memcpy(&r.word08, hdr + 0x08, 4);
    memcpy(&r.word0C, hdr + 0x0C, 4);
    memcpy(&r.fileSizeField, hdr + 0x10, 8);
    memcpy(&r.segCount, hdr + 0x18, 2);
    memcpy(&r.headerWord, hdr + 0x1A, 2);

    if (r.fileSizeField < r.actualSize)
        r.tailExtra = r.actualSize - r.fileSizeField;   // хвост, дописанный дампером

    if (r.segCount == 0 || r.segCount > 64) {
        char buf[128];
        snprintf(buf, sizeof(buf), "подозрительное число сегментов: %u", (unsigned)r.segCount);
        r.error = buf;
        return r;
    }

    // Таблица сегментов
    std::vector<uint8_t> table((size_t)r.segCount * 32);
    f.seekg(0x20);
    if (!f.read(reinterpret_cast<char*>(table.data()), (std::streamsize)table.size())) {
        r.error = "таблица сегментов не читается";
        return r;
    }
    for (uint16_t i = 0; i < r.segCount; ++i) {
        const uint8_t* p = table.data() + (size_t)i * 32;
        SegInfo s;
        memcpy(&s.flags, p, 8);
        memcpy(&s.off,   p + 8, 8);
        memcpy(&s.store, p + 16, 8);
        memcpy(&s.mem,   p + 24, 8);
        r.segs.push_back(s);
    }

    // Вложенный ELF
    r.elfOffset = 0x20 + (uint64_t)r.segCount * 32;
    if (r.elfOffset + 64 <= r.actualSize) {
        uint8_t e[64] = {};
        f.seekg((std::streamoff)r.elfOffset);
        if (f.read(reinterpret_cast<char*>(e), 64) && memcmp(e, "\x7F""ELF", 4) == 0) {
            r.nestedElf = true;
            memcpy(&r.elfType,  e + 16, 2);
            memcpy(&r.elfEntry, e + 24, 8);
            r.elfOsabi = e[7];
            memcpy(&r.elfPhnum, e + 0x38, 2);
        }
    }

    // Энтропия сегментов
    for (SegInfo& s : r.segs) {
        uint64_t off = s.off, len = s.store;
        if (off > r.actualSize) { off = r.actualSize; len = 0; }
        if (len > r.actualSize - off) len = r.actualSize - off;
        s.off = off;
        s.store = len;
        double e = 0.0, z = 100.0;
        ProbeSegment(f, s, &e, &z);
        s.ent = e;
        s.zeroPct = z;
        s.cls = ClassifyEntropy(e);
    }

    // Модули (только по содержательным сегментам)
    for (const SegInfo& s : r.segs) {
        if (s.store < 1024 || s.ent < 0.1) continue;
        ScanModulesRange(f, s.off, s.store, &r.modules);
    }

    // Бейдж: самый большой "живой" сегмент открыт?
    const SegInfo* best = nullptr;
    for (const SegInfo& s : r.segs) {
        if (s.store < 4096 || s.ent < 0.5) continue;
        if (!best || s.store > best->store) best = &s;
    }
    r.open = best && best->ent < 7.7;

    r.ok = true;
    return r;
}

// ----------------------------------------------------------------------------
// Корпус-режим
// ----------------------------------------------------------------------------
struct CorpusGame {
    std::string folder;
    std::string titleId;
    SelfReport  rep;
};

static std::string Narrow(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// Первый найденный файл с данным именем в дереве (глубина ограничена счётчиком)
static std::wstring FindFileRec(const std::wstring& dir, const wchar_t* name) {
    std::error_code ec;
    size_t visited = 0;
    for (std::filesystem::recursive_directory_iterator
             it(std::filesystem::path(dir), std::filesystem::directory_options::skip_permission_denied, ec),
             end;
         !ec && it != end && visited < 200000; it.increment(ec), ++visited) {
        if (!_wcsicmp(it->path().filename().c_str(), name))
            return it->path().wstring();
    }
    return std::wstring();
}

static std::string ReadTitleId(const std::wstring& paramPath) {
    if (paramPath.empty()) return "";
    std::ifstream f(paramPath.c_str(), std::ios::binary);
    if (!f) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    const std::string src = ss.str();
    const std::string key = "\"titleId\"";
    const size_t p = src.find(key);
    if (p == std::string::npos) return "";
    const size_t q1 = src.find('"', p + key.size());
    if (q1 == std::string::npos) return "";
    const size_t q2 = src.find('"', q1 + 1);
    if (q2 == std::string::npos) return "";
    return src.substr(q1 + 1, q2 - q1 - 1);
}

static std::string HumanSize(uint64_t b) {
    char buf[64];
    if (b >= 1024ull * 1024 * 1024)
        snprintf(buf, sizeof(buf), "%.2f GB", (double)b / (1024.0 * 1024 * 1024));
    else if (b >= 1024ull * 1024)
        snprintf(buf, sizeof(buf), "%.2f MB", (double)b / (1024.0 * 1024));
    else
        snprintf(buf, sizeof(buf), "%llu KB", (unsigned long long)(b / 1024));
    return buf;
}

void CorpusAnalyze(const std::wstring& rootDir) {
    printf("[CORPUS] сканирую: %s\n", Narrow(rootDir).c_str());

    std::vector<CorpusGame> games;
    std::error_code ec;
    for (std::filesystem::directory_iterator
             it(std::filesystem::path(rootDir),
                std::filesystem::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        if (!it->is_directory(ec)) continue;

        CorpusGame g;
        g.folder = Narrow(it->path().filename().wstring());

        const std::wstring eboot = FindFileRec(it->path().wstring(), L"eboot.bin");
        if (eboot.empty()) {
            printf("[CORPUS] %s: eboot.bin не найден — пропускаю\n", g.folder.c_str());
            continue;
        }
        const std::wstring param = FindFileRec(it->path().wstring(), L"param.json");
        g.titleId = ReadTitleId(param);

        g.rep = AnalyzeFile(eboot);
        games.push_back(g);
    }

    if (games.empty()) {
        printf("[CORPUS] SELF-дампов не найдено\n");
        return;
    }

    // --- Сводка по играм ---
    printf("\n=== СВОДКА (%u игр) ===\n", (unsigned)games.size());
    printf("%-28s %-11s %9s %9s %8s %s\n", "игра", "titleId", "код(откр)", "модули", "сегм", "бейдж");
    for (const CorpusGame& g : games) {
        uint64_t codeBytes = 0;
        for (const SegInfo& s : g.rep.segs)
            if (strstr(s.cls, "ОТКРЫТО")) codeBytes += s.store;
        printf("%-28s %-11s %9s %9u %8u %s\n",
               g.folder.substr(0, 28).c_str(),
               g.titleId.empty() ? "-" : g.titleId.substr(0, 11).c_str(),
               HumanSize(codeBytes).c_str(),
               (unsigned)g.rep.modules.size(),
               (unsigned)g.rep.segCount,
               g.rep.open ? "ОТКРЫТ -> фаза 3" : "ШИФР -> фаза 7");
    }

    // --- Ядро (пересечение всех) и уникальные ---
    std::set<std::string> core;
    bool first = true;
    for (const CorpusGame& g : games) {
        if (first) { core = g.rep.modules; first = false; continue; }
        std::set<std::string> inter;
        for (const std::string& m : core)
            if (g.rep.modules.count(m)) inter.insert(m);
        core = inter;
    }

    printf("\n=== ЯДРО ВСЕХ ИГР (%u модулей) ===\n", (unsigned)core.size());
    {
        size_t i = 0;
        for (const std::string& m : core) {
            printf("%s%s", i ? ", " : "", m.c_str());
            ++i;
            if ((i % 10) == 0) printf("\n");
        }
        if ((i % 10) != 0) printf("\n");
    }

    printf("\n=== УНИКАЛЬНЫЕ МОДУЛИ ПО ИГРАМ ===\n");
    for (const CorpusGame& g : games) {
        std::set<std::string> uniq;
        for (const std::string& m : g.rep.modules) {
            bool elsewhere = false;
            for (const CorpusGame& o : games) {
                if (&o == &g) continue;
                if (o.rep.modules.count(m)) { elsewhere = true; break; }
            }
            if (!elsewhere) uniq.insert(m);
        }
        printf("%s (%u):\n", g.folder.substr(0, 40).c_str(), (unsigned)uniq.size());
        size_t i = 0;
        for (const std::string& m : uniq) {
            printf("%s%s", i ? ", " : "  ", m.c_str());
            ++i;
            if ((i % 10) == 0) printf("\n");
        }
        if ((i % 10) != 0) printf("\n");
    }

    printf("\n[CORPUS] честное ограничение: список модулей берётся из строк в дампе,\n");
    printf("[CORPUS] NID-привязки (какая функция какой номер) — фаза 4+\n");
}

} } // namespace zrx::analyze
