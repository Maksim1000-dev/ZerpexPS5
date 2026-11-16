// ============================================================================
// ZerpexPS5 — ядро: библиотека игр (реализация)
// ============================================================================
#include "game.h"

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace zrx {

// ----------------------------------------------------------------------------
// Вспомогалки кодировок
// ----------------------------------------------------------------------------
static std::string NarrowUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)(n > 0 ? n : 0), '\0');
    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::wstring WideUtf8(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)(n > 0 ? n : 0), L'\0');
    if (n > 0)
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// ----------------------------------------------------------------------------
// Мини-JSON (достаточно для param.json и games.json)
// ----------------------------------------------------------------------------
static std::string JsonGetString(const std::string& src, const char* key) {
    const std::string pat = "\"" + std::string(key) + "\"";
    size_t p = src.find(pat);
    if (p == std::string::npos) return "";
    p = src.find(':', p + pat.size());
    if (p == std::string::npos) return "";
    p = src.find('"', p);
    if (p == std::string::npos) return "";
    std::string out;
    for (size_t i = p + 1; i < src.size(); ++i) {
        char c = src[i];
        if (c == '\\' && i + 1 < src.size()) {
            char n = src[++i];
            if (n == 'n') out += '\n';
            else out += n;
            continue;
        }
        if (c == '"') break;
        out += c;
    }
    return out;
}

static std::string JsonEscape(const std::string& s) {
    std::string out;
    for (char c : s) {
        if (c == '\\' || c == '"') { out += '\\'; out += c; }
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out;
}

// ----------------------------------------------------------------------------
// Поиск файлов (без учёта регистра)
// ----------------------------------------------------------------------------
static std::wstring FindInDir(const std::wstring& dir, const wchar_t* name) {
    std::error_code ec;
    for (fs::directory_iterator it(fs::path(dir), fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end; it.increment(ec)) {
        if (!_wcsicmp(it->path().filename().c_str(), name))
            return it->path().wstring();
    }
    return std::wstring();
}

// Магия исполняемого файла: ELF (7F "ELF") или SELF (контейнер PS5)
static std::string DetectEbootMagic(const std::wstring& path) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) return "";
    char m[4] = {};
    f.read(m, 4);
    if (f.gcount() >= 4 &&
        (unsigned char)m[0] == 0x7F && m[1] == 'E' && m[2] == 'L' && m[3] == 'F')
        return "elf";
    return "self";
}

// Фаза 2.5 (лайт-версия для лаунчера): смотрим энтропию самого крупного
// содержательного сегмента SELF. Код ~5-7 бит/байт, шифр ~7.9+.
// Только чтение, без криптографии.
static std::string ClassifySelf(const std::wstring& path) {
    std::ifstream f(path.c_str(), std::ios::binary);
    if (!f) return "self-locked";

    uint8_t hdr[0x300] = {};
    f.read(reinterpret_cast<char*>(hdr), sizeof(hdr));
    if (f.gcount() < 0x40) return "self-locked";

    uint32_t magic = 0;
    memcpy(&magic, hdr, 4);
    if (magic != 0xEEF51454u) return "self-locked";

    uint16_t segCount = 0;
    memcpy(&segCount, hdr + 0x18, 2);
    if (segCount == 0 || segCount > 64) return "self-locked";

    uint64_t bestOff = 0, bestStore = 0;
    double bestEnt = 0.0;
    for (uint16_t i = 0; i < segCount; ++i) {
        const size_t o = 0x20 + (size_t)i * 32;
        if (o + 32 > sizeof(hdr)) break;
        uint64_t off = 0, store = 0;
        memcpy(&off,   hdr + o + 8, 8);
        memcpy(&store, hdr + o + 16, 8);
        if (store < 65536) continue;          // интересует только крупное
        uint8_t sample[16384] = {};
        f.clear();
        f.seekg((std::streamoff)off);
        f.read(reinterpret_cast<char*>(sample), sizeof(sample));
        const std::streamsize got = f.gcount();
        if (got <= 0) continue;
        int hist[256] = {};
        for (std::streamsize k = 0; k < got; ++k) ++hist[sample[k]];
        double h = 0.0;
        for (int k = 0; k < 256; ++k) {
            if (!hist[k]) continue;
            const double p = (double)hist[k] / (double)got;
            h -= p * (log(p) / log(2.0));
        }
        if (h >= 0.5 && store > bestStore) {  // сегмент с содержимым
            bestStore = store;
            bestEnt = h;
            bestOff = off;
        }
    }
    (void)bestOff;
    if (bestStore == 0) return "self-locked";
    return bestEnt < 7.7 ? "self-open" : "self-locked";
}

bool DescribeGame(const std::wstring& root, Game* out) {
    if (!out || root.empty()) return false;

    const std::wstring eboot_bin = FindInDir(root, L"eboot.bin");
    const std::wstring eboot_elf = FindInDir(root, L"eboot.elf");
    const std::wstring sce_sys   = FindInDir(root, L"sce_sys");

    std::wstring param, icon;
    if (!sce_sys.empty()) {
        param = FindInDir(sce_sys, L"param.json");
        icon  = FindInDir(sce_sys, L"icon0.png");
    }

    if (eboot_bin.empty() && eboot_elf.empty() && param.empty())
        return false;

    out->root = root;
    out->eboot = !eboot_bin.empty() ? DetectEbootMagic(eboot_bin)
               : (!eboot_elf.empty() ? "elf" : "");
    out->eboot_path = !eboot_bin.empty() ? eboot_bin : eboot_elf;
    out->self_state = (out->eboot == "self") ? ClassifySelf(eboot_bin) : "";

    if (!param.empty()) {
        std::ifstream f(param.c_str(), std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        const std::string src = ss.str();
        out->title    = JsonGetString(src, "titleName");
        out->title_id = JsonGetString(src, "titleId");
        out->version  = JsonGetString(src, "contentVersion");
    }
    if (out->title.empty())
        out->title = NarrowUtf8(fs::path(root).filename().wstring());

    out->icon = icon;
    return true;
}

std::vector<Game> ScanForGames(const std::wstring& root) {
    std::vector<Game> found;
    std::vector<std::wstring> taken;
    std::error_code ec;
    size_t visited = 0;
    const size_t kMaxEntries = 300000;

    for (fs::recursive_directory_iterator
             it(fs::path(root), fs::directory_options::skip_permission_denied, ec), end;
         !ec && it != end && visited < kMaxEntries; it.increment(ec), ++visited) {
        if (!it->is_regular_file(ec) || ec)
            continue;
        const std::wstring name = it->path().filename().wstring();
        const bool is_eboot = !_wcsicmp(name.c_str(), L"eboot.bin") ||
                              !_wcsicmp(name.c_str(), L"eboot.elf");
        const bool is_param = !_wcsicmp(name.c_str(), L"param.json");
        if (!is_eboot && !is_param)
            continue;

        std::wstring dir = it->path().parent_path().wstring();
        if (is_param && _wcsicmp(fs::path(dir).filename().c_str(), L"sce_sys") == 0)
            dir = fs::path(dir).parent_path().wstring();

        if (std::find(taken.begin(), taken.end(), dir) != taken.end())
            continue;

        Game g;
        if (DescribeGame(dir, &g)) {
            taken.push_back(dir);
            found.push_back(g);
        }
    }
    return found;
}

// ----------------------------------------------------------------------------
// Сохранение/загрузка библиотеки (только пути — остальное описываем заново)
// ----------------------------------------------------------------------------
bool SaveGames(const std::wstring& file, const std::vector<Game>& games) {
    std::ofstream f(file.c_str(), std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << "{\n  \"games\": [\n";
    for (size_t i = 0; i < games.size(); ++i) {
        f << "    { \"path\": \"" << JsonEscape(NarrowUtf8(games[i].root)) << "\" }"
          << (i + 1 < games.size() ? "," : "") << "\n";
    }
    f << "  ]\n}\n";
    return true;
}

bool LoadGames(const std::wstring& file, std::vector<Game>* out) {
    if (!out) return false;
    std::ifstream f(file.c_str(), std::ios::binary);
    if (!f) return false;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string src = ss.str();

    const std::string key = "\"path\"";
    size_t p = 0;
    while ((p = src.find(key, p)) != std::string::npos) {
        p = src.find('"', p + key.size());
        if (p == std::string::npos) break;
        std::string raw;
        for (size_t i = p + 1; i < src.size(); ++i) {
            char c = src[i];
            if (c == '\\' && i + 1 < src.size()) { raw += src[++i]; continue; }
            if (c == '"') break;
            raw += c;
        }
        p += raw.size() + 1;
        Game g;
        if (DescribeGame(WideUtf8(raw), &g))
            out->push_back(g);
    }
    return true;
}

} // namespace zrx
