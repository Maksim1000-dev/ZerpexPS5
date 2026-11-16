// ============================================================================
// ZerpexPS5 — ядро: логгер (реализация)
// ============================================================================
#include "log.h"

#include <cstdarg>
#include <cstdio>

namespace zrx {

static std::vector<std::string>& GetLines() {
    static std::vector<std::string> lines;
    return lines;
}

const std::vector<std::string>& Log::lines() {
    return GetLines();
}

void Log::add(const char* level, const char* fmt, va_list args) {
    char buf[1024];
    std::vsnprintf(buf, sizeof(buf), fmt, args);

    char line[1104];
    std::snprintf(line, sizeof(line), "[%s] %s", level, buf);

    std::vector<std::string>& v = GetLines();
    v.push_back(line);
    if (v.size() > 256)
        v.erase(v.begin());
}

void Log::info(const char* fmt, ...) {
    va_list a; va_start(a, fmt); add("info",  fmt, a); va_end(a);
}

void Log::warn(const char* fmt, ...) {
    va_list a; va_start(a, fmt); add("warn",  fmt, a); va_end(a);
}

void Log::error(const char* fmt, ...) {
    va_list a; va_start(a, fmt); add("error", fmt, a); va_end(a);
}

} // namespace zrx
