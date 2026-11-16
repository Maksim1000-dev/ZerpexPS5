// ============================================================================
// ZerpexPS5 — ядро: логгер
// Простой буфер строк. Показывается в лаунчере и (потом) в оверлеях эмулятора.
// ============================================================================
#pragma once

#include <string>
#include <vector>

namespace zrx {

class Log {
public:
    static void info(const char* fmt, ...);
    static void warn(const char* fmt, ...);
    static void error(const char* fmt, ...);

    // Строки в порядке добавления (старые вытесняются новыми)
    static const std::vector<std::string>& lines();

private:
    static void add(const char* level, const char* fmt, va_list args);
};

} // namespace zrx
