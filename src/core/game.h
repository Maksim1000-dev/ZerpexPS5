// ============================================================================
// ZerpexPS5 — ядро: библиотека игр
// Сканирование папок на дампы PS5 (eboot.bin + sce_sys\param.json + icon0.png)
// и сохранение/загрузка списка игр рядом с EXE (games.json).
// ============================================================================
#pragma once

#include <string>
#include <vector>

namespace zrx {

struct Game {
    std::wstring root;       // корневая папка дампа/игры
    std::wstring icon;       // путь к обложке (icon0.png), может быть пустым
    std::string  title;      // из param.json или имя папки
    std::string  title_id;   // например PPSA15552
    std::string  version;    // contentVersion из param.json
    std::string  eboot;      // "self", "elf" или ""
    std::wstring eboot_path; // полный путь к eboot (для запуска ядра)
    std::string  self_state; // для SELF: "self-open" / "self-locked" / ""
};

// Сканирует папку рекурсивно и возвращает найденные игры PS5
std::vector<Game> ScanForGames(const std::wstring& root);

// Собирает описание игры по корневой папке.
// Возвращает false, если папка не похожа на игру PS5.
bool DescribeGame(const std::wstring& root, Game* out);

// Библиотека (games.json рядом с EXE): хранит пути, остальное восстанавливается
bool SaveGames(const std::wstring& file, const std::vector<Game>& games);
bool LoadGames(const std::wstring& file, std::vector<Game>* out);

} // namespace zrx
