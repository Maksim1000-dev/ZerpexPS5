// ============================================================================
// ZerpexPS5 — фаза 5.3: транслятор шейдеров RDNA2 (GFX10.3) -> SPIR-V
//
// Кодировка инструкций сверена ПО ДОКУ хозяина:
//   lab/RDNA2/rdna2-shader-instruction-set-architecture.pdf
//   (извлечённый текст: tools/rdna2_text.txt)
//   Таблицы дока: 62 (форматы), 65-72 (SOPK/SOP1/SOPC/SOPP), 75-78 (VOP2/VOP1),
//                 80-83 (VOPC/VOP3A), 56 (EXP), 13-16 (скалярные операнды).
//
// Кратко о ключевых раскладках (RDNA2, не GFX8/9 — там было иначе!):
//   Скалярные 32-бит, top9 = (w>>23)&0x1FF:
//     SOP2 0x100+op (ENC [31:30]="10", OP [29:23])
//     SOPK 0x160+op (ENC [31:28]="1011", OP [27:23], SDST [22:16], SIMM16 [15:0])
//     SOP1 0x17D    (OP [15:8] 8 бит, SDST [22:16], SSRC0 [7:0])
//     SOPC 0x17E, SOPP 0x17F (OP [22:16], SIMM16 [15:0])
//   Векторные 32-бит (bit31 == 0):
//     VOP2: OP [30:25] 6 бит (0..60), VSRC1 [16:9] VGPR, VDST [24:17], SRC0 [8:0]
//     VOP1: (w>>25)&0x7F == 63; OP [16:9] 8 бит, VDST [24:17], SRC0 [8:0]
//     VOPC: (w>>25)&0x7F == 62; OP [24:17], VSRC1 [16:9], SRC0 [8:0]
//   Векторные 64-бит: word0[31:26] == 0b110101 -> VOP3A/VOP3B (в RDNA2 половины
//   перевёрнуты относительно GFX8/9: контроль в МЛАДШЕМ слове!):
//     word0: VDST [7:0], ABS [10:8], OPSEL [14:11], CLMP [15], OP [25:16] 10 бит
//     word1: SRC0 [8:0], SRC1 [17:9], SRC2 [26:18], OMOD [28:27], NEG [31:29]
//   EXP (64-бит): word1[31:16] == 0:
//     word0: VSRC0 [7:0], VSRC1 [15:8], VSRC2 [23:16], VSRC3 [31:24]
//     word1: TARGET [5:0], COMPR [6], DONE [7], VM [8], EN [15:12]
//     (размеры/семантика полей — Table 56; битовые позиции канонические GFX6-10)
//
// Кодирование операндов (Table 75/77, SRC0 [8:0]):
//   0-105 SGPR, 106/107 VCC, 108-123 TTMP, 124 M0, 125 NULL, 126/127 EXEC,
//   128 = 0, 129-192 = int 1..64, 193-208 = int -1..-16,
//   240-247 = 0.5,-0.5,1.0,-1.0,2.0,-2.0,4.0,-4.0, 248 = 1/(2*PI),
//   249 SDWA, 250 DPP16, 251 VCCZ, 252 EXECZ, 253 SCC, 255 литерал (след. слово),
//   256-511 = VGPR0-255 (9-битный прямой доступ — новшество RDNA2).
//
// Номера SPIR-V-опкодов сверены с spirv.core.grammar.json (Khronos unified1).
//
// Честные ограничения v1 (unsupported -> ok=false, причина в логе):
//   SOP2/SOPC, VOPC, VINTRP, VOP3P, SMEM/MUBUF/MIMG/DS/FLAT/GLOBAL/SCRATCH,
//   SDWA/DPP/DPP8, ветвления, ABS/NEG/OMOD/OPSEL/CLMP != 0, EN != 0xF,
//   COMPR/VM != 0, экспорты кроме Position(12)/MRT0(0)/Null(9).
//
// Соглашение нашего прокси (до честных дескрипторов из 7.6):
//   VS: SGPR0-1 = индекс вершины -> gl_VertexIndex (Builtin 42)
//   VS: экспорт TARGET 12 (Position 0) -> gl_Position
//   FS: экспорт TARGET 0 (MRT0) -> out vec4 color (Location 0)
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace zrx {
namespace rdna2 {

struct TranslateResult {
    bool ok = false;
    std::vector<uint32_t> spirv;   // готовый модуль (если ok)
    int decoded = 0;               // сколько инструкций разобрано
    int unknown = 0;               // сколько не поддержано
    std::string firstUnknown;      // первая причина отказа (для лога)
    std::string error;             // фатальная ошибка (структура кода)
};

// Декодирует RDNA2-байткод (32-бит слова, little-endian) и строит SPIR-V
// для Vulkan (GLSL 450, версия 1.0 — как рукописные модули 5.2).
// isVertex: true = вершинный (см. соглашение в шапке), false = пиксельный.
// ok = true только если decoded == unknown == 0 (иначе честный отказ).
bool Translate(const uint8_t* code, size_t size, bool isVertex,
               TranslateResult* out);

} // namespace rdna2
} // namespace zrx
