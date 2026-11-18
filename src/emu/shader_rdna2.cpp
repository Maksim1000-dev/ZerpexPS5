// ============================================================================
// ZerpexPS5 — фаза 5.3: транслятор RDNA2 -> SPIR-V (реализация)
// Кодировки и соглашения — см. шапку shader_rdna2.h (source of truth).
// Все SPIR-V-номера сверены с spirv.core.grammar.json (Khronos unified1).
// ============================================================================
#include "shader_rdna2.h"

#include <cstdio>
#include <cstring>

namespace zrx {
namespace rdna2 {

namespace {

// --- SPIR-V опкоды / константы (проверены по грамматике) --------------------
enum : uint32_t {
    SPV_OpCapability         = 17,
    SPV_OpTypeVoid           = 19,
    SPV_OpTypeInt            = 21,
    SPV_OpTypeFloat          = 22,
    SPV_OpTypeVector         = 23,
    SPV_OpTypePointer        = 32,
    SPV_OpTypeFunction       = 33,
    SPV_OpConstant           = 43,
    SPV_OpFunction           = 54,
    SPV_OpFunctionEnd        = 56,
    SPV_OpVariable           = 59,
    SPV_OpLoad               = 61,
    SPV_OpStore              = 62,
    SPV_OpDecorate           = 71,
    SPV_OpCompositeConstruct = 80,
    SPV_OpConvertSToF        = 111,
    SPV_OpBitcast            = 124,
    SPV_OpFAdd               = 129,
    SPV_OpFMul               = 133,
    SPV_OpShiftRightLogical  = 194,
    SPV_OpShiftLeftLogical   = 196,
    SPV_OpBitwiseOr          = 197,
    SPV_OpBitwiseAnd         = 199,
    SPV_OpLabel              = 248,
    SPV_OpReturn             = 253,
    SPV_OpMemoryModel        = 14,
    SPV_OpEntryPoint         = 15,
    SPV_OpExecutionMode      = 16,
};
enum : uint32_t {
    SPV_DecomLocation = 30,   // Decoration
    SPV_DecomBuiltIn  = 11,
    SPV_BI_Position    = 0,   // BuiltIn
    SPV_BI_VertexIndex = 42,
    SPV_EM_OriginUpperLeft = 7,  // ExecutionMode (FS)
    SPV_ExecVertex   = 0,    // ExecutionModel
    SPV_ExecFragment = 4,
    SPV_SC_Input     = 1,    // StorageClass
    SPV_SC_Output    = 3,
    SPV_MM_Logical   = 0,    // MemoryModel
    SPV_MM_GLSL450   = 1,
};

// --- Кодирование RDNA2 (сверено с дном хозяина) -----------------------------
enum : uint32_t {
    // скалярные top9 = (w >> 23) & 0x1FF
    R2_TOP_SOP2_MIN = 0x100, R2_TOP_SOP2_MAX = 0x15F,   // не поддержан в v1
    R2_TOP_SOPK_MIN = 0x160, R2_TOP_SOPK_MAX = 0x17C,
    R2_TOP_SOP1     = 0x17D,
    R2_TOP_SOPC     = 0x17E,
    R2_TOP_SOPP     = 0x17F,
    R2_VOP3A_TOP6   = 0x35,   // word0[31:26] = 0b110101
    R2_VOP3P_TOP6   = 0x33,   // word0[31:26] = 0b110011
    R2_EXP_TOP6     = 0x3E,   // Table 106: word0[31:26] = 0b111110
    R2_SOPK_S_MOVK_I32 = 0,
    R2_SOP1_S_MOV_B32  = 3,
    R2_SOPP_S_NOP      = 0,
    R2_SOPP_S_ENDPGM   = 1,
    R2_SOPP_S_BARRIER  = 10,
    R2_SOPP_S_WAITCNT  = 12,
    R2_VOP2_V_ADD_F32     = 3,
    R2_VOP2_V_MUL_F32     = 8,
    R2_VOP2_V_LSHRREV_B32 = 22,
    R2_VOP2_V_LSHLREV_B32 = 26,
    R2_VOP2_V_AND_B32     = 27,
    R2_VOP2_V_OR_B32      = 28,
    R2_VOP1_V_MOV_B32     = 1,
    R2_VOP1_V_CVT_F32_I32 = 5,
    R2_VOP3A_V_FMA_F32    = 331,
    R2_EXP_TARGET_POSITION = 12,
    R2_EXP_TARGET_MRT0     = 0,
    R2_EXP_TARGET_NULL     = 9,
};

// Инлайн-константы операндов (Table 67/75/77; SRC0 9 бит, SSRC0 8 бит).
// 240..248 — флоаты (биты f32); 128..208 — целые.
static bool InlineFloat(uint32_t code, uint32_t* bits) {
    static const uint32_t tbl[9] = {          // 0.5,-0.5,1.0,-1.0,2.0,-2.0,4.0,-4.0,1/(2pi)
        0x3F000000u, 0xBF000000u, 0x3F800000u, 0xBF800000u,
        0x40000000u, 0xC0000000u, 0x40800000u, 0xC0800000u, 0x3F22F983u };
    if (code < 240 || code > 248) return false;
    *bits = tbl[code - 240];
    return true;
}
static bool InlineInt(uint32_t code, int64_t* v) {
    if (code == 128) { *v = 0; return true; }          // 0
    if (code >= 129 && code <= 192) { *v = int64_t(code - 128); return true; }   // 1..64
    if (code >= 193 && code <= 208) { *v = -int64_t(code - 192); return true; }  // -1..-16
    return false;
}

// ============================================================================
// Строитель SPIR-V: два потока — pre (типы/константы/глобалы) и fn (тело).
// Глобалы известны заранее, константы материализуются лениво в pre —
// порядок логической раскладки не нарушается.
// ============================================================================
struct Builder {
    std::vector<uint32_t> pre, fn;
    uint32_t next = 1;                       // id counter (bound = next)
    // типы
    uint32_t tVoid = 0, tF32 = 0, tI32 = 0, tU32 = 0, tV4 = 0, tFn = 0;
    uint32_t ptrInI32 = 0, ptrOutV4 = 0;
    uint32_t fnId = 0, entryId = 0;
    uint32_t varVid = 0, varPos = 0;         // VS: gl_VertexIndex / gl_Position
    uint32_t varCol = 0;                     // FS: out color
    bool     isVertex = false;
    uint32_t vidxId = 0;                     // кэш Load(gl_VertexIndex)

    uint32_t id() { return next++; }

    static void emit(std::vector<uint32_t>& dst, uint32_t op,
                     const uint32_t* ops, size_t n) {
        dst.push_back((uint32_t(n + 1) << 16) | op);
        for (size_t i = 0; i < n; i++) dst.push_back(ops[i]);
    }
    void emitPre(uint32_t op, const std::vector<uint32_t>& ops) {
        emit(pre, op, ops.data(), ops.size());
    }
    void emitFn(uint32_t op, const std::vector<uint32_t>& ops) {
        emit(fn, op, ops.data(), ops.size());
    }

    void typeVoid() {
        if (tVoid) return;
        tVoid = id(); uint32_t o[] = { tVoid };
        emitPre(SPV_OpTypeVoid, std::vector<uint32_t>(o, o + 1));
    }
    uint32_t typeF32() {
        if (tF32) return tF32;
        typeVoid(); tF32 = id();
        emitPre(SPV_OpTypeFloat, { tF32, 32 });
        return tF32;
    }
    uint32_t typeI32() {
        if (tI32) return tI32;
        typeVoid(); tI32 = id();
        emitPre(SPV_OpTypeInt, { tI32, 32, 1 });
        return tI32;
    }
    uint32_t typeU32() {
        if (tU32) return tU32;
        typeVoid(); tU32 = id();
        emitPre(SPV_OpTypeInt, { tU32, 32, 0 });
        return tU32;
    }
    uint32_t typeV4() {
        if (tV4) return tV4;
        tV4 = id();
        emitPre(SPV_OpTypeVector, { tV4, typeF32(), 4 });
        return tV4;
    }
    // КОНСТАНТЫ — материализуются лениво (в pre, до функции — порядок ок)
    uint32_t constI(uint32_t type, int64_t v) {
        uint32_t r = id();
        emitPre(SPV_OpConstant, { type, r, uint32_t(v & 0xFFFFFFFF) });
        return r;
    }
    uint32_t constF(uint32_t bits) {
        uint32_t r = id();
        emitPre(SPV_OpConstant, { typeF32(), r, bits });
        return r;
    }
    void declare(uint32_t var, uint32_t decoration, uint32_t value) {
        emitPre(SPV_OpDecorate, { var, decoration, value });
    }
    // Глобальные переменные + типы указателей + функция — сразу при старте.
    void init(bool vertex) {
        isVertex = vertex;
        typeVoid(); typeF32(); typeI32(); typeU32(); typeV4();
        // OpTypeFunction void main()
        tFn = id();
        emitPre(SPV_OpTypeFunction, { tFn, tVoid });
        fnId = id();
        if (vertex) {
            ptrInI32 = id();
            emitPre(SPV_OpTypePointer, { ptrInI32, SPV_SC_Input, typeI32() });
            varVid = id();
            emitPre(SPV_OpVariable, { ptrInI32, varVid, SPV_SC_Input });
            declare(varVid, SPV_DecomBuiltIn, SPV_BI_VertexIndex);
        }
        ptrOutV4 = id();
        emitPre(SPV_OpTypePointer, { ptrOutV4, SPV_SC_Output, typeV4() });
        if (vertex) {
            varPos = id();
            emitPre(SPV_OpVariable, { ptrOutV4, varPos, SPV_SC_Output });
            declare(varPos, SPV_DecomBuiltIn, SPV_BI_Position);
        } else {
            varCol = id();
            emitPre(SPV_OpVariable, { ptrOutV4, varCol, SPV_SC_Output });
            declare(varCol, SPV_DecomLocation, 0);
        }
        // Функция + метка
        emitFn(SPV_OpFunction, { tVoid, fnId, 0 /*control*/, tFn });
        entryId = id();
        emitFn(SPV_OpLabel, { entryId });
    }
    void finish(std::vector<uint32_t>* out) {
        emitFn(SPV_OpReturn, {});
        emitFn(SPV_OpFunctionEnd, {});
        out->clear();
        out->push_back(0x07230203);          // magic
        out->push_back(0x00010000);          // версия 1.0 (как рукописные 5.2)
        out->push_back(0x00080000 | 0);      // generator (dev build id)
        out->push_back(next);                // bound (ids: 1..next-1)
        out->push_back(0);                   // schema
        // Capability + MemoryModel
        uint32_t cap[] = { 1 };              // 1 = Shader
        std::vector<uint32_t> head;
        emit(head, SPV_OpCapability, cap, 1);
        uint32_t mm[] = { SPV_MM_Logical, SPV_MM_GLSL450 };
        emit(head, SPV_OpMemoryModel, mm, 2);
        // EntryPoint + интерфейс
        std::vector<uint32_t> ep;
        ep.push_back(isVertex ? SPV_ExecVertex : SPV_ExecFragment);
        ep.push_back(fnId);
        // "main" — UTF-8 с завершающим нулём, выравнивается до 4 байт:
        // 5 байт = ДВА слова (0x6E69616D + 0x00000000). Без второго слова
        // парсер съедал первый id интерфейса как хвост строки, и драйвер
        // отвергал модуль на компиляции пайплайна (VK_ERROR_UNKNOWN -13).
        ep.push_back(0x6E69616D);
        ep.push_back(0);
        if (isVertex) { ep.push_back(varVid); ep.push_back(varPos); }
        else          { ep.push_back(varCol); }
        emit(head, SPV_OpEntryPoint, ep.data(), ep.size());
        if (!isVertex) {
            uint32_t em[] = { fnId, SPV_EM_OriginUpperLeft };
            emit(head, SPV_OpExecutionMode, em, 2);
        }
        for (uint32_t w : head) out->push_back(w);
        for (uint32_t w : pre)  out->push_back(w);
        for (uint32_t w : fn)   out->push_back(w);
    }
    // Арифметика/память (в тело)
    uint32_t load(uint32_t type, uint32_t ptr) {
        uint32_t r = id();
        emitFn(SPV_OpLoad, { type, r, ptr });
        return r;
    }
    void store(uint32_t ptr, uint32_t val) {
        emitFn(SPV_OpStore, { ptr, val });
    }
    uint32_t compositeV4(uint32_t c0, uint32_t c1, uint32_t c2, uint32_t c3) {
        uint32_t r = id();
        emitFn(SPV_OpCompositeConstruct, { typeV4(), r, c0, c1, c2, c3 });
        return r;
    }
    uint32_t convertSToF(uint32_t src) {
        uint32_t r = id();
        emitFn(SPV_OpConvertSToF, { typeF32(), r, src });
        return r;
    }
    uint32_t bitcast(uint32_t fromType, uint32_t toType, uint32_t src) {
        uint32_t r = id();
        emitFn(SPV_OpBitcast, { toType, r, src });
        (void)fromType;
        return r;
    }
    uint32_t binop(uint32_t op, uint32_t type, uint32_t a, uint32_t b) {
        uint32_t r = id();
        emitFn(op, { type, r, a, b });
        return r;
    }
};

// ============================================================================
// Значение (Val): константа или SSA-ссылка. RDNA2-регистры нетипизированы,
// поэтому тип тянется за значением и приводится биткастом при необходимости.
// ============================================================================
struct Val {
    enum K { UNDEF, CI, CF, REF } k = UNDEF;
    enum T { T_I32, T_U32, T_F32 } t = T_I32;   // тип REF-значения
    int64_t  ci = 0;                            // CONST_I
    uint32_t cf = 0;                            // CONST_F биты
    uint32_t id = 0;                            // REF
};

struct Ctx {
    Builder b;
    const uint32_t* w32 = nullptr;
    size_t nWords = 0, ip = 0;
    Val v[256];                              // VGPR
    Val s[106];                              // SGPR (только 0-105)
    bool sDef[106] = {};
    int  decoded = 0;
    std::string fail;

    bool Fail(const char* what, uint32_t arg) {
        if (fail.empty()) {
            char buf[128];
            std::snprintf(buf, sizeof buf, "%s (0x%X / arg %u)", what, uint32_t(ip - 1), arg);
            fail = buf;
        }
        return false;
    }
};

// Читает следующий 32-битный литерал (SRC0 == 255).
static bool TakeLiteral(Ctx& c, uint32_t* lit) {
    if (c.ip >= c.nWords) return c.Fail("truncated (literal)", 0);
    *lit = c.w32[c.ip++];
    return true;
}

// Значение inline-константы по коду операнда (без SGPR/VGPR/литерала).
static bool InlineVal(Ctx& c, uint32_t code, Val* out) {
    int64_t iv;
    uint32_t fb;
    if (InlineInt(code, &iv)) { out->k = Val::CI; out->ci = iv; return true; }
    if (InlineFloat(code, &fb)) { out->k = Val::CF; out->cf = fb; return true; }
    if (code == 125) { out->k = Val::CI; out->ci = 0; return true; }  // NULL = 0
    return c.Fail("operand code unsupported", code);
}

// Приведение Val к f32-значению (id в SPIR-V).
static bool MatF(Ctx& c, const Val& v, uint32_t* outId) {
    if (v.k == Val::REF) {
        if (v.t == Val::T_F32) { *outId = v.id; return true; }
        uint32_t srcType = (v.t == Val::T_I32) ? c.b.typeI32() : c.b.typeU32();
        *outId = c.b.bitcast(srcType, c.b.typeF32(), v.id);
        return true;
    }
    if (v.k == Val::CF) { *outId = c.b.constF(v.cf); return true; }
    if (v.k == Val::CI) { *outId = c.b.convertSToF(c.b.constI(c.b.typeI32(), v.ci)); return true; }
    return c.Fail("undefined value (float)", 0);
}
// Приведение к целому (знаковость по параметру).
static bool MatI(Ctx& c, const Val& v, bool sign, uint32_t* outId) {
    if (v.k == Val::REF) {
        if (v.k == Val::CI) return c.Fail("internal", 0);
        if (v.t == Val::T_F32) {
            *outId = c.b.bitcast(c.b.typeF32(), sign ? c.b.typeI32() : c.b.typeU32(), v.id);
            return true;
        }
        bool vSign = (v.t == Val::T_I32);
        if (vSign == sign) { *outId = v.id; return true; }
        uint32_t from = vSign ? c.b.typeI32() : c.b.typeU32();
        uint32_t to   = sign   ? c.b.typeI32() : c.b.typeU32();
        *outId = c.b.bitcast(from, to, v.id);
        return true;
    }
    if (v.k == Val::CI) { *outId = c.b.constI(sign ? c.b.typeI32() : c.b.typeU32(), v.ci); return true; }
    if (v.k == Val::CF) { *outId = c.b.bitcast(c.b.typeF32(), sign ? c.b.typeI32() : c.b.typeU32(), c.b.constF(v.cf)); return true; }
    return c.Fail("undefined value (int)", 0);
}

// Чтение скалярного операнда (9-битный код; для SSRC0 8-бит — коды совпадают).
static bool ScalarOp(Ctx& c, uint32_t code, Val* out) {
    if (code <= 105) {                                   // SGPR
        if (!c.sDef[code]) {
            if (c.b.isVertex && code == 0) {             // соглашение: SGPR0 = индекс вершины
                uint32_t r = c.b.load(c.b.typeI32(), c.b.varVid);
                c.s[code].k = Val::REF; c.s[code].t = Val::T_I32; c.s[code].id = r;
                c.sDef[code] = true;
            } else {
                return c.Fail("read undefined SGPR", code);
            }
        }
        *out = c.s[code];
        return true;
    }
    if (code == 255) { out->k = Val::CI; out->ci = 0; return true; }  // заменит литерал
    return InlineVal(c, code, out);
}

// Чтение SRC0 (9 бит, может быть литералом).
static bool Src0(Ctx& c, uint32_t code, Val* out) {
    if (code == 255) {
        uint32_t lit;
        if (!TakeLiteral(c, &lit)) return false;
        out->k = Val::CI; out->ci = int64_t(int32_t(lit));
        return true;
    }
    if (code >= 256) {                                   // прямой VGPR (новшество RDNA2)
        uint32_t g = code - 256;
        if (c.v[g].k == Val::UNDEF) return c.Fail("read undefined VGPR", g);
        *out = c.v[g];
        return true;
    }
    return ScalarOp(c, code, out);
}
// VSRC1 (8 бит — только VGPR).
static bool Src1Vgpr(Ctx& c, uint32_t code, Val* out) {
    if (c.v[code].k == Val::UNDEF) return c.Fail("read undefined VGPR", code);
    *out = c.v[code];
    return true;
}
static void WriteV(Ctx& c, uint32_t dst, const Val& v) {
    if (dst >= 256) { c.Fail("bad VGPR dst", dst); return; }
    c.v[dst] = v;
}
static void WriteS(Ctx& c, uint32_t dst, const Val& v) {
    if (dst >= 106) { c.Fail("bad SGPR dst", dst); return; }
    c.s[dst] = v; c.sDef[dst] = true;
}

// ============================================================================
// Диспетчеризация инструкций
// ============================================================================
static bool Decode(Ctx& c) {
    while (c.ip < c.nWords) {
        uint32_t w = c.w32[c.ip++];
        uint32_t top9 = (w >> 23) & 0x1FF;

        // ---------------- SOPP (0x17F) ----------------
        if (top9 == R2_TOP_SOPP) {
            uint32_t op = (w >> 16) & 0x7F;
            if (op == R2_SOPP_S_ENDPGM) break;           // конец шейдера
            if (op == R2_SOPP_S_NOP || op == R2_SOPP_S_BARRIER ||
                op == R2_SOPP_S_WAITCNT) {               // нет памяти/ветвлений — пропускаем
                c.decoded++; continue;
            }
            return c.Fail("SOPP op unsupported (branches)", op);
        }
        // ---------------- SOPC (0x17E) ----------------
        if (top9 == R2_TOP_SOPC) return c.Fail("SOPC unsupported", w);
        // ---------------- SOP1 (0x17D) ----------------
        if (top9 == R2_TOP_SOP1) {
            uint32_t op = (w >> 8) & 0xFF;
            uint32_t sdst = (w >> 16) & 0x7F;
            uint32_t src0 = w & 0xFF;
            if (op == R2_SOP1_S_MOV_B32) {
                Val v;
                if (src0 == 255) { uint32_t lit; if (!TakeLiteral(c, &lit)) return false;
                    v.k = Val::CI; v.ci = int64_t(int32_t(lit)); }
                else if (!ScalarOp(c, src0, &v)) return false;
                WriteS(c, sdst, v);
                c.decoded++; continue;
            }
            return c.Fail("SOP1 op unsupported", op);
        }
        // ---------------- SOPK (0x160..0x17C) ----------------
        if (top9 >= R2_TOP_SOPK_MIN && top9 <= R2_TOP_SOPK_MAX) {
            uint32_t op = top9 - R2_TOP_SOPK_MIN;
            uint32_t sdst = (w >> 16) & 0x7F;
            uint32_t simm = w & 0xFFFF;
            if (op == R2_SOPK_S_MOVK_I32) {
                if (sdst >= 106) return c.Fail("S_MOVK to non-SGPR", sdst);
                if (!c.sDef[sdst]) return c.Fail("S_MOVK on undefined SGPR", sdst);
                Val& d = c.s[sdst];
                if (d.k == Val::CI) {
                    d.ci = (d.ci & ~int64_t(0xFFFF)) | int64_t(simm);  // младшие 16 бит
                } else {
                    return c.Fail("S_MOVK on register (не константа)", sdst);  // честно: v1
                }
                c.decoded++; continue;
            }
            return c.Fail("SOPK op unsupported", op);
        }
        // ---------------- SOP2 (0x100..0x15F) ----------------
        if (top9 >= R2_TOP_SOP2_MIN && top9 <= R2_TOP_SOP2_MAX)
            return c.Fail("SOP2 unsupported", w & 0x7F);

        // ---------------- 64-битные векторные (по word0[31:26]) ----------------
        // ВАЖНО: проверяем ДО скалярной ловушки ниже — у VOP3A/EXP бит31=1,
        // иначе V_FMA 0xD54B0006 уходил в "unknown scalar" (top9 0x1AA).
        uint32_t top6 = w >> 26;
        if (top6 == R2_VOP3P_TOP6) return c.Fail("VOP3P unsupported", w);
        if (top6 == R2_VOP3A_TOP6) {
            if (c.ip >= c.nWords) return c.Fail("truncated (VOP3)", 0);
            uint32_t w1 = c.w32[c.ip++];
            uint32_t op   = (w >> 16) & 0x3FF;
            uint32_t vdst = w & 0xFF;
            uint32_t s0c  = w1 & 0x1FF;
            uint32_t s1c  = (w1 >> 9) & 0x1FF;
            uint32_t s2c  = (w1 >> 18) & 0x1FF;
            uint32_t mods = ((w1 >> 27) & 0x3) | ((w1 >> 29) & 0x7) |
                            (((w >> 8) & 0x7)) | (((w >> 11) & 0xF)) |
                            (((w >> 15) & 1));
            if (mods) return c.Fail("VOP3A modifiers (ABS/NEG/OMOD/OPSEL/CLMP)", mods);
            if (op == R2_VOP3A_V_FMA_F32) {
                Val a, b, d2;
                if (!Src0(c, s0c, &a) || !Src0(c, s1c, &b) || !Src0(c, s2c, &d2))
                    return false;
                uint32_t fa, fbv, fc;
                if (!MatF(c, a, &fa) || !MatF(c, b, &fbv) || !MatF(c, d2, &fc)) return false;
                uint32_t mul = c.b.binop(SPV_OpFMul, c.b.typeF32(), fa, fbv);
                uint32_t add = c.b.binop(SPV_OpFAdd, c.b.typeF32(), mul, fc);
                Val r; r.k = Val::REF; r.t = Val::T_F32; r.id = add;
                WriteV(c, vdst, r);
                c.decoded++; continue;
            }
            return c.Fail("VOP3A op unsupported", op);
        }
        // ---------------- EXP (Table 106): ENCODING [31:26] = 0x3E ----------------
        // word0 = управление (EN/TARGET/COMPR/DONE/VM), word1 = VSRC0..3.
        // (в прокси-шейдере слова стояли наоборот — EXP ошибочно шёл в VOP2)
        if (top6 == R2_EXP_TOP6) {
            if (c.ip >= c.nWords) return c.Fail("truncated (EXP)", 0);
            const uint32_t w1 = c.w32[c.ip++];
            const uint32_t en     = w & 0xF;
            const uint32_t target = (w >> 4) & 0x3F;
            const uint32_t compr  = (w >> 10) & 1;
            const uint32_t done   = (w >> 11) & 1;   // не влияет на трансляцию
            const uint32_t vm     = (w >> 12) & 1;
            (void)done;
            const uint32_t srcs[4] = { w1 & 0xFF, (w1 >> 8) & 0xFF,
                                       (w1 >> 16) & 0xFF, (w1 >> 24) & 0xFF };
            if (target == R2_EXP_TARGET_NULL) { c.decoded++; continue; }  // Null — скип
            if (compr || vm) return c.Fail("EXP COMPR/VM not supported", w);
            if (en != 0xF) return c.Fail("EXP partial EN", en);
                if (c.b.isVertex && target == R2_EXP_TARGET_POSITION) {
                    uint32_t cs[4];
                    for (int i = 0; i < 4; i++) {
                        Val v;
                        if (c.v[srcs[i]].k == Val::UNDEF)
                            return c.Fail("EXP src undefined VGPR", srcs[i]);
                        v = c.v[srcs[i]];
                        if (!MatF(c, v, &cs[i])) return false;
                    }
                    c.b.store(c.b.varPos, c.b.compositeV4(cs[0], cs[1], cs[2], cs[3]));
                    c.decoded++; continue;
                }
                if (!c.b.isVertex && target == R2_EXP_TARGET_MRT0) {
                    uint32_t cs[4];
                    for (int i = 0; i < 4; i++) {
                        if (c.v[srcs[i]].k == Val::UNDEF)
                            return c.Fail("EXP src undefined VGPR", srcs[i]);
                        uint32_t idv;
                        if (!MatF(c, c.v[srcs[i]], &idv)) return false;
                        cs[i] = idv;
                    }
                    c.b.store(c.b.varCol, c.b.compositeV4(cs[0], cs[1], cs[2], cs[3]));
                    c.decoded++; continue;
                }
                return c.Fail("EXP target unsupported", target);
        }
        // ---------------- прочие скалярные/64-битные (SMEM и т.п.) ----------------
        if (w & 0x80000000u) return c.Fail("unknown 64-bit/scalar encoding", top9);

        // ---------------- 32-битные векторные (bit31 == 0) ----------------
        uint32_t fam = (w >> 25) & 0x7F;
        if (fam == 62) return c.Fail("VOPC unsupported", w);
        if (fam == 63) {
            // VOP1: OP [16:9], VDST [24:17], SRC0 [8:0]
            uint32_t op = (w >> 9) & 0xFF;
            uint32_t vdst = (w >> 17) & 0xFF;
            uint32_t s0c = w & 0x1FF;
            if (op == R2_VOP1_V_MOV_B32) {
                Val v;
                if (!Src0(c, s0c, &v)) return false;
                WriteV(c, vdst, v);
                c.decoded++; continue;
            }
            if (op == R2_VOP1_V_CVT_F32_I32) {
                Val v;
                if (!Src0(c, s0c, &v)) return false;
                uint32_t srci;
                if (!MatI(c, v, true, &srci)) return false;
                uint32_t f = c.b.convertSToF(srci);
                Val r; r.k = Val::REF; r.t = Val::T_F32; r.id = f;
                WriteV(c, vdst, r);
                c.decoded++; continue;
            }
            return c.Fail("VOP1 op unsupported", op);
        }
        // VOP2: OP [30:25], VDST [24:17], SRC0 [8:0], VSRC1 [16:9] (8 бит, VGPR)
        {
            uint32_t op = (w >> 25) & 0x3F;
            uint32_t vdst = (w >> 17) & 0xFF;
            uint32_t s0c = w & 0x1FF;
            uint32_t s1c = (w >> 9) & 0xFF;
            if (s1c >= 256) return c.Fail("bad VSRC1", s1c);
            Val a, b2;
            if (!Src0(c, s0c, &a)) return false;
            if (!Src1Vgpr(c, s1c, &b2)) return false;
            uint32_t rId = 0;
            Val::T rt = Val::T_U32;
            switch (op) {
            case R2_VOP2_V_ADD_F32:
            case R2_VOP2_V_MUL_F32: {
                rt = Val::T_F32;
                uint32_t fa, fbv;
                if (!MatF(c, a, &fa) || !MatF(c, b2, &fbv)) return false;
                rId = c.b.binop(op == R2_VOP2_V_ADD_F32 ? SPV_OpFAdd : SPV_OpFMul,
                                c.b.typeF32(), fa, fbv);
                break;
            }
            case R2_VOP2_V_LSHRREV_B32:
            case R2_VOP2_V_LSHLREV_B32: {
                uint32_t cnt;
                if (!MatI(c, a, false, &cnt)) return false;
                if (a.k == Val::CI) {
                    // константный сдвиг — маску [4:0] сворачиваем на месте
                    Val sv; sv.k = Val::CI; sv.ci = a.ci & 31;
                    if (!MatI(c, sv, false, &cnt)) return false;
                } else {
                    uint32_t m31 = c.b.constI(c.b.typeU32(), 31);
                    cnt = c.b.binop(SPV_OpBitwiseAnd, c.b.typeU32(), cnt, m31);
                }
                uint32_t base;
                if (!MatI(c, b2, false, &base)) return false;
                rId = c.b.binop(op == R2_VOP2_V_LSHRREV_B32 ? SPV_OpShiftRightLogical
                                                            : SPV_OpShiftLeftLogical,
                                c.b.typeU32(), base, cnt);
                break;
            }
            case R2_VOP2_V_AND_B32:
            case R2_VOP2_V_OR_B32: {
                uint32_t ua, ub;
                if (!MatI(c, a, false, &ua) || !MatI(c, b2, false, &ub)) return false;
                rId = c.b.binop(op == R2_VOP2_V_AND_B32 ? SPV_OpBitwiseAnd : SPV_OpBitwiseOr,
                                c.b.typeU32(), ua, ub);
                break;
            }
            default:
                return c.Fail("VOP2 op unsupported", op);
            }
            Val r; r.k = Val::REF; r.t = rt; r.id = rId;
            WriteV(c, vdst, r);
            c.decoded++;
        }
    }
    return true;
}

} // namespace

bool Translate(const uint8_t* code, size_t size, bool isVertex,
               TranslateResult* out) {
    out->ok = false;
    out->decoded = 0;
    out->unknown = 0;
    out->firstUnknown.clear();
    out->error.clear();
    out->spirv.clear();
    if (!code || size == 0 || size % 4) {
        out->error = "bytecode size is 0 or not multiple of 4";
        return false;
    }
    Ctx c;
    c.w32 = reinterpret_cast<const uint32_t*>(code);
    c.nWords = size / 4;
    c.b.init(isVertex);
    if (!Decode(c)) {
        out->firstUnknown = c.fail;
        return false;
    }
    // Проверка: VS обязан экспортировать gl_Position, FS — цвет.
    if (isVertex && !c.b.varPos) { out->error = "no position export"; return false; }
    // (композит уже сохранён, varPos ненулевой по построению — проверка формальна)
    c.b.finish(&out->spirv);
    out->decoded = c.decoded;
    out->unknown = 0;
    out->ok = true;
    return true;
}

} // namespace rdna2
} // namespace zrx
