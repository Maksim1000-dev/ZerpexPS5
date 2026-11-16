// ============================================================================
// ZerpexPS5 — фаза 5.1 (шаг 1): разведка PM4 (реализация)
// Формат пакета type-3 (GCN/PS4/PS5):
//   header dword: [31:30]=3 (тип), [25]=predication, [23:16]=?(res),
//                 [15:8]=опкод IT_*, [13:0]=count в dword'ах payload.
//   count==0x3FFF — переменная длина: следующий dword несёт реальный счётчик.
//   type-2 = NOP-филлер (просто пропускаем dword).
// Payload SET_*_REG: [base_reg_offset, v1..vn], count = 1+n.
// Payload INDIRECT_BUFFER(_CONST): [addr_lo, addr_hi, size_dwords|флаги].
// ============================================================================
#include "pm4.h"

#include <cstdio>
#include <map>
#include <string>

namespace zrx { namespace pm4 {

// --- Имена опкодов (по открытым GCN-документам; при расхождении с реальным
// --- дампом правим здесь — формат печати честный: неизвестное = hex).
static const char* OpName(uint32_t op) {
    switch (op) {
    case 0x10: return "NOP";
    case 0x26: return "WAIT_REG_MEM";
    case 0x33: return "INDIRECT_BUFFER_CONST";
    case 0x3F: return "INDIRECT_BUFFER";
    case 0x46: return "EVENT_WRITE";
    case 0x47: return "EVENT_WRITE_EOP";
    case 0x58: return "ACQUIRE_MEM";
    case 0x68: return "SET_CONFIG_REG";
    case 0x73: return "SET_CONTEXT_REG";
    case 0x76: return "SET_SH_REG";
    case 0x97: return "NUM_INSTANCES";
    case 0xB9: return "DRAW_INDEX_AUTO";
    default:   return nullptr;
    }
}

static void PrintPayload(const uint32_t* p, uint32_t n) {
    printf(" [");
    const uint32_t show = n < 6 ? n : 6;
    for (uint32_t k = 0; k < show; ++k)
        printf("%s%08X", k ? " " : "", p[k]);
    if (n > show) printf(" ... +%u", n - show);
    printf("]");
}

static const uint32_t kMaxPackets = 40;   // печатаем первые N пакетов уровня
static const int      kMaxDepth   = 2;    // глубина вложенных INDIRECT_BUFFER

void DumpStream(const char* label, const uint32_t* d, uint32_t n,
                int depth, ResolveFn resolve, void* user, Frame* frame) {
    if (!d || n == 0) {
        printf("[PM4] %s: пустой буфер\n", label);
        fflush(stdout);
        return;
    }
    if (depth == 0)
        printf("[PM4] %s: %u dword (%u байт)\n", label, n, n * 4u);

    const char* indent = depth > 0 ? "| " : "";
    uint32_t i = 0, printed = 0, filler = 0, errors = 0, packets = 0;
    std::map<uint32_t, uint32_t> perOp;    // опкод -> сколько раз

    while (i < n) {
        const uint32_t hdr = d[i];
        const uint32_t type = hdr >> 30;

        if (type == 2) {                    // type-2: NOP-филлер
            ++filler;
            ++i;
            continue;
        }
        if (type != 3) {                    // типы 0/1 — редкие, честно как hex
            if (errors < 3)
                printf("[PM4]   %s? тип %u (не type-3) @ dword %u: %08X\n",
                       indent, type, i, hdr);
            ++errors;
            ++packets;
            ++i;
            continue;
        }

        const uint32_t op  = (hdr >> 8) & 0xFF;
        uint32_t cnt       =  hdr & 0x3FFF;
        ++i;                                // заголовок прочли
        if (cnt == 0x3FFF) {                // переменная длина
            if (i >= n) {
                printf("[PM4]   %s? обрезанный заголовок переменной длины\n", indent);
                ++errors;
                break;
            }
            cnt = d[i++];
        }
        if (i + cnt > n) {
            printf("[PM4]   %s? ОБРЕЗАННЫЙ пакет op=0x%02X count=%u — остаётся %u\n",
                   indent, op, cnt, n - i);
            ++errors;
            ++packets;
            break;
        }

        const uint32_t* payload = d + i;
        const char* nm = OpName(op);
        ++packets;
        ++perOp[op];

        if (printed < kMaxPackets || depth > 0) {
            if (nm)
                printf("[PM4]   %sop=0x%02X %-22s count=%u", indent, op, nm, cnt);
            else
                printf("[PM4]   %sop=0x%02X (неизвестный)        count=%u", indent, op, cnt);
            if (cnt) PrintPayload(payload, cnt);
            printf("\n");
            ++printed;
        }

        // Фаза 5.2: DRAW_INDEX_AUTO — счётчик вершин в payload[0].
        // Пока это единственный источник «намерения нарисовать» — реальные
        // шейдеры/состояние появятся в 5.3, сейчас честный прокси-рендер.
        if (op == 0xB9 && cnt >= 1 && frame) {
            frame->hasDraw   = true;
            frame->drawCount = payload[0];
        }

        // Вложенный командный буфер: [addr_lo, addr_hi, size_dwords|флаги]
        if ((op == 0x33 || op == 0x3F) && cnt >= 3 && depth < kMaxDepth) {
            const uint64_t base = ((uint64_t)payload[1] << 32) | payload[0];
            const uint32_t sub  = payload[2] & ~0xFu;   // младшие биты — флаги
            printf("[PM4]     %s-> вложенный буфер guest 0x%llX (%u dword)\n",
                   indent, (unsigned long long)base, sub);
            if (resolve && sub) {
                const uint32_t* sd = resolve(base, (uint64_t)sub * 4, user);
                if (sd)
                    DumpStream("вложенный IB", sd, sub, depth + 1, resolve, user, frame);
                else
                    printf("[PM4]     %s-> память не мапнута, вложенный не разбираю\n",
                           indent);
            }
        }

        i += cnt;
    }

    std::string ops;
    for (const auto& kv : perOp) {
        char b[40];
        snprintf(b, sizeof(b), "%s0x%02X x%u", ops.empty() ? "" : ", ", kv.first, kv.second);
        ops += b;
    }
    printf("[PM4] %sитог: пакетов %u, NOP-филлеров %u, ошибок %u%s%s\n",
           indent, packets, filler, errors,
           ops.empty() ? "" : ", опкоды: ", ops.c_str());
    fflush(stdout);
}

} } // namespace zrx::pm4
