// SPDX-FileCopyrightText: 2022-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2019-2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include "simatic.h"
#include <stdio.h>
#include <time.h>

#if __WINDOWS__
#define PFMT64x "I64x"
#else
#define PFMT64x "llx"
#endif

#define false 0
#define true  (!false)

#define INSTR_MASK_N(x)     ((x) & (0x0F))
#define INSTR_MASK_T(x)     ((x) & (0x70))
#define INSTR_MASK_T_LOW(x) ((x) & (0x07))

#define INSTR_IS_BITLOGIC(x)   ((x) >= (0x10) && (x) <= (0x67))
#define INSTR_IS_BITLOGIC_N(x) ((x) >= (0x90) && (x) <= (0xE7))

#define INSTR_IS_BITLOGIC_MEM(x)    (INSTR_MASK_T_LOW((x)) != 0 && INSTR_MASK_T_LOW((x)) != 7 && (x) >= (0x31) && (x) <= (0x6E))
#define INSTR_IS_BITLOGIC_MEM_N(x)  (INSTR_MASK_T_LOW((x)) != 0 && INSTR_MASK_T_LOW((x)) != 7 && (x) >= (0xB1) && (x) <= (0xEE))
#define INSTR_IS_BITLOGIC_MEM_IO(x) (((x) & 0xF) >= (0x9))

#define INSTR_IS_79(x)   ((x) >= (0x10) && (x) <= (0x6D))
#define INSTR_IS_79_N(x) ((x) >= (0x90) && (x) <= (0xED))

#define INSTR_IS_7E(x) ((x) >= (0x01) && (x) <= (0x67))

#define INSTR_IS_MEM(x)    ((x) >= (0x30) && (x) <= (0x6E))
#define INSTR_IS_MEM_N(x)  ((x) >= (0xB0) && (x) <= (0xEE))
#define INSTR_IS_MEM_IO(x) (((x) & 0x0F) > (6))

#define S7_INVALID_JUMP (0xFFFFFFFFFFFFFFFFull)

typedef float ft32;
typedef double ft64;

#define BIN_FMT "%c%c%c%c%c%c%c%c"
#define BIN_BYTE(x) \
	(((x) & 0x80) ? '1' : '0'), \
		(((x) & 0x40) ? '1' : '0'), \
		(((x) & 0x20) ? '1' : '0'), \
		(((x) & 0x10) ? '1' : '0'), \
		(((x) & 0x08) ? '1' : '0'), \
		(((x) & 0x04) ? '1' : '0'), \
		(((x) & 0x02) ? '1' : '0'), \
		(((x) & 0x01) ? '1' : '0')

#define s7_instr(i, fmt, ...) snprintf(i->assembly, sizeof(i->assembly), fmt, ##__VA_ARGS__)

typedef struct {
	const ut8_t byte;
	const char *type;
} s7_type_t;

static const s7_type_t types_def[] = {
	{ 0x10, "I" },
	{ 0x20, "Q" },
	{ 0x30, "M" },
	{ 0x40, "DB" },
	{ 0x50, "DI" },
	{ 0x60, "L" },
	{ 0xFF, NULL }
};

static const s7_type_t types_x[] = {
	{ 0x10, "I" },
	{ 0x20, "Q" },
	{ 0x30, "M" },
	{ 0x40, "DBX" },
	{ 0x50, "DIX" },
	{ 0x60, "L" },
	{ 0xFF, NULL }
};

static const s7_type_t types_w[] = {
	{ 0x00, "PIW" },
	{ 0x10, "IW" },
	{ 0x20, "QW" },
	{ 0x30, "MW" },
	{ 0x40, "DBW" },
	{ 0x50, "DIW" },
	{ 0x60, "LW" },
	{ 0xFF, NULL }
};

static const s7_type_t types_d[] = {
	{ 0x00, "PID" },
	{ 0x10, "ID" },
	{ 0x20, "QD" },
	{ 0x30, "MD" },
	{ 0x40, "DBD" },
	{ 0x50, "DID" },
	{ 0x60, "LD" },
	{ 0xFF, NULL }
};

static const s7_type_t types_b[] = {
	{ 0x00, "PIB" },
	{ 0x10, "IB" },
	{ 0x20, "QB" },
	{ 0x30, "MB" },
	{ 0x40, "DBB" },
	{ 0x50, "DIB" },
	{ 0x60, "LB" },
	{ 0xFF, NULL }
};

static inline const char *s7_type(ut8_t T, const s7_type_t *types) {
	while (types->type) {
		if (T == types->byte) {
			return types->type;
		}
		types++;
	}
	return "?";
}

static inline const char *s7_mem_type(ut8_t T) {
	T = INSTR_MASK_T(T);
	return (T == 0x30 ? "MD" : (T == 0x40 ? "DBD" : (T == 0x50 ? "DID" : (T == 0x60 ? "LD" : NULL))));
}

static inline ut16_t s7_ut16(const ut8_t *buffer) {
	return ((buffer[0] << 8) | buffer[1]);
}

static inline ut32_t s7_ut32(const ut8_t *buffer) {
	ut32_t x = ((buffer[0] << 24) | (buffer[1] << 16));
	return x | ((buffer[2] << 8) | buffer[3]);
}

static inline void s7_print_bin32(const char *prefix, const ut8_t *buffer, S7Instr *instr) {
	char bin[34];
	snprintf(bin, sizeof(bin), "" BIN_FMT "" BIN_FMT "" BIN_FMT "" BIN_FMT, BIN_BYTE(buffer[0]), BIN_BYTE(buffer[1]), BIN_BYTE(buffer[2]), BIN_BYTE(buffer[3]));
	ut64_t i;
	for (i = 0; i < 31; ++i) {
		if (bin[i] != '0') {
			break;
		}
	}
	s7_instr(instr, "%s%s", prefix, &bin[i]);
}

static inline void s7_print_bin16(const char *prefix, const ut8_t *buffer, S7Instr *instr) {
	char bin[18];
	snprintf(bin, sizeof(bin), "" BIN_FMT "" BIN_FMT, BIN_BYTE(buffer[0]), BIN_BYTE(buffer[1]));
	ut64_t i;
	for (i = 0; i < 15; ++i) {
		if (bin[i] != '0') {
			break;
		}
	}
	s7_instr(instr, "%s%s", prefix, &bin[i]);
}

static int s7_decode_bitlogic(const char *zero_op, const char *memory_op, const char *io_op, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (buffer[0] == 0x00) {
		s7_instr(instr, zero_op);
		return 2;
	} else if (size > 2) {
		if (INSTR_IS_BITLOGIC(buffer[0])) {
			ut16_t value = s7_ut16(buffer + 1);
			ut8_t N = INSTR_MASK_N(buffer[0]);
			// if (INSTR_MASK_T (buffer[0]) < 0x40 && value < 256) {
			//	return -1;
			// }
			const char *type = s7_type(INSTR_MASK_T(buffer[0]), types_x);
			s7_instr(instr, "%s %s %u.%u", memory_op, type, value, N);
			return 4;
		} else if (io_op && INSTR_IS_BITLOGIC_N(buffer[0])) { // io_op might be NULL, because some might not have BITLOGIC_N
			ut16_t value = s7_ut16(buffer + 1);
			ut8_t N = INSTR_MASK_N(buffer[0]);
			// if (INSTR_MASK_T (buffer[0]) < 0x40 && value < 256) {
			//	return -1;
			// }
			const char *type = s7_type(INSTR_MASK_T(buffer[0]), types_x);
			s7_instr(instr, "%s %s %u.%u", io_op, type, value, N);
			return 4;
		}
	}
	return -1;
}

static int s7_decode_byte(const char *op, const char *prefix, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	(void)size;
	ut8_t N = buffer[0];
	s7_instr(instr, "%s %s%u", op, prefix, N);
	return 2;
}

static int s7_decode_byte_s(const char *op, const char *suffix, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	(void)size;
	ut8_t N = buffer[0];
	s7_instr(instr, "%s %u%s", op, N, suffix);
	return 2;
}

static int s7_decode_4bit(const char *op, bool_t high, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	(void)size;
	ut8_t N = high ? (buffer[0] >> 4) : (buffer[0] & 0x0F);
	s7_instr(instr, "%s %u", op, N);
	return 2;
}

static int s7_decode_byte_signed(const char *op, const char *type_pos, const char *type_neg, const char *suffix, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	(void)size;
	ut8_t N = (ut8_t)buffer[0];
	if (N > 0x7F) {
		N &= 0x7F;
		s7_instr(instr, "%s %s %u%s", op, type_neg, N, suffix);
	} else {
		s7_instr(instr, "%s %s %u%s", op, type_pos, N, suffix);
	}
	return 2;
}

static int s7_decode_cmp(const char *type, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	(void)size;
	switch (buffer[0]) {
	case 0x20:
		s7_instr(instr, ">%s", type);
		break;
	case 0x40:
		s7_instr(instr, "<%s", type);
		break;
	case 0x60:
		s7_instr(instr, "<>%s", type);
		break;
	case 0x80:
		s7_instr(instr, "==%s", type);
		break;
	case 0xA0:
		s7_instr(instr, ">=%s", type);
		break;
	case 0xC0:
		s7_instr(instr, "<=%s", type);
		break;
	default:
		return -1;
	}
	return 2;
}

static int s7_decode_lit16(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (size < 2) {
		return -1;
	}
	ut16_t value = s7_ut16(buffer + 1);
	switch (buffer[0]) {
	case 0x02:
		s7_print_bin16("L 2#", buffer + 1, instr);
		break;
	case 0x03:
		s7_instr(instr, "L %d", ((st16_t)value));
		break;
	case 0x05:
		if (buffer[1]) {
			s7_instr(instr, "L '%c%c'", buffer[1], buffer[2]);
		} else {
			s7_instr(instr, "L '%c'", buffer[2]);
		}
		break;
	case 0x06:
		s7_instr(instr, "L B#(%02u, %02u)", buffer[1], buffer[2]);
		break;
	case 0x07:
		s7_instr(instr, "L W#16#%x", value);
		break;
	case 0x08:
		if (value < 0x1000) {
			s7_instr(instr, "L C#%x", value);
		} else {
			return -1;
		}
		break;
	case 0x0A: {
		// MIN L D#1990-01-01 | MAX L D#2168-12-31
		time_t rawtime = (value * 86400) + 631152000;
		struct tm *ptm = localtime(&rawtime);
		int year = 1900 + ptm->tm_year;
		int month = ptm->tm_mon + 1;
		int day = ptm->tm_mday;
		s7_instr(instr, "L D#%d-%d-%d", year, month, day);
	} break;
	case 0x0C: {
		// S5T#0MS -> S5T#2H46M30S
		if ((value & 0xf000) > 0x3000 || value > 0x3999) {
			return -1;
		}
		st32_t ms = 0;
		st32_t secs = 0;
		st32_t mins = 0;
		st32_t hours = 0;
		/* S5TIME
		 *  [--yy aaaa bbbb cccc]
		 * 15                   0
		 * yy = 00 -> 10 ms - 9 s 990 ms         (time base 10  ms)
		 * yy = 01 -> 100 ms - 1 min 39 s 900 ms (time base 100 ms)
		 * yy = 10 -> 1 s - 16 min 39 s          (time base 1    s)
		 * yy = 11 -> 10 s - 2 hr 46 min 30 s    (time base 10   s)
		 * 0000aaaabbbbcccc is time value in binary-coded decimal format
		 */
		ms = (((value & 0x0F00) >> 8) * 100) + (((value & 0xF0) >> 4) * 10) + (value & 0x0F);
		if ((value & 0xf000) == 0x3000) {
			ms *= 10000;
		} else if ((value & 0xf000) == 0x2000) {
			ms *= 1000;
		} else if ((value & 0xf000) == 0x1000) {
			ms *= 100;
		} else {
			ms *= 10;
		}

		if (ms >= 3600000) {
			hours = ms / 3600000;
			ms -= (hours * 3600000);
		}

		if (ms >= 60000) {
			mins = ms / 60000;
			ms -= (mins * 60000);
		}

		if (ms >= 1000) {
			secs = ms / 1000;
			ms -= (secs * 1000);
		}

		int p = s7_instr(instr, "L S5T#");
		if (hours > 0) {
			p += snprintf(instr->assembly + p, sizeof(instr->assembly) - p, "%dH", hours);
		}
		if (mins > 0) {
			p += snprintf(instr->assembly + p, sizeof(instr->assembly) - p, "%dM", mins);
		}
		if (secs > 0) {
			p += snprintf(instr->assembly + p, sizeof(instr->assembly) - p, "%dS", secs);
		}
		if ((ms > 0 && ((value & 0xf000) < 0x2000)) || (hours < 1 && mins < 1 && secs < 1)) {
			snprintf(instr->assembly + p, sizeof(instr->assembly) - p, "%dMS", ms);
		}
		return 4;
	} break;
	default:
		return -1;
	}
	return 4;
}

static inline const char *s7_memory_loc(ut8_t byte) {
	/*
		80h | PI/PQ | Periphery input/output
		81h | I     | Input
		82h | Q     | Output
		83h | M     | Bit memory
		84h | DB    | Data block
		85h | DI    | Instance data block
		86h | L     | Local Stack
		87h | V     | Previous Local Stack
	*/
	switch (byte) {
	case 0x00: return "";
	case 0x80: return "PI/PQ";
	case 0x81: return "I";
	case 0x82: return "Q";
	case 0x83: return "M";
	case 0x84: return "DB";
	case 0x85: return "DI";
	case 0x86: return "L";
	case 0x87: return "V";
	default:
		// eprintf ("missing area 0x%02x (%u)\n", byte, byte);
		break;
	}
	return NULL;
}

static int s7_decode_lit32(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (size < 5) {
		return -1;
	}
	ut32_t value = s7_ut32(buffer + 1);
	switch (buffer[0]) {
	case 0x01: // REAL NUMBER
	{
		ft32 *f = (ft32 *)&value;
		s7_instr(instr, "L %.6f", (*f));
	} break;
	case 0x02:
		s7_print_bin32("L 2#", buffer + 1, instr);
		break;
	case 0x03:
		s7_instr(instr, "L L#%d", ((st32_t)value));
		break;
	case 0x04: {
		const char *loc = s7_memory_loc(buffer[1]);
		if (!loc || (buffer[2] & 0xF8)) {
			return -1;
		}
		ut8_t bit_addr = buffer[2] & 7;
		value &= 0xFFFF;
		s7_instr(instr, "L P#%s%u.%u", loc, value, bit_addr);
	} break;
	case 0x05:
		if (buffer[1] && buffer[2] && buffer[3]) {
			s7_instr(instr, "L '%c%c%c%c'", buffer[1], buffer[2], buffer[3], buffer[4]);
		} else if (buffer[2] && buffer[3]) {
			s7_instr(instr, "L '%c%c%c'", buffer[2], buffer[3], buffer[4]);
		} else if (buffer[3]) {
			s7_instr(instr, "L '%c%c'", buffer[3], buffer[4]);
		} else {
			s7_instr(instr, "L '%c'", buffer[4]);
		}
		break;
	case 0x06:
		s7_instr(instr, "L B#(%02u, %02u, %02u, %02u)", buffer[1], buffer[2], buffer[3], buffer[4]);
		break;
	case 0x07:
		s7_instr(instr, "L DW#16#%x", value);
		break;
	case 0x09:
		s7_instr(instr, "L T#%uMS", value);
		break;
	case 0x0B: {
		ut32_t ms = value % 1000;
		ut32_t tsecs = value / 1000;
		ut32_t secs = tsecs % 60;
		ut32_t mins = (tsecs / 60) % 60;
		ut32_t hours = (tsecs / 3600);
		s7_instr(instr, "L TOD#%u:%u:%u.%u", hours, mins, secs, ms);
	} break;
	default:
		return -1;
	}
	return 6;
}

static int s7_decode_bitlogic_mem(const char *zero_op, bool_t zero_op_value, const char *memory_op, const char *io_op, const char *n_memory_op, const char *n_io_op,
	const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (buffer[0] == 0x00 && !zero_op_value) {
		s7_instr(instr, zero_op);
		return 2;
	} else if (size > 2) {
		if (buffer[0] == 0x00 && zero_op_value) {
			st16_t value = (st16_t)s7_ut16(buffer + 1);
			s7_instr(instr, "%s %d", zero_op, value);
			return 4;
		}
		const char *mem_type = s7_mem_type(buffer[0]);
		ut16_t value = s7_ut16(buffer + 1);
		if (mem_type && INSTR_IS_BITLOGIC_MEM(buffer[0])) {
			const char *op = INSTR_IS_BITLOGIC_MEM_IO(buffer[0]) ? io_op : memory_op;
			const char *type = s7_type(INSTR_MASK_T(buffer[0] << 4), types_x);
			s7_instr(instr, "%s %s [%s %u]", op, type, mem_type, value);
			return 4;
		} else if (mem_type && INSTR_IS_BITLOGIC_MEM_N(buffer[0])) {
			const char *op = INSTR_IS_BITLOGIC_MEM_IO(buffer[0]) ? n_io_op : n_memory_op;
			if (!op) {
				return -1;
			}
			const char *type = s7_type(INSTR_MASK_T(buffer[0] << 4), types_x);
			s7_instr(instr, "%s %s [%s %u]", op, type, mem_type, value);
			return 4;
		}
	}
	return -1;
}

static int s7_decode_jump(const char *op, ut64_t addr, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (size > 2) {
		st16_t N = (st16_t)s7_ut16(buffer + 1);
		addr += N;
		instr->jump = addr;
		s7_instr(instr, "%s 0x%" PFMT64x, op, addr);
		return 4;
	}
	return -1;
}

typedef struct {
	ut8_t byte;
	const char *op;
} s7_static_t;

static int s7_decode_static(const s7_static_t *s, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	(void)size;
	while (s && s->op) {
		if (buffer[0] == s->byte) {
			s7_instr(instr, "%s", s->op);
			return 2;
		}
		s++;
	}
	return -1;
}

static int s7_decode_79(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (buffer[0] == 0x00) {
		s7_instr(instr, "+I");
		return 2;
	} else if (size > 2) {
		ut8_t op = buffer[0] & 0x07;
		ut8_t ar = (buffer[0] & 0x08) ? 2 : 1;
		ut16_t value = s7_ut16(buffer + 1);
		const char *type = s7_type(INSTR_MASK_T(buffer[0]), types_x);
		if (INSTR_IS_79(buffer[0])) {
			switch (op) {
			case 0x00:
				s7_instr(instr, "A %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x01:
				s7_instr(instr, "AN %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x02:
				s7_instr(instr, "O %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x03:
				s7_instr(instr, "ON %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x04:
				s7_instr(instr, "X %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x05:
				s7_instr(instr, "XN %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			default:
				return -1;
			}
		} else if (INSTR_IS_79_N(buffer[0])) {
			switch (op) {
			case 0x00:
				s7_instr(instr, "S %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x01:
				s7_instr(instr, "R %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x02:
				s7_instr(instr, "= %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x04:
				s7_instr(instr, "FP %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x05:
				s7_instr(instr, "FN %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			default:
				return -1;
			}
		}
	}
	return -1;
}

static inline const char *s7_type_7E(ut8_t T) {
	if (INSTR_MASK_T(T) == 0x00) {
		return INSTR_MASK_T_LOW(T) > 0x03 ? "PQ" : "PI";
	}
	T = INSTR_MASK_T(T);
	return (T == 0x10 ? "I" : (T == 0x20 ? "Q" : (T == 0x30 ? "M" : (T == 0x40 ? "DB" : (T == 0x50 ? "DI" : (T == 0x60 ? "L" : "?"))))));
}

static int s7_decode_7E(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (size > 2 && INSTR_IS_7E(buffer[0])) {
		ut8_t op = buffer[0] & 0x07;
		ut16_t value = s7_ut16(buffer + 1);
		const char *type = s7_type_7E(buffer[0]);
		switch (op) {
		case 0x01:
			s7_instr(instr, "L %sB %u", type, value);
			return 4;
		case 0x02:
			s7_instr(instr, "L %sW %u", type, value);
			return 4;
		case 0x03:
			s7_instr(instr, "L %sD %u", type, value);
			return 4;
		case 0x05:
			s7_instr(instr, "T %sB %u", type, value);
			return 4;
		case 0x06:
			s7_instr(instr, "T %sW %u", type, value);
			return 4;
		case 0x07:
			s7_instr(instr, "T %sD %u", type, value);
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

static int s7_decode_mem(const char *zero_op, const char *memory_op, const char *io_op, const s7_type_t *memory_type, const s7_type_t *io_type, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (buffer[0] == 0x00) {
		s7_instr(instr, zero_op);
		return 2;
	} else if (size > 2) {
		const char *mem_type = s7_mem_type(buffer[0]);
		ut16_t value = s7_ut16(buffer + 1);
		if (mem_type && INSTR_IS_MEM(buffer[0])) {
			const char *type = s7_type(INSTR_MASK_T(buffer[0] << 4), INSTR_IS_MEM_IO(buffer[0]) ? io_type : memory_type);
			s7_instr(instr, "%s %s [%s %u]", memory_op, type, mem_type, value);
			return 4;
		} else if (mem_type && INSTR_IS_MEM_N(buffer[0])) {
			const char *type = s7_type(INSTR_MASK_T(buffer[0] << 4), INSTR_IS_MEM_IO(buffer[0]) ? io_type : memory_type);
			s7_instr(instr, "%s %s [%s %u]", io_op, type, mem_type, value);
			return 4;
		}
	}
	return -1;
}

static int s7_decode_BE(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (size > 2 && buffer[0] >= 0x11 && buffer[0] <= 0x6F && (buffer[0] & 0x0F)) {
		ut8_t op = buffer[0] & 0x0F;
		ut16_t value = s7_ut16(buffer + 1);
		const char *type = s7_type(INSTR_MASK_T(buffer[0]), types_def);
		switch (op) {
		case 0x01:
			s7_instr(instr, "L %sB [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x02:
			s7_instr(instr, "L %sW [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x03:
			s7_instr(instr, "L %sD [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x05:
			s7_instr(instr, "T %sB [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x06:
			s7_instr(instr, "T %sW [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x07:
			s7_instr(instr, "T %sD [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x09:
			s7_instr(instr, "L %sB [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0A:
			s7_instr(instr, "L %sW [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0B:
			s7_instr(instr, "L %sD [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0D:
			s7_instr(instr, "T %sB [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0E:
			s7_instr(instr, "T %sW [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0F:
			s7_instr(instr, "T %sD [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

static int s7_decode_BF(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (buffer[0] == 0x00) {
		s7_instr(instr, ")");
		return 2;
	} else if (size > 2) {
		ut16_t value = s7_ut16(buffer + 1);
		switch (buffer[0]) {
		case 0x30:
			s7_instr(instr, "A T [MW %d]", value);
			return 4;
		case 0x31:
			s7_instr(instr, "AN T [MW %d]", value);
			return 4;
		case 0x32:
			s7_instr(instr, "O T [MW %d]", value);
			return 4;
		case 0x33:
			s7_instr(instr, "ON T [MW %d]", value);
			return 4;
		case 0x34:
			s7_instr(instr, "X T [MW %d]", value);
			return 4;
		case 0x35:
			s7_instr(instr, "XN T [MW %d]", value);
			return 4;
		case 0x36:
			s7_instr(instr, "L T [MW %d]", value);
			return 4;
		case 0x38:
			s7_instr(instr, "FR T [MW %d]", value);
			return 4;
		case 0x39:
			s7_instr(instr, "LC T [MW %d]", value);
			return 4;
		case 0x3A:
			s7_instr(instr, "SF T [MW %d]", value);
			return 4;
		case 0x3B:
			s7_instr(instr, "SE T [MW %d]", value);
			return 4;
		case 0x3C:
			s7_instr(instr, "SD T [MW %d]", value);
			return 4;
		case 0x3D:
			s7_instr(instr, "SS T [MW %d]", value);
			return 4;
		case 0x3E:
			s7_instr(instr, "SP T [MW %d]", value);
			return 4;
		case 0x3F:
			s7_instr(instr, "R T [MW %d]", value);
			return 4;
		case 0x40:
			s7_instr(instr, "A T [DBW %d]", value);
			return 4;
		case 0x41:
			s7_instr(instr, "AN T [DBW %d]", value);
			return 4;
		case 0x42:
			s7_instr(instr, "O T [DBW %d]", value);
			return 4;
		case 0x43:
			s7_instr(instr, "ON T [DBW %d]", value);
			return 4;
		case 0x44:
			s7_instr(instr, "X T [DBW %d]", value);
			return 4;
		case 0x45:
			s7_instr(instr, "XN T [DBW %d]", value);
			return 4;
		case 0x46:
			s7_instr(instr, "L T [DBW %d]", value);
			return 4;
		case 0x48:
			s7_instr(instr, "FR T [DBW %d]", value);
			return 4;
		case 0x49:
			s7_instr(instr, "LC T [DBW %d]", value);
			return 4;
		case 0x4A:
			s7_instr(instr, "SF T [DBW %d]", value);
			return 4;
		case 0x4B:
			s7_instr(instr, "SE T [DBW %d]", value);
			return 4;
		case 0x4C:
			s7_instr(instr, "SD T [DBW %d]", value);
			return 4;
		case 0x4D:
			s7_instr(instr, "SS T [DBW %d]", value);
			return 4;
		case 0x4E:
			s7_instr(instr, "SP T [DBW %d]", value);
			return 4;
		case 0x4F:
			s7_instr(instr, "R T [DBW %d]", value);
			return 4;
		case 0x50:
			s7_instr(instr, "A T [DIW %d]", value);
			return 4;
		case 0x51:
			s7_instr(instr, "AN T [DIW %d]", value);
			return 4;
		case 0x52:
			s7_instr(instr, "O T [DIW %d]", value);
			return 4;
		case 0x53:
			s7_instr(instr, "ON T [DIW %d]", value);
			return 4;
		case 0x54:
			s7_instr(instr, "X T [DIW %d]", value);
			return 4;
		case 0x55:
			s7_instr(instr, "XN T [DIW %d]", value);
			return 4;
		case 0x58:
			s7_instr(instr, "FR T [DIW %d]", value);
			return 4;
		case 0x5C:
			s7_instr(instr, "SD T [DIW %d]", value);
			return 4;
		case 0x5D:
			s7_instr(instr, "SS T [DIW %d]", value);
			return 4;
		case 0x5E:
			s7_instr(instr, "SP T [DIW %d]", value);
			return 4;
		case 0x5F:
			s7_instr(instr, "R T [DIW %d]", value);
			return 4;
		case 0x60:
			s7_instr(instr, "A T [LW %d]", value);
			return 4;
		case 0x61:
			s7_instr(instr, "AN T [LW %d]", value);
			return 4;
		case 0x62:
			s7_instr(instr, "O T [LW %d]", value);
			return 4;
		case 0x63:
			s7_instr(instr, "ON T [LW %d]", value);
			return 4;
		case 0x64:
			s7_instr(instr, "X T [LW %d]", value);
			return 4;
		case 0x65:
			s7_instr(instr, "XN T [LW %d]", value);
			return 4;
		case 0x66:
			s7_instr(instr, "L T [LW %d]", value);
			return 4;
		case 0x68:
			s7_instr(instr, "FR T [LW %d]", value);
			return 4;
		case 0x69:
			s7_instr(instr, "LC T [LW %d]", value);
			return 4;
		case 0x6A:
			s7_instr(instr, "SF T [LW %d]", value);
			return 4;
		case 0x6B:
			s7_instr(instr, "SE T [LW %d]", value);
			return 4;
		case 0x6C:
			s7_instr(instr, "SD T [LW %d]", value);
			return 4;
		case 0x6D:
			s7_instr(instr, "SS T [LW %d]", value);
			return 4;
		case 0x6E:
			s7_instr(instr, "SP T [LW %d]", value);
			return 4;
		case 0x6F:
			s7_instr(instr, "R T [LW %d]", value);
			return 4;
		case 0xB0:
			s7_instr(instr, "A C [MW %d]", value);
			return 4;
		case 0xB1:
			s7_instr(instr, "AN C [MW %d]", value);
			return 4;
		case 0xB2:
			s7_instr(instr, "O C [MW %d]", value);
			return 4;
		case 0xB3:
			s7_instr(instr, "ON C [MW %d]", value);
			return 4;
		case 0xB4:
			s7_instr(instr, "X C [MW %d]", value);
			return 4;
		case 0xB5:
			s7_instr(instr, "XN C [MW %d]", value);
			return 4;
		case 0xB6:
			s7_instr(instr, "L C [MW %d]", value);
			return 4;
		case 0xB8:
			s7_instr(instr, "FR C [MW %d]", value);
			return 4;
		case 0xB9:
			s7_instr(instr, "LC C [MW %d]", value);
			return 4;
		case 0xBA:
			s7_instr(instr, "CD C [MW %d]", value);
			return 4;
		case 0xBB:
			s7_instr(instr, "S C [MW %d]", value);
			return 4;
		case 0xBD:
			s7_instr(instr, "CU C [MW %d]", value);
			return 4;
		case 0xBF:
			s7_instr(instr, "R C [MW %d]", value);
			return 4;
		case 0xC0:
			s7_instr(instr, "A C [DBW %d]", value);
			return 4;
		case 0xC1:
			s7_instr(instr, "AN C [DBW %d]", value);
			return 4;
		case 0xC2:
			s7_instr(instr, "O C [DBW %d]", value);
			return 4;
		case 0xC3:
			s7_instr(instr, "ON C [DBW %d]", value);
			return 4;
		case 0xC4:
			s7_instr(instr, "X C [DBW %d]", value);
			return 4;
		case 0xC5:
			s7_instr(instr, "XN C [DBW %d]", value);
			return 4;
		case 0xC6:
			s7_instr(instr, "L C [DBW %d]", value);
			return 4;
		case 0xC8:
			s7_instr(instr, "FR C [DBW %d]", value);
			return 4;
		case 0xC9:
			s7_instr(instr, "LC C [DBW %d]", value);
			return 4;
		case 0xCA:
			s7_instr(instr, "CD C [DBW %d]", value);
			return 4;
		case 0xCB:
			s7_instr(instr, "S C [DBW %d]", value);
			return 4;
		case 0xCD:
			s7_instr(instr, "CU C [DBW %d]", value);
			return 4;
		case 0xCF:
			s7_instr(instr, "R C [DBW %d]", value);
			return 4;
		case 0xD0:
			s7_instr(instr, "A C [DIW %d]", value);
			return 4;
		case 0xD1:
			s7_instr(instr, "AN C [DIW %d]", value);
			return 4;
		case 0xD2:
			s7_instr(instr, "O C [DIW %d]", value);
			return 4;
		case 0xD3:
			s7_instr(instr, "ON C [DIW %d]", value);
			return 4;
		case 0xD4:
			s7_instr(instr, "X C [DIW %d]", value);
			return 4;
		case 0xD5:
			s7_instr(instr, "XN C [DIW %d]", value);
			return 4;
		case 0xD6:
			s7_instr(instr, "L C [DIW %d]", value);
			return 4;
		case 0xD8:
			s7_instr(instr, "FR C [DIW %d]", value);
			return 4;
		case 0xD9:
			s7_instr(instr, "LC C [DIW %d]", value);
			return 4;
		case 0xDA:
			s7_instr(instr, "CD C [DIW %d]", value);
			return 4;
		case 0xDB:
			s7_instr(instr, "S C [DIW %d]", value);
			return 4;
		case 0xDD:
			s7_instr(instr, "CU C [DIW %d]", value);
			return 4;
		case 0xDF:
			s7_instr(instr, "R C [DIW %d]", value);
			return 4;
		case 0xE0:
			s7_instr(instr, "A C [LW %d]", value);
			return 4;
		case 0xE1:
			s7_instr(instr, "AN C [LW %d]", value);
			return 4;
		case 0xE2:
			s7_instr(instr, "O C [LW %d]", value);
			return 4;
		case 0xE3:
			s7_instr(instr, "ON C [LW %d]", value);
			return 4;
		case 0xE4:
			s7_instr(instr, "X C [LW %d]", value);
			return 4;
		case 0xE5:
			s7_instr(instr, "XN C [LW %d]", value);
			return 4;
		case 0xE6:
			s7_instr(instr, "L C [LW %d]", value);
			return 4;
		case 0xE8:
			s7_instr(instr, "FR C [LW %d]", value);
			return 4;
		case 0xE9:
			s7_instr(instr, "LC C [LW %d]", value);
			return 4;
		case 0xEA:
			s7_instr(instr, "CD C [LW %d]", value);
			return 4;
		case 0xEB:
			s7_instr(instr, "S C [LW %d]", value);
			return 4;
		case 0xED:
			s7_instr(instr, "CU C [LW %d]", value);
			return 4;
		case 0xEF:
			s7_instr(instr, "R C [LW %d]", value);
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

static int s7_decode_FB(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	switch (buffer[0]) {
	case 0x00:
		s7_instr(instr, "O");
		return 2;
	case 0x3C:
		s7_instr(instr, "L DBLG");
		return 2;
	case 0x3D:
		s7_instr(instr, "L DILG");
		return 2;
	case 0x4C:
		s7_instr(instr, "L DBNO");
		return 2;
	case 0x4D:
		s7_instr(instr, "L DINO");
		return 2;
	case 0x7C:
		s7_instr(instr, "CDB");
		return 2;
	default:
		break;
	}
	if (size > 2) {
		ut16_t value = s7_ut16(buffer + 1);
		switch (buffer[0]) {
		case 0x01:
			s7_instr(instr, "L B [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x02:
			s7_instr(instr, "L W [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x03:
			s7_instr(instr, "L D [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x05:
			s7_instr(instr, "T B [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x06:
			s7_instr(instr, "T W [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x07:
			s7_instr(instr, "T D [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x09:
			s7_instr(instr, "L B [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0B:
			s7_instr(instr, "L W [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0C:
			s7_instr(instr, "L D [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0D:
			s7_instr(instr, "T B [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0E:
			s7_instr(instr, "T W [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0F:
			s7_instr(instr, "T D [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x10:
			s7_instr(instr, "A [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x11:
			s7_instr(instr, "AN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x12:
			s7_instr(instr, "O [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x13:
			s7_instr(instr, "ON [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x14:
			s7_instr(instr, "X [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x15:
			s7_instr(instr, "XN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x18:
			s7_instr(instr, "A [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x19:
			s7_instr(instr, "AN [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x1A:
			s7_instr(instr, "O [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x1B:
			s7_instr(instr, "ON [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x1C:
			s7_instr(instr, "X [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x1D:
			s7_instr(instr, "XN [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x20:
			s7_instr(instr, "S [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x21:
			s7_instr(instr, "R [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x22:
			s7_instr(instr, "= [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x24:
			s7_instr(instr, "FP [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x25:
			s7_instr(instr, "FN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x28:
			s7_instr(instr, "S [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x29:
			s7_instr(instr, "R [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x2A:
			s7_instr(instr, "= [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x2C:
			s7_instr(instr, "FP [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x2D:
			s7_instr(instr, "FN [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x30:
			s7_instr(instr, "UC FC [MW %u]", value);
			return 4;
		case 0x31:
			s7_instr(instr, "CC FC [MW %u]", value);
			return 4;
		case 0x32:
			s7_instr(instr, "UC FB [MW %u]", value);
			return 4;
		case 0x33:
			s7_instr(instr, "CC FB [MW %u]", value);
			return 4;
		case 0x38:
			s7_instr(instr, "OPN DB [MW %u]", value);
			return 4;
		case 0x39:
			s7_instr(instr, "OPN DI [MW %u]", value);
			return 4;
		case 0x40:
			s7_instr(instr, "UC FC [DBW %u]", value);
			return 4;
		case 0x41:
			s7_instr(instr, "CC FC [DBW %u]", value);
			return 4;
		case 0x42:
			s7_instr(instr, "UC FB [DBW %u]", value);
			return 4;
		case 0x43:
			s7_instr(instr, "CC FB [DBW %u]", value);
			return 4;
		case 0x48:
			s7_instr(instr, "OPN DB [DBW %u]", value);
			return 4;
		case 0x49:
			s7_instr(instr, "OPN DI [DBW %u]", value);
			return 4;
		case 0x50:
			s7_instr(instr, "UC FC [DIW %u]", value);
			return 4;
		case 0x51:
			s7_instr(instr, "CC FC [DIW %u]", value);
			return 4;
		case 0x52:
			s7_instr(instr, "UC FB [DIW %u]", value);
			return 4;
		case 0x53:
			s7_instr(instr, "CC FB [DIW %u]", value);
			return 4;
		case 0x58:
			s7_instr(instr, "OPN DB [DIW %u]", value);
			return 4;
		case 0x59:
			s7_instr(instr, "OPN DI [DIW %u]", value);
			return 4;
		case 0x60:
			s7_instr(instr, "UC FC [LW %u]", value);
			return 4;
		case 0x61:
			s7_instr(instr, "CC FC [LW %u]", value);
			return 4;
		case 0x62:
			s7_instr(instr, "UC FB [LW %u]", value);
			return 4;
		case 0x63:
			s7_instr(instr, "CC FB [LW %u]", value);
			return 4;
		case 0x68:
			s7_instr(instr, "OPN DB [LW %u]", value);
			return 4;
		case 0x69:
			s7_instr(instr, "OPN DI [LW %u]", value);
			return 4;
		case 0x70:
			s7_instr(instr, "UC FC %u", value);
			return 4;
		case 0x71:
			s7_instr(instr, "CC FC %u", value);
			return 4;
		case 0x72:
			s7_instr(instr, "UC FC %u", value);
			return 4;
		case 0x73:
			s7_instr(instr, "CC FB %u", value);
			return 4;
		case 0x74:
			s7_instr(instr, "UC SFC %u", value);
			return 4;
		case 0x76:
			s7_instr(instr, "UC SFB %u", value);
			return 4;
		case 0x78:
			s7_instr(instr, "OPN DB %u", value);
			return 4;
		case 0x79:
			s7_instr(instr, "OPN DI %u", value);
			return 4;
		case 0x80:
			s7_instr(instr, "A [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x81:
			s7_instr(instr, "AN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x82:
			s7_instr(instr, "O [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x83:
			s7_instr(instr, "ON [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x84:
			s7_instr(instr, "X [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x85:
			s7_instr(instr, "XN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x90:
			s7_instr(instr, "S [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x91:
			s7_instr(instr, "R [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x92:
			s7_instr(instr, "= [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x94:
			s7_instr(instr, "FP [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x95:
			s7_instr(instr, "FN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0xA0:
			s7_instr(instr, "A [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA1:
			s7_instr(instr, "AN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA2:
			s7_instr(instr, "O [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA3:
			s7_instr(instr, "ON [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA4:
			s7_instr(instr, "X [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA5:
			s7_instr(instr, "XN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA6:
			s7_instr(instr, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA8:
			s7_instr(instr, "FR [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA9:
			s7_instr(instr, "LC [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAA:
			s7_instr(instr, "SF [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAB:
			s7_instr(instr, "SE [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAC:
			s7_instr(instr, "SD [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAD:
			s7_instr(instr, "SS [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAE:
			s7_instr(instr, "SP [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAF:
			s7_instr(instr, "R [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xB0:
			s7_instr(instr, "A [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB1:
			s7_instr(instr, "AN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB2:
			s7_instr(instr, "O [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB3:
			s7_instr(instr, "ON [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB4:
			s7_instr(instr, "X [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB5:
			s7_instr(instr, "XN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB6:
			s7_instr(instr, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB8:
			s7_instr(instr, "FR [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB9:
			s7_instr(instr, "LC [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xBA:
			s7_instr(instr, "CD [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xBB:
			s7_instr(instr, "S [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xBD:
			s7_instr(instr, "CU [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xBF:
			s7_instr(instr, "R [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xC1:
			s7_instr(instr, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BYTE
			return 4;
		case 0xC2:
			s7_instr(instr, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_WORD
			return 4;
		case 0xC3:
			s7_instr(instr, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_DWORD
			return 4;
		case 0xC5:
			s7_instr(instr, "T [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BYTE
			return 4;
		case 0xC6:
			s7_instr(instr, "T [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_WORD
			return 4;
		case 0xC7:
			s7_instr(instr, "T [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_DWORD
			return 4;
		case 0xD0:
			s7_instr(instr, "UC [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BLOCK_FC
			return 4;
		case 0xD2:
			s7_instr(instr, "UC [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BLOCK_FB
			return 4;
		case 0xD8:
			s7_instr(instr, "OPN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BLOCK_DB
			return 4;
		case 0xE0:
			s7_instr(instr, "A T %u", value);
			return 4;
		case 0xE1:
			s7_instr(instr, "AN T %u", value);
			return 4;
		case 0xE2:
			s7_instr(instr, "O T %u", value);
			return 4;
		case 0xE3:
			s7_instr(instr, "ON T %u", value);
			return 4;
		case 0xE4:
			s7_instr(instr, "X T %u", value);
			return 4;
		case 0xE5:
			s7_instr(instr, "XN T %u", value);
			return 4;
		case 0xE6:
			s7_instr(instr, "L T %u", value);
			return 4;
		case 0xE8:
			s7_instr(instr, "FR T %u", value);
			return 4;
		case 0xE9:
			s7_instr(instr, "LC T %u", value);
			return 4;
		case 0xEA:
			s7_instr(instr, "SF T %u", value);
			return 4;
		case 0xEB:
			s7_instr(instr, "SE T %u", value);
			return 4;
		case 0xEC:
			s7_instr(instr, "SD T %u", value);
			return 4;
		case 0xED:
			s7_instr(instr, "SS T %u", value);
			return 4;
		case 0xEE:
			s7_instr(instr, "SP T %u", value);
			return 4;
		case 0xEF:
			s7_instr(instr, "R T %u", value);
			return 4;
		case 0xF0:
			s7_instr(instr, "A C %u", value);
			return 4;
		case 0xF1:
			s7_instr(instr, "AN C %u", value);
			return 4;
		case 0xF2:
			s7_instr(instr, "O C %u", value);
			return 4;
		case 0xF3:
			s7_instr(instr, "ON C %u", value);
			return 4;
		case 0xF4:
			s7_instr(instr, "X C %u", value);
			return 4;
		case 0xF5:
			s7_instr(instr, "XN C %u", value);
			return 4;
		case 0xF6:
			s7_instr(instr, "L C %u", value);
			return 4;
		case 0xF8:
			s7_instr(instr, "FR C %u", value);
			return 4;
		case 0xF9:
			s7_instr(instr, "LC C %u", value);
			return 4;
		case 0xFA:
			s7_instr(instr, "CD %u", value);
			return 4;
		case 0xFB:
			s7_instr(instr, "S %u", value);
			return 4;
		case 0xFD:
			s7_instr(instr, "CU %u", value);
			return 4;
		case 0xFF:
			s7_instr(instr, "R %u", value);
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

static int s7_decode_FE(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if ((buffer[0] & 0xF0) == 0xC0) {
		ut8_t value = (buffer[0] & 0x0F);
		s7_instr(instr, "SRD %u", value);
		return 2;
	}
	switch (buffer[0]) {
	case 0x01:
		s7_instr(instr, "LAR1 AR2");
		return 2;
	case 0x04:
		s7_instr(instr, "LAR1");
		return 2;
	case 0x05:
		s7_instr(instr, "TAR1");
		return 2;
	case 0x06:
		s7_instr(instr, "+AR1");
		return 2;
	case 0x08:
		s7_instr(instr, "CAR");
		return 2;
	case 0x09:
		s7_instr(instr, "TAR1 AR2");
		return 2;
	case 0x0C:
		s7_instr(instr, "LAR2");
		return 2;
	case 0x0D:
		s7_instr(instr, "TAR2");
		return 2;
	case 0x0E:
		s7_instr(instr, "+AR2");
		return 2;
	default:
		break;
	}
	if (size > 2) {
		switch (buffer[0]) {
		case 0x03:
			if (size > 4) {
				ut32_t value = s7_ut32(buffer + 1);
				s7_instr(instr, "LAR1 P#%u.%u", (value >> 1), (value & 1));
				return 6;
			}
			return -1;
		case 0x0B:
			if (size > 4) {
				ut32_t value = s7_ut32(buffer + 1);
				s7_instr(instr, "LAR2 P#%u.%u", (value >> 1), (value & 1));
				return 6;
			}
			return -1;
		case 0x02: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "+AR1 P#%u.%u", (value & 0xFFF), (value >> 12));
			return 4;
		}
		case 0x0A: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "+AR2 P#%u.%u", (value & 0xFFF), (value >> 12));
			return 4;
		}
		case 0x33: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "LAR1 MD %u", value);
			return 4;
		}
		case 0x37: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "TAR1 MD %u", value);
			return 4;
		}
		case 0x3B: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "LAR2 MD %u", value);
			return 4;
		}
		case 0x3F: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "TAR2 MD %u", value);
			return 4;
		}
		case 0x43: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "LAR1 DBD %u", value);
			return 4;
		}
		case 0x47: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "TAR1 DBD %u", value);
			return 4;
		}
		case 0x4B: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "LAR2 DBD %u", value);
			return 4;
		}
		case 0x4F: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "TAR2 DBD %u", value);
			return 4;
		}
		case 0x53: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "LAR1 DID %u", value);
			return 4;
		}
		case 0x57: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "TAR1 DID %u", value);
			return 4;
		}
		case 0x5B: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "LAR2 DID %u", value);
			return 4;
		}
		case 0x5F: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "TAR2 DID %u", value);
			return 4;
		}
		case 0x63: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "LAR1 LD %u", value);
			return 4;
		}
		case 0x67: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "TAR1 LD %u", value);
			return 4;
		}
		case 0x6B: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "LAR2 LD %u", value);
			return 4;
		}
		case 0x6F: {
			ut16_t value = s7_ut16(buffer + 1);
			s7_instr(instr, "TAR2 LD %u", value);
			return 4;
		}
		}
	}
	return -1;
}

static int s7_decode_FF(ut64_t addr, const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	switch (buffer[0]) {
	case 0x00:
		s7_instr(instr, "A OS");
		return 2;
	case 0x01:
		s7_instr(instr, "AN OS");
		return 2;
	case 0x02:
		s7_instr(instr, "O OS");
		return 2;
	case 0x03:
		s7_instr(instr, "ON OS");
		return 2;
	case 0x04:
		s7_instr(instr, "X OS");
		return 2;
	case 0x05:
		s7_instr(instr, "XN OS");
		return 2;
	case 0x10:
		s7_instr(instr, "A OV");
		return 2;
	case 0x11:
		s7_instr(instr, "AN OV");
		return 2;
	case 0x12:
		s7_instr(instr, "O OV");
		return 2;
	case 0x13:
		s7_instr(instr, "ON OV");
		return 2;
	case 0x14:
		s7_instr(instr, "X OV");
		return 2;
	case 0x15:
		s7_instr(instr, "XN OV");
		return 2;
	case 0x20:
		s7_instr(instr, "A >0");
		return 2;
	case 0x21:
		s7_instr(instr, "AN >0");
		return 2;
	case 0x22:
		s7_instr(instr, "O >0");
		return 2;
	case 0x23:
		s7_instr(instr, "ON >0");
		return 2;
	case 0x24:
		s7_instr(instr, "X >0");
		return 2;
	case 0x25:
		s7_instr(instr, "XN >0");
		return 2;
	case 0x40:
		s7_instr(instr, "A <0");
		return 2;
	case 0x41:
		s7_instr(instr, "AN <0");
		return 2;
	case 0x42:
		s7_instr(instr, "O <0");
		return 2;
	case 0x43:
		s7_instr(instr, "ON <0");
		return 2;
	case 0x44:
		s7_instr(instr, "X <0");
		return 2;
	case 0x45:
		s7_instr(instr, "XN <0");
		return 2;
	case 0x50:
		s7_instr(instr, "A UO");
		return 2;
	case 0x51:
		s7_instr(instr, "AN UO");
		return 2;
	case 0x52:
		s7_instr(instr, "O UO");
		return 2;
	case 0x53:
		s7_instr(instr, "ON UO");
		return 2;
	case 0x54:
		s7_instr(instr, "X UO");
		return 2;
	case 0x55:
		s7_instr(instr, "XN UO");
		return 2;
	case 0x60:
		s7_instr(instr, "A <>0");
		return 2;
	case 0x61:
		s7_instr(instr, "AN <>0");
		return 2;
	case 0x62:
		s7_instr(instr, "O <>0");
		return 2;
	case 0x63:
		s7_instr(instr, "ON <>0");
		return 2;
	case 0x64:
		s7_instr(instr, "X <>0");
		return 2;
	case 0x65:
		s7_instr(instr, "XN <>0");
		return 2;
	case 0x80:
		s7_instr(instr, "A ==0");
		return 2;
	case 0x81:
		s7_instr(instr, "AN ==0");
		return 2;
	case 0x82:
		s7_instr(instr, "O ==0");
		return 2;
	case 0x83:
		s7_instr(instr, "ON ==0");
		return 2;
	case 0x84:
		s7_instr(instr, "X ==0");
		return 2;
	case 0x85:
		s7_instr(instr, "XN ==0");
		return 2;
	case 0xA0:
		s7_instr(instr, "A >=0");
		return 2;
	case 0xA1:
		s7_instr(instr, "AN >=0");
		return 2;
	case 0xA2:
		s7_instr(instr, "O >=0");
		return 2;
	case 0xA3:
		s7_instr(instr, "ON >=0");
		return 2;
	case 0xA4:
		s7_instr(instr, "X >=0");
		return 2;
	case 0xA5:
		s7_instr(instr, "XN >=0");
		return 2;
	case 0xC0:
		s7_instr(instr, "A <=0");
		return 2;
	case 0xC1:
		s7_instr(instr, "AN <=0");
		return 2;
	case 0xC2:
		s7_instr(instr, "O <=0");
		return 2;
	case 0xC3:
		s7_instr(instr, "ON <=0");
		return 2;
	case 0xC4:
		s7_instr(instr, "X <=0");
		return 2;
	case 0xC5:
		s7_instr(instr, "XN <=0");
		return 2;
	case 0xE0:
		s7_instr(instr, "A BR");
		return 2;
	case 0xE1:
		s7_instr(instr, "AN BR");
		return 2;
	case 0xE2:
		s7_instr(instr, "O BR");
		return 2;
	case 0xE3:
		s7_instr(instr, "ON BR");
		return 2;
	case 0xE4:
		s7_instr(instr, "X BR");
		return 2;
	case 0xE5:
		s7_instr(instr, "XN BR");
		return 2;
	case 0xF1:
		s7_instr(instr, "AN(");
		return 2;
	case 0xF3:
		s7_instr(instr, "ON(");
		return 2;
	case 0xF4:
		s7_instr(instr, "X(");
		return 2;
	case 0xF5:
		s7_instr(instr, "XN(");
		return 2;
	case 0xFF:
		s7_instr(instr, "NOP 1");
		return 2;
	default:
		break;
	}
	if (size > 2) {
		st16_t value = (st16_t)s7_ut16(buffer + 1);
		addr += value;
		instr->jump = addr;
		switch (buffer[0]) {
		case 0x08:
			s7_instr(instr, "JOS 0x%" PFMT64x, addr);
			return 4;
		case 0x18:
			s7_instr(instr, "JO 0x%" PFMT64x, addr);
			return 4;
		case 0x28:
			s7_instr(instr, "JP 0x%" PFMT64x, addr);
			return 4;
		case 0x48:
			s7_instr(instr, "JM 0x%" PFMT64x, addr);
			return 4;
		case 0x58:
			s7_instr(instr, "JUO 0x%" PFMT64x, addr);
			return 4;
		case 0x68:
			s7_instr(instr, "JN 0x%" PFMT64x, addr);
			return 4;
		case 0x78:
			s7_instr(instr, "JNBI 0x%" PFMT64x, addr);
			return 4;
		case 0x88:
			s7_instr(instr, "JZ 0x%" PFMT64x, addr);
			return 4;
		case 0x98:
			s7_instr(instr, "JNB 0x%" PFMT64x, addr);
			return 4;
		case 0xA8:
			s7_instr(instr, "JPZ 0x%" PFMT64x, addr);
			return 4;
		case 0xB8:
			s7_instr(instr, "JCN 0x%" PFMT64x, addr);
			return 4;
		case 0xC8:
			s7_instr(instr, "JMZ 0x%" PFMT64x, addr);
			return 4;
		case 0xD8:
			s7_instr(instr, "JCB 0x%" PFMT64x, addr);
			return 4;
		case 0xE8:
			s7_instr(instr, "JBI 0x%" PFMT64x, addr);
			return 4;
		case 0xF8:
			s7_instr(instr, "JC 0x%" PFMT64x, addr);
			return 4;
		default:
			instr->jump = S7_INVALID_JUMP;
			return -1;
		}
	}
	return -1;
}

static int s7_decode_200A(const ut8_t *buffer, const ut64_t size, S7Instr *instr) {
	if (size < 5) {
		return -1;
	}
	ut8_t db = buffer[0];
	switch (buffer[1]) {
	case 0x05:
		switch ((buffer[2] & 0xF0)) {
		case 0xC0: {
			ut8_t n = buffer[2] & 0x0F;
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "XN DB%u.DBX %u.%u", db, value, n);
			return 6;
		}
		default:
			return -1;
		}
	case 0xFE:
		switch (buffer[2]) {
		case 0x33: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "LAR1 DB%u.MD %u", db, value);
			return 6;
		}
		case 0x37: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "TAR1 DB%u.MD %u", db, value);
			return 6;
		}
		case 0x3B: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "LAR2 DB%u.MD %u", db, value);
			return 6;
		}
		case 0x3F: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "TAR2 DB%u.MD %u", db, value);
			return 6;
		}
		case 0x43: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "LAR1 DB%u.DBD %u", db, value);
			return 6;
		}
		case 0x47: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "TAR1 DB%u.DBD %u", db, value);
			return 6;
		}
		case 0x4B: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "LAR2 DB%u.DBD %u", db, value);
			return 6;
		}
		case 0x4F: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "TAR2 DB%u.DBD %u", db, value);
			return 6;
		}
		case 0x53: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "LAR1 DB%u.DID %u", db, value);
			return 6;
		}
		case 0x57: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "TAR1 DB%u.DID %u", db, value);
			return 6;
		}
		case 0x5B: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "LAR2 DB%u.DID %u", db, value);
			return 6;
		}
		case 0x5F: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "TAR2 DB%u.DID %u", db, value);
			return 6;
		}
		case 0x63: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "LAR1 DB%u.LD %u", db, value);
			return 6;
		}
		case 0x67: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "TAR1 DB%u.LD %u", db, value);
			return 6;
		}
		case 0x6B: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "LAR2 DB%u.LD %u", db, value);
			return 6;
		}
		case 0x6F: {
			ut16_t value = s7_ut16(buffer + 3);
			s7_instr(instr, "TAR2 DB%u.LD %u", db, value);
			return 6;
		}
		default:
			return -1;
		}
	default:
		return -1;
	}
}

int simatic_s7_decode_instruction(const ut8_t *buffer, const ut64_t size, const ut64_t addr, S7Instr *instr) {
	if (!buffer || size < 2 || !instr) {
		return -1;
	}
	s7_instr(instr, "invalid");
	instr->jump = S7_INVALID_JUMP;
	instr->is_return = false;

	switch (buffer[0]) {
	case 0x00:
		return s7_decode_bitlogic("NOP 0", "A", "AN", buffer + 1, size - 1, instr);
	case 0x01:
		return s7_decode_bitlogic("INVI", "O", "ON", buffer + 1, size - 1, instr);
	case 0x02:
		return s7_decode_byte("L", "T ", buffer + 1, size - 1, instr);
	case 0x04:
		return s7_decode_byte("FR", "T ", buffer + 1, size - 1, instr);
	case 0x05: {
		int ret = s7_decode_bitlogic("BEC", "X", "XN", buffer + 1, size - 1, instr);
		if (ret > 0) {
			instr->is_return = true;
		}
		return ret;
	}
	case 0x09:
		return s7_decode_bitlogic("NEGI", "S", "R", buffer + 1, size - 1, instr);
	case 0x0A:
		return s7_decode_byte("L", "MB ", buffer + 1, size - 1, instr);
	case 0x0B:
		return s7_decode_byte("T", "MB ", buffer + 1, size - 1, instr);
	case 0x0C:
		return s7_decode_byte("LC", "T ", buffer + 1, size - 1, instr);
	case 0x10: {
		int ret = s7_decode_byte("BLD", "", buffer + 1, size - 1, instr);
		if (ret > 0) {
			instr->is_return = true;
		}
		return ret;
	}
	case 0x11:
		return s7_decode_byte("INC", "", buffer + 1, size - 1, instr);
	case 0x12:
		return s7_decode_byte("L", "MW ", buffer + 1, size - 1, instr);
	case 0x13:
		return s7_decode_byte("T", "MW ", buffer + 1, size - 1, instr);
	case 0x14:
		return s7_decode_byte("SF", "T ", buffer + 1, size - 1, instr);
	case 0x19:
		return s7_decode_byte("DEC", "", buffer + 1, size - 1, instr);
	case 0x1A:
		return s7_decode_byte("L", "MD ", buffer + 1, size - 1, instr);
	case 0x1B:
		return s7_decode_byte("T", "MD ", buffer + 1, size - 1, instr);
	case 0x1C:
		return s7_decode_byte("SE", "T ", buffer + 1, size - 1, instr);
	case 0x1D:
		return s7_decode_byte("CC", "FC ", buffer + 1, size - 1, instr);
	case 0x20:
		if (buffer[1] == 0x0A) {
			return s7_decode_200A(buffer + 1, size - 1, instr);
		} else {
			return s7_decode_byte("OPN", "DB ", buffer + 1, size - 1, instr);
		}
	case 0x21:
		return s7_decode_cmp("I", buffer + 1, size - 1, instr);
	case 0x24:
		return s7_decode_byte("SD", "T ", buffer + 1, size - 1, instr);
	case 0x28:
		return s7_decode_byte("L", "B#16#", buffer + 1, size - 1, instr);
	case 0x29:
		if (buffer[1] < 0x10) {
			return s7_decode_byte("SLD", "", buffer + 1, size - 1, instr);
		} else {
			return -1;
		}
	case 0x2C:
		return s7_decode_byte("SS", "T ", buffer + 1, size - 1, instr);
	case 0x30:
		return s7_decode_lit16(buffer + 1, size - 1, instr);
	case 0x31:
		return s7_decode_cmp("R", buffer + 1, size - 1, instr);
	case 0x34:
		return s7_decode_byte("SP", "T ", buffer + 1, size - 1, instr);
	case 0x38:
		return s7_decode_lit32(buffer + 1, size - 1, instr);
	case 0x39:
		return s7_decode_cmp("D", buffer + 1, size - 1, instr);
	case 0x3C:
		return s7_decode_byte("R", "T ", buffer + 1, size - 1, instr);
	case 0x3D:
		return s7_decode_byte("UC", "FC ", buffer + 1, size - 1, instr);
	case 0x41:
		return s7_decode_bitlogic("AW", "=", NULL, buffer + 1, size - 1, instr);
	case 0x42:
		return s7_decode_byte("L", "C ", buffer + 1, size - 1, instr);
	case 0x44:
		return s7_decode_byte("FR", "C ", buffer + 1, size - 1, instr);
	case 0x49:
		return s7_decode_bitlogic("OW", "FP", "FN", buffer + 1, size - 1, instr);
	case 0x4A:
		return s7_decode_byte_signed("L", "IB", "QB", "", buffer + 1, size - 1, instr);
	case 0x4B:
		return s7_decode_byte_signed("T", "IB", "QB", "", buffer + 1, size - 1, instr);
	case 0x4C:
		return s7_decode_byte("LC", "C ", buffer + 1, size - 1, instr);
	case 0x51:
		return s7_decode_bitlogic_mem("XOW", false, "A", "O", "AN", "ON", buffer + 1, size - 1, instr);
	case 0x52:
		return s7_decode_byte_signed("L", "IW", "QW", "", buffer + 1, size - 1, instr);
	case 0x53:
		return s7_decode_byte_signed("T", "IW", "QW", "", buffer + 1, size - 1, instr);
	case 0x54:
		return s7_decode_byte("CD", "C ", buffer + 1, size - 1, instr);
	case 0x55:
		return s7_decode_byte("CC", "FB ", buffer + 1, size - 1, instr);
	case 0x58:
		return s7_decode_bitlogic_mem("+", true, "X", "S", "XN", "R", buffer + 1, size - 1, instr);
	case 0x59:
		return s7_decode_bitlogic_mem("-I", false, "=", "FP", NULL, "FN", buffer + 1, size - 1, instr);
	case 0x5A:
		return s7_decode_byte_signed("L", "ID", "QD", "", buffer + 1, size - 1, instr);
	case 0x5B:
		return s7_decode_byte_signed("T", "ID", "QD", "", buffer + 1, size - 1, instr);
	case 0x5C:
		return s7_decode_byte("S", "C ", buffer + 1, size - 1, instr);
	case 0x60:
		if (buffer[1] == 0x05 && size > 5) {
			st32_t value = (st32_t)s7_ut32(buffer + 2);
			s7_instr(instr, "+ L#%d", value);
			return 6;
		} else {
			const s7_static_t ops[] = {
				{ 0x00, "/I" },
				{ 0x01, "MOD" },
				{ 0x02, "ABS" },
				{ 0x03, "/R" },
				{ 0x04, "*I" },
				{ 0x06, "NEGR" },
				{ 0x07, "*R" },
				{ 0x08, "ENT" },
				{ 0x09, "-D" },
				{ 0x0A, "*D" },
				{ 0x0B, "-R" },
				{ 0x0D, "+D" },
				{ 0x0E, "/D" },
				{ 0x0F, "+R" },
				{ 0x10, "SIN" },
				{ 0x11, "COS" },
				{ 0x12, "TAN" },
				{ 0x13, "LN" },
				{ 0x14, "SQRT" },
				{ 0x18, "ASIN" },
				{ 0x19, "ACOS" },
				{ 0x1A, "ATAN" },
				{ 0x1B, "EXP" },
				{ 0x1C, "SQR" },
				{ 0, NULL }
			};
			return s7_decode_static(ops, buffer + 1, size - 1, instr);
		}
	case 0x61:
		if (buffer[1] < 0x10) {
			return s7_decode_4bit("SLW", false, buffer + 1, size - 1, instr);
		} else {
			return -1;
		}
	case 0x64:
		if (buffer[1] <= 32) {
			return s7_decode_byte("RLD", "", buffer + 1, size - 1, instr);
		} else {
			return -1;
		}
	case 0x65: {
		const s7_static_t ops[] = {
			{ 0x00, "BE" },
			{ 0x01, "BEU" },
			{ 0, NULL }
		};
		int ret = s7_decode_static(ops, buffer + 1, size - 1, instr);
		if (ret > 0) {
			instr->is_return = true;
		}
		return ret;
	}
	case 0x68:
		if (size > 5) {
			ut32_t value = s7_ut32(buffer + 2);
			switch (buffer[1]) {
			case 0x36:
				s7_instr(instr, "AD DW#16#%x", value);
				return 6;
			case 0x46:
				s7_instr(instr, "OD DW#16#%x", value);
				return 6;
			case 0x56:
				s7_instr(instr, "XOD DW#16#%x", value);
				return 6;
			default:
				break;
			}
		} else if (size > 3) {
			ut16_t value = s7_ut16(buffer + 2);
			switch (buffer[1]) {
			case 0x34:
				s7_instr(instr, "AW W#16#%x", value);
				return 4;
			case 0x44:
				s7_instr(instr, "OW W#16#%x", value);
				return 4;
			case 0x54:
				s7_instr(instr, "XOW W#16#%x", value);
				return 4;
			default:
				break;
			}
		}
		if ((buffer[1] & 0x0F) == 0x01) {
			return s7_decode_4bit("SSI", true, buffer + 1, size - 1, instr);
		} else {
			const s7_static_t ops[] = {
				{ 0x06, "DTR" },
				{ 0x07, "NEGD" },
				{ 0x08, "ITB" },
				{ 0x0A, "DTB" },
				{ 0x0C, "BTI" },
				{ 0x0E, "BTD" },
				{ 0x0D, "INVD" },
				{ 0x12, "SLW" },
				{ 0x13, "SLD" },
				{ 0x17, "RLD" },
				{ 0x18, "RLDA" },
				{ 0x1A, "CAW" },
				{ 0x1B, "CAD" },
				{ 0x1C, "CLR" },
				{ 0x1D, "SET" },
				{ 0x1E, "ITD" },
				{ 0x22, "SRW" },
				{ 0x23, "SRD" },
				{ 0x24, "SSI" },
				{ 0x25, "SSD" },
				{ 0x27, "RRD" },
				{ 0x28, "RRDA" },
				{ 0x2C, "SAVE" },
				{ 0x2D, "NOT" },
				{ 0x2E, "PUSH" },
				{ 0x37, "AD" },
				{ 0x3A, "MCRA" },
				{ 0x3B, "MCRD" },
				{ 0x3C, "MCR(" },
				{ 0x3D, ")MCR" },
				{ 0x3E, "POP" },
				{ 0x47, "OD" },
				{ 0x4E, "LEAVE" },
				{ 0x57, "XOD" },
				{ 0x5C, "RND" },
				{ 0x5D, "RND-" },
				{ 0x5E, "RND+" },
				{ 0x5F, "TRUNC" },
				{ 0, NULL }
			};
			return s7_decode_static(ops, buffer + 1, size - 1, instr);
		}
		return -1;
	case 0x69:
		if (buffer[1] < 0x10) {
			return s7_decode_4bit("SRW", false, buffer + 1, size - 1, instr);
		} else {
			return -1;
		}
	case 0x6C:
		return s7_decode_byte("CU", "C ", buffer + 1, size - 1, instr);
	case 0x70:
		if (buffer[1] == 0x08) {
			return s7_decode_jump("LOOP", addr, buffer + 1, size - 1, instr);
		} else if (buffer[1] == 0x09) {
			return s7_decode_jump("JL", addr, buffer + 1, size - 1, instr);
		} else if (buffer[1] == 0x0B) {
			return s7_decode_jump("JU", addr, buffer + 1, size - 1, instr);
		} else {
			const s7_static_t ops[] = {
				{ 0x02, "TAK" },
				{ 0x06, "L STW" },
				{ 0x07, "T STW" },
				{ 0, NULL }
			};
			return s7_decode_static(ops, buffer + 1, size - 1, instr);
		}
	case 0x71:
		if (buffer[1] < 0x10) {
			return s7_decode_4bit("SSD", false, buffer + 1, size - 1, instr);
		} else {
			return -1;
		}
	case 0x74:
		return s7_decode_byte("RRD", "", buffer + 1, size - 1, instr);
	case 0x75:
		return s7_decode_byte("UC", "FB ", buffer + 1, size - 1, instr);
	case 0x79:
		return s7_decode_79(buffer + 1, size - 1, instr);
	case 0x7C:
		return s7_decode_byte("R", "C ", buffer + 1, size - 1, instr);
	case 0x7E:
		return s7_decode_7E(buffer + 1, size - 1, instr);
	case 0x80:
		return s7_decode_byte_s("A M", ".0", buffer + 1, size - 1, instr);
	case 0x81:
		return s7_decode_byte_s("A M", ".1", buffer + 1, size - 1, instr);
	case 0x82:
		return s7_decode_byte_s("A M", ".2", buffer + 1, size - 1, instr);
	case 0x83:
		return s7_decode_byte_s("A M", ".3", buffer + 1, size - 1, instr);
	case 0x84:
		return s7_decode_byte_s("A M", ".4", buffer + 1, size - 1, instr);
	case 0x85:
		return s7_decode_byte_s("A M", ".5", buffer + 1, size - 1, instr);
	case 0x86:
		return s7_decode_byte_s("A M", ".6", buffer + 1, size - 1, instr);
	case 0x87:
		return s7_decode_byte_s("A M", ".7", buffer + 1, size - 1, instr);
	case 0x88:
		return s7_decode_byte_s("O M", ".0", buffer + 1, size - 1, instr);
	case 0x89:
		return s7_decode_byte_s("O M", ".1", buffer + 1, size - 1, instr);
	case 0x8A:
		return s7_decode_byte_s("O M", ".2", buffer + 1, size - 1, instr);
	case 0x8B:
		return s7_decode_byte_s("O M", ".3", buffer + 1, size - 1, instr);
	case 0x8C:
		return s7_decode_byte_s("O M", ".4", buffer + 1, size - 1, instr);
	case 0x8D:
		return s7_decode_byte_s("O M", ".5", buffer + 1, size - 1, instr);
	case 0x8E:
		return s7_decode_byte_s("O M", ".6", buffer + 1, size - 1, instr);
	case 0x8F:
		return s7_decode_byte_s("O M", ".7", buffer + 1, size - 1, instr);
	case 0x90:
		return s7_decode_byte_s("S M", ".0", buffer + 1, size - 1, instr);
	case 0x91:
		return s7_decode_byte_s("S M", ".1", buffer + 1, size - 1, instr);
	case 0x92:
		return s7_decode_byte_s("S M", ".2", buffer + 1, size - 1, instr);
	case 0x93:
		return s7_decode_byte_s("S M", ".3", buffer + 1, size - 1, instr);
	case 0x94:
		return s7_decode_byte_s("S M", ".4", buffer + 1, size - 1, instr);
	case 0x95:
		return s7_decode_byte_s("S M", ".5", buffer + 1, size - 1, instr);
	case 0x96:
		return s7_decode_byte_s("S M", ".6", buffer + 1, size - 1, instr);
	case 0x97:
		return s7_decode_byte_s("S M", ".7", buffer + 1, size - 1, instr);
	case 0x98:
		return s7_decode_byte_s("= M", ".0", buffer + 1, size - 1, instr);
	case 0x99:
		return s7_decode_byte_s("= M", ".1", buffer + 1, size - 1, instr);
	case 0x9A:
		return s7_decode_byte_s("= M", ".2", buffer + 1, size - 1, instr);
	case 0x9B:
		return s7_decode_byte_s("= M", ".3", buffer + 1, size - 1, instr);
	case 0x9C:
		return s7_decode_byte_s("= M", ".4", buffer + 1, size - 1, instr);
	case 0x9D:
		return s7_decode_byte_s("= M", ".5", buffer + 1, size - 1, instr);
	case 0x9E:
		return s7_decode_byte_s("= M", ".6", buffer + 1, size - 1, instr);
	case 0x9F:
		return s7_decode_byte_s("= M", ".7", buffer + 1, size - 1, instr);
	case 0xA0:
		return s7_decode_byte_s("AN M", ".0", buffer + 1, size - 1, instr);
	case 0xA1:
		return s7_decode_byte_s("AN M", ".1", buffer + 1, size - 1, instr);
	case 0xA2:
		return s7_decode_byte_s("AN M", ".2", buffer + 1, size - 1, instr);
	case 0xA3:
		return s7_decode_byte_s("AN M", ".3", buffer + 1, size - 1, instr);
	case 0xA4:
		return s7_decode_byte_s("AN M", ".4", buffer + 1, size - 1, instr);
	case 0xA5:
		return s7_decode_byte_s("AN M", ".5", buffer + 1, size - 1, instr);
	case 0xA6:
		return s7_decode_byte_s("AN M", ".6", buffer + 1, size - 1, instr);
	case 0xA7:
		return s7_decode_byte_s("AN M", ".7", buffer + 1, size - 1, instr);
	case 0xA8:
		return s7_decode_byte_s("ON M", ".0", buffer + 1, size - 1, instr);
	case 0xA9:
		return s7_decode_byte_s("ON M", ".1", buffer + 1, size - 1, instr);
	case 0xAA:
		return s7_decode_byte_s("ON M", ".2", buffer + 1, size - 1, instr);
	case 0xAB:
		return s7_decode_byte_s("ON M", ".3", buffer + 1, size - 1, instr);
	case 0xAC:
		return s7_decode_byte_s("ON M", ".4", buffer + 1, size - 1, instr);
	case 0xAD:
		return s7_decode_byte_s("ON M", ".5", buffer + 1, size - 1, instr);
	case 0xAE:
		return s7_decode_byte_s("ON M", ".6", buffer + 1, size - 1, instr);
	case 0xAF:
		return s7_decode_byte_s("ON M", ".7", buffer + 1, size - 1, instr);
	case 0xB0:
		return s7_decode_byte_s("R M", ".0", buffer + 1, size - 1, instr);
	case 0xB1:
		return s7_decode_byte_s("R M", ".1", buffer + 1, size - 1, instr);
	case 0xB2:
		return s7_decode_byte_s("R M", ".2", buffer + 1, size - 1, instr);
	case 0xB3:
		return s7_decode_byte_s("R M", ".3", buffer + 1, size - 1, instr);
	case 0xB4:
		return s7_decode_byte_s("R M", ".4", buffer + 1, size - 1, instr);
	case 0xB5:
		return s7_decode_byte_s("R M", ".5", buffer + 1, size - 1, instr);
	case 0xB6:
		return s7_decode_byte_s("R M", ".6", buffer + 1, size - 1, instr);
	case 0xB7:
		return s7_decode_byte_s("R M", ".7", buffer + 1, size - 1, instr);
	case 0xB8:
		return s7_decode_byte("A", "C ", buffer + 1, size - 1, instr);
	case 0xB9:
		return s7_decode_byte("O", "C ", buffer + 1, size - 1, instr);
	case 0xBC:
		return s7_decode_byte("AN", "C ", buffer + 1, size - 1, instr);
	case 0xBD:
		return s7_decode_byte("ON", "C ", buffer + 1, size - 1, instr);
	case 0xBA:
		if ((buffer[1] > 0x66 && buffer[1] < 0xB0) || buffer[1] > 0xE6) {
			return -1;
		} else {
			return s7_decode_mem("A(", "L", "T", types_b, types_b, buffer + 1, size - 1, instr);
		}
	case 0xBB:
		return s7_decode_mem("O(", "L", "T", types_w, types_d, buffer + 1, size - 1, instr);
	case 0xBE:
		return s7_decode_BE(buffer + 1, size - 1, instr);
	case 0xBF:
		return s7_decode_BF(buffer + 1, size - 1, instr);
	case 0xC0:
		return s7_decode_byte_signed("A", "I", "Q", ".0", buffer + 1, size - 1, instr);
	case 0xC1:
		return s7_decode_byte_signed("A", "I", "Q", ".1", buffer + 1, size - 1, instr);
	case 0xC2:
		return s7_decode_byte_signed("A", "I", "Q", ".2", buffer + 1, size - 1, instr);
	case 0xC3:
		return s7_decode_byte_signed("A", "I", "Q", ".3", buffer + 1, size - 1, instr);
	case 0xC4:
		return s7_decode_byte_signed("A", "I", "Q", ".4", buffer + 1, size - 1, instr);
	case 0xC5:
		return s7_decode_byte_signed("A", "I", "Q", ".5", buffer + 1, size - 1, instr);
	case 0xC6:
		return s7_decode_byte_signed("A", "I", "Q", ".6", buffer + 1, size - 1, instr);
	case 0xC7:
		return s7_decode_byte_signed("A", "I", "Q", ".7", buffer + 1, size - 1, instr);
	case 0xC8:
		return s7_decode_byte_signed("O", "I", "Q", ".0", buffer + 1, size - 1, instr);
	case 0xC9:
		return s7_decode_byte_signed("O", "I", "Q", ".1", buffer + 1, size - 1, instr);
	case 0xCA:
		return s7_decode_byte_signed("O", "I", "Q", ".2", buffer + 1, size - 1, instr);
	case 0xCB:
		return s7_decode_byte_signed("O", "I", "Q", ".3", buffer + 1, size - 1, instr);
	case 0xCC:
		return s7_decode_byte_signed("O", "I", "Q", ".4", buffer + 1, size - 1, instr);
	case 0xCD:
		return s7_decode_byte_signed("O", "I", "Q", ".5", buffer + 1, size - 1, instr);
	case 0xCE:
		return s7_decode_byte_signed("O", "I", "Q", ".6", buffer + 1, size - 1, instr);
	case 0xCF:
		return s7_decode_byte_signed("O", "I", "Q", ".7", buffer + 1, size - 1, instr);
	case 0xD0:
		return s7_decode_byte_signed("S", "I", "Q", ".0", buffer + 1, size - 1, instr);
	case 0xD1:
		return s7_decode_byte_signed("S", "I", "Q", ".1", buffer + 1, size - 1, instr);
	case 0xD2:
		return s7_decode_byte_signed("S", "I", "Q", ".2", buffer + 1, size - 1, instr);
	case 0xD3:
		return s7_decode_byte_signed("S", "I", "Q", ".3", buffer + 1, size - 1, instr);
	case 0xD4:
		return s7_decode_byte_signed("S", "I", "Q", ".4", buffer + 1, size - 1, instr);
	case 0xD5:
		return s7_decode_byte_signed("S", "I", "Q", ".5", buffer + 1, size - 1, instr);
	case 0xD6:
		return s7_decode_byte_signed("S", "I", "Q", ".6", buffer + 1, size - 1, instr);
	case 0xD7:
		return s7_decode_byte_signed("S", "I", "Q", ".7", buffer + 1, size - 1, instr);
	case 0xD8:
		return s7_decode_byte_signed("=", "I", "Q", ".0", buffer + 1, size - 1, instr);
	case 0xD9:
		return s7_decode_byte_signed("=", "I", "Q", ".1", buffer + 1, size - 1, instr);
	case 0xDA:
		return s7_decode_byte_signed("=", "I", "Q", ".2", buffer + 1, size - 1, instr);
	case 0xDB:
		return s7_decode_byte_signed("=", "I", "Q", ".3", buffer + 1, size - 1, instr);
	case 0xDC:
		return s7_decode_byte_signed("=", "I", "Q", ".4", buffer + 1, size - 1, instr);
	case 0xDD:
		return s7_decode_byte_signed("=", "I", "Q", ".5", buffer + 1, size - 1, instr);
	case 0xDE:
		return s7_decode_byte_signed("=", "I", "Q", ".6", buffer + 1, size - 1, instr);
	case 0xDF:
		return s7_decode_byte_signed("=", "I", "Q", ".7", buffer + 1, size - 1, instr);
	case 0xE0:
		return s7_decode_byte_signed("AN", "I", "Q", ".0", buffer + 1, size - 1, instr);
	case 0xE1:
		return s7_decode_byte_signed("AN", "I", "Q", ".1", buffer + 1, size - 1, instr);
	case 0xE2:
		return s7_decode_byte_signed("AN", "I", "Q", ".2", buffer + 1, size - 1, instr);
	case 0xE3:
		return s7_decode_byte_signed("AN", "I", "Q", ".3", buffer + 1, size - 1, instr);
	case 0xE4:
		return s7_decode_byte_signed("AN", "I", "Q", ".4", buffer + 1, size - 1, instr);
	case 0xE5:
		return s7_decode_byte_signed("AN", "I", "Q", ".5", buffer + 1, size - 1, instr);
	case 0xE6:
		return s7_decode_byte_signed("AN", "I", "Q", ".6", buffer + 1, size - 1, instr);
	case 0xE7:
		return s7_decode_byte_signed("AN", "I", "Q", ".7", buffer + 1, size - 1, instr);
	case 0xE8:
		return s7_decode_byte_signed("ON", "I", "Q", ".0", buffer + 1, size - 1, instr);
	case 0xE9:
		return s7_decode_byte_signed("ON", "I", "Q", ".1", buffer + 1, size - 1, instr);
	case 0xEA:
		return s7_decode_byte_signed("ON", "I", "Q", ".2", buffer + 1, size - 1, instr);
	case 0xEB:
		return s7_decode_byte_signed("ON", "I", "Q", ".3", buffer + 1, size - 1, instr);
	case 0xEC:
		return s7_decode_byte_signed("ON", "I", "Q", ".4", buffer + 1, size - 1, instr);
	case 0xED:
		return s7_decode_byte_signed("ON", "I", "Q", ".5", buffer + 1, size - 1, instr);
	case 0xEE:
		return s7_decode_byte_signed("ON", "I", "Q", ".6", buffer + 1, size - 1, instr);
	case 0xEF:
		return s7_decode_byte_signed("ON", "I", "Q", ".7", buffer + 1, size - 1, instr);
	case 0xF0:
		return s7_decode_byte_signed("R", "I", "Q", ".0", buffer + 1, size - 1, instr);
	case 0xF1:
		return s7_decode_byte_signed("R", "I", "Q", ".1", buffer + 1, size - 1, instr);
	case 0xF2:
		return s7_decode_byte_signed("R", "I", "Q", ".2", buffer + 1, size - 1, instr);
	case 0xF3:
		return s7_decode_byte_signed("R", "I", "Q", ".3", buffer + 1, size - 1, instr);
	case 0xF4:
		return s7_decode_byte_signed("R", "I", "Q", ".4", buffer + 1, size - 1, instr);
	case 0xF5:
		return s7_decode_byte_signed("R", "I", "Q", ".5", buffer + 1, size - 1, instr);
	case 0xF6:
		return s7_decode_byte_signed("R", "I", "Q", ".6", buffer + 1, size - 1, instr);
	case 0xF7:
		return s7_decode_byte_signed("R", "I", "Q", ".7", buffer + 1, size - 1, instr);
	case 0xF8:
		return s7_decode_byte("A", "T ", buffer + 1, size - 1, instr);
	case 0xF9:
		return s7_decode_byte("O", "T ", buffer + 1, size - 1, instr);
	case 0xFB:
		return s7_decode_FB(buffer + 1, size - 1, instr);
	case 0xFC:
		return s7_decode_byte("AN", "T ", buffer + 1, size - 1, instr);
	case 0xFD:
		return s7_decode_byte("ON", "T ", buffer + 1, size - 1, instr);
	case 0xFE:
		return s7_decode_FE(buffer + 1, size - 1, instr);
	case 0xFF:
		return s7_decode_FF(addr, buffer + 1, size - 1, instr);
	default:
		break;
	}
	return -1;
}
