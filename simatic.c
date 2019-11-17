/* libmc7 - LGPL - Copyright 2019 - deroad */

#include "simatic.h"
#include <stdio.h>
#include <time.h>

//#include <r_cons.h>

#define INSTR_MASK_N(x) ((x)&(0x0F))
#define INSTR_MASK_T(x) ((x)&(0x70))
#define INSTR_MASK_T_LOW(x) ((x)&(0x07))

#define INSTR_IS_BITLOGIC(x) ((x)>=(0x10)&&(x)<=(0x67))
#define INSTR_IS_BITLOGIC_N(x) ((x)>=(0x90)&&(x)<=(0xE7))

#define INSTR_IS_BITLOGIC_MEM(x) (INSTR_MASK_T_LOW((x))!=0&&INSTR_MASK_T_LOW((x))!=7&&(x)>=(0x31)&&(x)<=(0x6E))
#define INSTR_IS_BITLOGIC_MEM_N(x) (INSTR_MASK_T_LOW((x))!=0&&INSTR_MASK_T_LOW((x))!=7&&(x)>=(0xB1)&&(x)<=(0xEE))
#define INSTR_IS_BITLOGIC_MEM_IO(x) (((x)&0xF)>=(0x9))

#define INSTR_IS_79(x) ((x)>=(0x10)&&(x)<=(0x6D))
#define INSTR_IS_79_N(x) ((x)>=(0x90)&&(x)<=(0xED))

#define INSTR_IS_7E(x) ((x)>=(0x01)&&(x)<=(0x67))

#define INSTR_IS_MEM(x) ((x)>=(0x30)&&(x)<=(0x6E))
#define INSTR_IS_MEM_N(x) ((x)>=(0xB0)&&(x)<=(0xEE))
#define INSTR_IS_MEM_IO(x) (((x)&0x0F)>(6))

typedef float  ft32;
typedef double ft64;

#define BIN_FMT "%c%c%c%c%c%c%c%c"
#define BIN_BYTE(x) \
				(((x)&0x80)?'1':'0'), \
				(((x)&0x40)?'1':'0'), \
				(((x)&0x20)?'1':'0'), \
				(((x)&0x10)?'1':'0'), \
				(((x)&0x08)?'1':'0'), \
				(((x)&0x04)?'1':'0'), \
				(((x)&0x02)?'1':'0'), \
				(((x)&0x01)?'1':'0') 

typedef struct {
	const ut8 byte;
	const char* type;
} s7_type_t;

const s7_type_t types_def[] = {
	{0x10, "I"}, 
	{0x20, "Q"}, 
	{0x30, "M"}, 
	{0x40, "DB"}, 
	{0x50, "DI"}, 
	{0x60, "L"},
	{0xFF, NULL}
};

const s7_type_t types_x[] = {
	{0x10, "I"}, 
	{0x20, "Q"}, 
	{0x30, "M"}, 
	{0x40, "DBX"}, 
	{0x50, "DIX"}, 
	{0x60, "L"},
	{0xFF, NULL}
};

const s7_type_t types_w[] = {
	{0x00, "PIW"}, 
	{0x10, "IW"}, 
	{0x20, "QW"}, 
	{0x30, "MW"}, 
	{0x40, "DBW"}, 
	{0x50, "DIW"}, 
	{0x60, "LW"},
	{0xFF, NULL}
};

const s7_type_t types_d[] = {
	{0x00, "PID"}, 
	{0x10, "ID"}, 
	{0x20, "QD"}, 
	{0x30, "MD"}, 
	{0x40, "DBD"}, 
	{0x50, "DID"}, 
	{0x60, "LD"},
	{0xFF, NULL}
};

const s7_type_t types_b[] = {
	{0x00, "PIB"}, 
	{0x10, "IB"}, 
	{0x20, "QB"}, 
	{0x30, "MB"}, 
	{0x40, "DBB"}, 
	{0x50, "DIB"}, 
	{0x60, "LB"},
	{0xFF, NULL}
};

static inline const char* s7_type(ut8 T, const s7_type_t* types) {
	while (types->type) {
		if (T == types->byte) {
			return types->type;
		}
		types++;
	}
	return "?";
}

static inline const char* s7_mem_type(ut8 T) {
	T = INSTR_MASK_T (T);
	return (T == 0x30 ? "MD" : (T == 0x40 ? "DBD" : (T == 0x50 ? "DID" : (T == 0x60 ? "LD" : NULL))));
}

static inline ut16 s7_ut16(const ut8* buffer) {
	return ((buffer[0] << 8) | buffer[1]);
}

static inline ut32 s7_ut32(const ut8* buffer) {
	ut32 x = ((buffer[0] << 24) | (buffer[1] << 16));
	return x | ((buffer[2] << 8) | buffer[3]);
}

static inline void s7_print_bin32(const char* prefix, const ut8* buffer, char* str_buf, int str_len) {
	char bin[34];
	snprintf (bin, sizeof (bin), ""BIN_FMT""BIN_FMT""BIN_FMT""BIN_FMT, BIN_BYTE(buffer[0]), BIN_BYTE(buffer[1]), BIN_BYTE(buffer[2]), BIN_BYTE(buffer[3]));
	ut64 i;
	for (i = 0; i < 31; ++i) {
		if (bin[i] != '0') {
			break;
		}
	}
	snprintf (str_buf, str_len, "%s%s", prefix, &bin[i]);
}

static inline void s7_print_bin16(const char* prefix, const ut8* buffer, char* str_buf, int str_len) {
	char bin[18];
	snprintf (bin, sizeof (bin), ""BIN_FMT""BIN_FMT, BIN_BYTE(buffer[0]), BIN_BYTE(buffer[1]));
	ut64 i;
	for (i = 0; i < 15; ++i) {
		if (bin[i] != '0') {
			break;
		}
	}
	snprintf (str_buf, str_len, "%s%s", prefix, &bin[i]);
}

static int s7_decode_bitlogic(const char* zero_op, const char* memory_op, const char* io_op, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (buffer[0] == 0x00) {
		snprintf (str_buf, str_len, zero_op);
		return 2;
	} else if (size > 2) {
		if (INSTR_IS_BITLOGIC (buffer[0])) {
			ut16 value = s7_ut16 (buffer + 1);
			ut8  N = INSTR_MASK_N (buffer[0]);
			if (INSTR_MASK_T (buffer[0]) < 0x40 && value < 256) {
				return -1;
			}
			const char* type = s7_type (INSTR_MASK_T (buffer[0]), types_x);
			snprintf (str_buf, str_len, "%s %s %u.%u", memory_op, type, value, N);
			return 4;
		} else if (io_op && INSTR_IS_BITLOGIC_N (buffer[0])) { // io_op might be NULL, because some might not have BITLOGIC_N
			ut16 value = s7_ut16 (buffer + 1);
			ut8  N = INSTR_MASK_N (buffer[0]);
			if (INSTR_MASK_T (buffer[0]) < 0x40 && value < 256) {
				return -1;
			}
			const char* type = s7_type (INSTR_MASK_T (buffer[0]), types_x);
			snprintf (str_buf, str_len, "%s %s %u.%u", io_op, type, value, N);
			return 4;
		}
	}
	return -1;
}

static int s7_decode_byte(const char* op, const char* prefix, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	(void)size;
	ut8 N = buffer[0];
	snprintf (str_buf, str_len, "%s %s%u", op, prefix, N);
	return 2;
}

static int s7_decode_byte_s(const char* op, const char* suffix, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	(void)size;
	ut8 N = buffer[0];
	snprintf (str_buf, str_len, "%s%u%s", op, N, suffix);
	return 2;
}

static int s7_decode_4bit(const char* op, bool high, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	(void)size;
	ut8 N = high ? (buffer[0] >> 4) : (buffer[0] & 0x0F);
	snprintf (str_buf, str_len, "%s %u", op, N);
	return 2;
}

static int s7_decode_byte_signed(const char* op, const char* type_pos, const char* type_neg, const char* suffix, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	(void)size;
	ut8 N = (ut8) buffer[0];
	if (N > 0x7F) {
		N &= 0x7F;
		snprintf (str_buf, str_len, "%s %s%u%s", op, type_neg, N, suffix);
	} else {
		snprintf (str_buf, str_len, "%s %s%u%s", op, type_pos, N, suffix);
	}
	return 2;
}

static int s7_decode_cmp(const char* type, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	(void)size;
	switch (buffer[0]) {
	case 0x20:
		snprintf (str_buf, str_len, ">%s", type);
		break;
	case 0x40:
		snprintf (str_buf, str_len, ">=%s", type);
		break;
	case 0x60:
		snprintf (str_buf, str_len, "<>%s", type);
		break;
	case 0x80:
		snprintf (str_buf, str_len, "==%s", type);
		break;
	case 0xA0:
		snprintf (str_buf, str_len, "<%s", type);
		break;
	case 0xC0:
		snprintf (str_buf, str_len, "<=%s", type);
		break;
	default:
		return -1;
	}
	return 2;
}

static int s7_decode_lit16(const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (size < 2) {
		return -1;
	}
	ut16 value = s7_ut16 (buffer + 1);
	switch (buffer[0]) {
	case 0x02:
		s7_print_bin16 ("L 2#", buffer + 1, str_buf, str_len);
		break;
	case 0x03:
		snprintf (str_buf, str_len, "L %d", ((st16)value));
		break;
	case 0x05:
		if (buffer[1]) {
			snprintf (str_buf, str_len, "L '%c%c'", buffer[1], buffer[2]); // unicode hack
		} else {
			snprintf (str_buf, str_len, "L '%c'", buffer[2]); // ascii hack
		}
		break;
	case 0x06:
		snprintf (str_buf, str_len, "L B#(%02u, %02u)", buffer[1], buffer[2]);
		break;
	case 0x07:
		snprintf (str_buf, str_len, "L W#16#%u", value);
		break;
	case 0x08:
		if (value < 1000) {
			snprintf (str_buf, str_len, "L C#%u", value);
		} else {
			return -1;
		}
		break;
	case 0x0A:
		{
			// MIN L D#1990-01-01 | MAX L D#2168-12-31
			time_t rawtime = (value * 86400) + 631152000;
			struct tm *ptm = localtime (&rawtime);
			int year = 1900 + ptm->tm_year;
			int month = ptm->tm_mon + 1;
			int day = ptm->tm_mday;
			snprintf (str_buf, str_len, "L D#%d-%d-%d", year, month, day);
		}
		break;
	case 0x0C:
		{
			ft32 f = value;
			f *= 6.25;
			snprintf (str_buf, str_len, "L S5T#%.fMS", f);
		}
		break;
	default:
		return -1;
	}
	return 4;
}

static inline const char* s7_memory_loc(ut8 byte) {
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
	case 0x80: return "PI/PQ";
	case 0x81: return "I";
	case 0x82: return "Q";
	case 0x83: return "M";
	case 0x84: return "DB";
	case 0x85: return "DI";
	case 0x86: return "L";
	case 0x87: return "V";
	default: break;
	}
	return NULL;
}

static int s7_decode_lit32(const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (size < 5) {
		return -1;
	}
	ut32 value = s7_ut32 (buffer + 1);
	switch (buffer[0]) {
	case 0x01: // REAL NUMBER
		{
			ft32* f = (ft32*) &value;
			snprintf (str_buf, str_len, "L %.6f", (*f));
		}
		break;
	case 0x02:
		s7_print_bin32 ("L 2#", buffer + 1, str_buf, str_len);
		break;
	case 0x03:
		snprintf (str_buf, str_len, "L L#%d", ((st32)value));
		break;
	case 0x04:
		{
			const char* loc = s7_memory_loc (buffer[1]);
			if (!loc || (value & 0xF80000)) {
				return -1;
			}
			ut8 bit_addr = buffer[4] & 7;
			value = (value & 0x7FFF8) >> 3;
			snprintf (str_buf, str_len, "L P#%s%u.%u", loc, value, bit_addr);
		}
		break;
	case 0x06:
		snprintf (str_buf, str_len, "L B#(%02u, %02u, %02u, %02u)", buffer[1], buffer[2], buffer[3], buffer[4]);
		break;
	case 0x07:
		snprintf (str_buf, str_len, "L DW#16#%u", value);
		break;
	case 0x09:
		snprintf (str_buf, str_len, "L T#%uMS", value);
		break;
	case 0x0B:
		{
			ut32 ms = value % 1000;
			ut32 tsecs = value / 1000;
			ut32 secs  = tsecs % 60;
			ut32 mins  = (tsecs / 60) % 60;
			ut32 hours = (tsecs / 3600);
			snprintf (str_buf, str_len, "L TOD#%u:%u:%u.%u", hours, mins, secs, ms);
		}
		break;
	default:
		return -1;
	}
	return 6;
}

static int s7_decode_bitlogic_mem(const char* zero_op, bool zero_op_value, const char* memory_op, const char* io_op, const char* n_memory_op, const char* n_io_op,
	const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (buffer[0] == 0x00 && !zero_op_value) {
		snprintf (str_buf, str_len, zero_op);
		return 2;
	} else if (size > 2) {
		if (buffer[0] == 0x00 && zero_op_value) {
			st16 value = (st16) s7_ut16 (buffer + 1);
			snprintf (str_buf, str_len, "%s %d", zero_op, value);
			return 4;
		}
		const char* mem_type = s7_mem_type (buffer[0]);
		ut16 value = s7_ut16 (buffer + 1);
		if (mem_type && INSTR_IS_BITLOGIC_MEM (buffer[0])) {
			const char* op = INSTR_IS_BITLOGIC_MEM_IO (buffer[0]) ? io_op : memory_op; 
			const char* type = s7_type (INSTR_MASK_T (buffer[0] << 4), types_x);
			snprintf (str_buf, str_len, "%s %s [%s %u]", op, type, mem_type, value);
			return 4;
		} else if (mem_type && INSTR_IS_BITLOGIC_MEM_N (buffer[0])) {
			const char* op = INSTR_IS_BITLOGIC_MEM_IO (buffer[0]) ? n_io_op : n_memory_op; 
			if (!op) {
				return -1;
			}
			const char* type = s7_type (INSTR_MASK_T (buffer[0] << 4), types_x);
			snprintf (str_buf, str_len, "%s %s [%s %u]", op, type, mem_type, value);
			return 4;
		}
	}
	return -1;
}

static int s7_decode_jump(const char* op, ut64 addr, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (size > 2) {
		st16 N = (st16) s7_ut16 (buffer + 1);
		addr += N;
		snprintf (str_buf, str_len, "%s 0x%"PFMT64x, op, addr);
		return 4;
	}
	return -1;
}

typedef struct {
	ut8 byte;
	const char* op;
} s7_static_t;

static int s7_decode_static(const s7_static_t* s, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	(void)size;
	while (s && s->op) {
		if (buffer[0] == s->byte) {
			snprintf (str_buf, str_len, "%s", s->op);
			return 2;
		}
		s++;
	}
	return -1;
}

static int s7_decode_79(const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (buffer[0] == 0x00) {
		snprintf (str_buf, str_len, "+I");
		return 2;
	} else if (size > 2) {
		ut8 op = buffer[0] & 0x07;
		ut8 ar = (buffer[0] & 0x08) ? 2 : 1;
		ut16 value = s7_ut16 (buffer + 1);
		const char* type = s7_type (INSTR_MASK_T (buffer[0]), types_x);
		if (INSTR_IS_79 (buffer[0])) {
			switch (op) {
			case 0x00:
				snprintf (str_buf, str_len, "A %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x01:
				snprintf (str_buf, str_len, "AN %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x02:
				snprintf (str_buf, str_len, "O %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x03:
				snprintf (str_buf, str_len, "ON %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x04:
				snprintf (str_buf, str_len, "X %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x05:
				snprintf (str_buf, str_len, "XN %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			default:
				return -1;
			}
		} else if (INSTR_IS_79_N (buffer[0])) {
			switch (op) {
			case 0x00:
				snprintf (str_buf, str_len, "S %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x01:
				snprintf (str_buf, str_len, "R %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x02:
				snprintf (str_buf, str_len, "= %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x04:
				snprintf (str_buf, str_len, "FP %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			case 0x05:
				snprintf (str_buf, str_len, "FN %s [AR%d, P#%u.%u]", type, ar, (value >> 3), (value & 7));
				return 4;
			default:
				return -1;
			}
		}
	}
	return -1;
}

static inline const char* s7_type_7E(ut8 T) {
	if (INSTR_MASK_T (T) == 0x00) {
		return INSTR_MASK_T_LOW (T) > 0x03 ? "PQ" : "PI";
	}
	T = INSTR_MASK_T (T);
	return (T == 0x10 ? "I" : (T == 0x20 ? "Q" : (T == 0x30 ? "M" : (T == 0x40 ? "DB" : (T == 0x50 ? "DI" : (T == 0x60 ? "L" : "?"))))));
}

static int s7_decode_7E(const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (size > 2 && INSTR_IS_7E (buffer[0])) {
		ut8 op = buffer[0] & 0x07;
		ut16 value = s7_ut16 (buffer + 1);
		const char* type = s7_type_7E (buffer[0]);
		switch (op) {
		case 0x01:
			snprintf (str_buf, str_len, "L %sB %u", type, value);
			return 4;
		case 0x02:
			snprintf (str_buf, str_len, "L %sW %u", type, value);
			return 4;
		case 0x03:
			snprintf (str_buf, str_len, "L %sD %u", type, value);
			return 4;
		case 0x05:
			snprintf (str_buf, str_len, "T %sB %u", type, value);
			return 4;
		case 0x06:
			snprintf (str_buf, str_len, "T %sW %u", type, value);
			return 4;
		case 0x07:
			snprintf (str_buf, str_len, "T %sD %u", type, value);
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

static int s7_decode_mem(const char* zero_op, const char* memory_op, const char* io_op, const s7_type_t* memory_type, const s7_type_t* io_type, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (buffer[0] == 0x00) {
		snprintf (str_buf, str_len, zero_op);
		return 2;
	} else if (size > 2) {
		const char* mem_type = s7_mem_type (buffer[0]);
		ut16 value = s7_ut16 (buffer + 1);
		if (mem_type && INSTR_IS_MEM (buffer[0])) {
			const char* type = s7_type (INSTR_MASK_T (buffer[0] << 4), INSTR_IS_MEM_IO (buffer[0]) ? io_type : memory_type);
			snprintf (str_buf, str_len, "%s %s [%s %u]", memory_op, type, mem_type, value);
			return 4;
		} else if (mem_type && INSTR_IS_MEM_N (buffer[0])) {
			const char* type = s7_type (INSTR_MASK_T (buffer[0] << 4), INSTR_IS_MEM_IO (buffer[0]) ? io_type : memory_type);
			snprintf (str_buf, str_len, "%s %s [%s %u]", io_op, type, mem_type, value);
			return 4;
		}
	}
	return -1;
}

static int s7_decode_BE(const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (size > 2 && buffer[0] >= 0x11 && buffer[0] <= 0x6F && (buffer[0] & 0x0F)) {
		ut8 op = buffer[0] & 0x0F;
		ut16 value = s7_ut16 (buffer + 1);
		const char* type = s7_type (INSTR_MASK_T (buffer[0]), types_def);
		switch (op) {
		case 0x01:
			snprintf (str_buf, str_len, "L %sB [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x02:
			snprintf (str_buf, str_len, "L %sW [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x03:
			snprintf (str_buf, str_len, "L %sD [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x05:
			snprintf (str_buf, str_len, "T %sB [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x06:
			snprintf (str_buf, str_len, "T %sW [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x07:
			snprintf (str_buf, str_len, "T %sD [AR1, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x09:
			snprintf (str_buf, str_len, "L %sB [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0A:
			snprintf (str_buf, str_len, "L %sW [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0B:
			snprintf (str_buf, str_len, "L %sD [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0D:
			snprintf (str_buf, str_len, "T %sB [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0E:
			snprintf (str_buf, str_len, "T %sW [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		case 0x0F:
			snprintf (str_buf, str_len, "T %sD [AR2, P#%u.%u]", type, (value >> 3), (value & 7));
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

static int s7_decode_BF(const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if (buffer[0] == 0x00) {
		snprintf (str_buf, str_len, ")");
		return 2;
	} else if (size > 2) {
		ut16 value = s7_ut16 (buffer + 1);
		switch (buffer[0]) {
		case 0x30:
			snprintf (str_buf, str_len, "A T [MW %d]", value);
			return 4;
		case 0x31:
			snprintf (str_buf, str_len, "AN T [MW %d]", value);
			return 4;
		case 0x32:
			snprintf (str_buf, str_len, "O T [MW %d]", value);
			return 4;
		case 0x33:
			snprintf (str_buf, str_len, "ON T [MW %d]", value);
			return 4;
		case 0x34:
			snprintf (str_buf, str_len, "X T [MW %d]", value);
			return 4;
		case 0x35:
			snprintf (str_buf, str_len, "XN T [MW %d]", value);
			return 4;
		case 0x36:
			snprintf (str_buf, str_len, "L T [MW %d]", value);
			return 4;
		case 0x38:
			snprintf (str_buf, str_len, "FR T [MW %d]", value);
			return 4;
		case 0x39:
			snprintf (str_buf, str_len, "LC T [MW %d]", value);
			return 4;
		case 0x3A:
			snprintf (str_buf, str_len, "SF T [MW %d]", value);
			return 4;
		case 0x3B:
			snprintf (str_buf, str_len, "SE T [MW %d]", value);
			return 4;
		case 0x3C:
			snprintf (str_buf, str_len, "SD T [MW %d]", value);
			return 4;
		case 0x3D:
			snprintf (str_buf, str_len, "SS T [MW %d]", value);
			return 4;
		case 0x3E:
			snprintf (str_buf, str_len, "SP T [MW %d]", value);
			return 4;
		case 0x3F:
			snprintf (str_buf, str_len, "R T [MW %d]", value);
			return 4;
		case 0x40:
			snprintf (str_buf, str_len, "A T [DBW %d]", value);
			return 4;
		case 0x41:
			snprintf (str_buf, str_len, "AN T [DBW %d]", value);
			return 4;
		case 0x42:
			snprintf (str_buf, str_len, "O T [DBW %d]", value);
			return 4;
		case 0x43:
			snprintf (str_buf, str_len, "ON T [DBW %d]", value);
			return 4;
		case 0x44:
			snprintf (str_buf, str_len, "X T [DBW %d]", value);
			return 4;
		case 0x45:
			snprintf (str_buf, str_len, "XN T [DBW %d]", value);
			return 4;
		case 0x46:
			snprintf (str_buf, str_len, "L T [DBW %d]", value);
			return 4;
		case 0x48:
			snprintf (str_buf, str_len, "FR T [DBW %d]", value);
			return 4;
		case 0x49:
			snprintf (str_buf, str_len, "LC T [DBW %d]", value);
			return 4;
		case 0x4A:
			snprintf (str_buf, str_len, "SF T [DBW %d]", value);
			return 4;
		case 0x4B:
			snprintf (str_buf, str_len, "SE T [DBW %d]", value);
			return 4;
		case 0x4C:
			snprintf (str_buf, str_len, "SD T [DBW %d]", value);
			return 4;
		case 0x4D:
			snprintf (str_buf, str_len, "SS T [DBW %d]", value);
			return 4;
		case 0x4E:
			snprintf (str_buf, str_len, "SP T [DBW %d]", value);
			return 4;
		case 0x4F:
			snprintf (str_buf, str_len, "R T [DBW %d]", value);
			return 4;
		case 0x50:
			snprintf (str_buf, str_len, "A T [DIW %d]", value);
			return 4;
		case 0x51:
			snprintf (str_buf, str_len, "AN T [DIW %d]", value);
			return 4;
		case 0x52:
			snprintf (str_buf, str_len, "O T [DIW %d]", value);
			return 4;
		case 0x53:
			snprintf (str_buf, str_len, "ON T [DIW %d]", value);
			return 4;
		case 0x54:
			snprintf (str_buf, str_len, "X T [DIW %d]", value);
			return 4;
		case 0x55:
			snprintf (str_buf, str_len, "XN T [DIW %d]", value);
			return 4;
		case 0x5C:
			snprintf (str_buf, str_len, "SD T [DIW %d]", value);
			return 4;
		case 0x5D:
			snprintf (str_buf, str_len, "SS T [DIW %d]", value);
			return 4;
		case 0x5E:
			snprintf (str_buf, str_len, "SP T [DIW %d]", value);
			return 4;
		case 0x5F:
			snprintf (str_buf, str_len, "R T [DIW %d]", value);
			return 4;
		case 0x60:
			snprintf (str_buf, str_len, "A T [LW %d]", value);
			return 4;
		case 0x61:
			snprintf (str_buf, str_len, "AN T [LW %d]", value);
			return 4;
		case 0x62:
			snprintf (str_buf, str_len, "O T [LW %d]", value);
			return 4;
		case 0x63:
			snprintf (str_buf, str_len, "ON T [LW %d]", value);
			return 4;
		case 0x64:
			snprintf (str_buf, str_len, "X T [LW %d]", value);
			return 4;
		case 0x65:
			snprintf (str_buf, str_len, "XN T [LW %d]", value);
			return 4;
		case 0x66:
			snprintf (str_buf, str_len, "L T [LW %d]", value);
			return 4;
		case 0x68:
			snprintf (str_buf, str_len, "FR T [LW %d]", value);
			return 4;
		case 0x69:
			snprintf (str_buf, str_len, "LC T [LW %d]", value);
			return 4;
		case 0x6A:
			snprintf (str_buf, str_len, "SF T [LW %d]", value);
			return 4;
		case 0x6B:
			snprintf (str_buf, str_len, "SE T [LW %d]", value);
			return 4;
		case 0x6C:
			snprintf (str_buf, str_len, "SD T [LW %d]", value);
			return 4;
		case 0x6D:
			snprintf (str_buf, str_len, "SS T [LW %d]", value);
			return 4;
		case 0x6E:
			snprintf (str_buf, str_len, "SP T [LW %d]", value);
			return 4;
		case 0x6F:
			snprintf (str_buf, str_len, "R T [LW %d]", value);
			return 4;
		case 0xB0:
			snprintf (str_buf, str_len, "A C [MW %d]", value);
			return 4;
		case 0xB1:
			snprintf (str_buf, str_len, "AN C [MW %d]", value);
			return 4;
		case 0xB2:
			snprintf (str_buf, str_len, "O C [MW %d]", value);
			return 4;
		case 0xB3:
			snprintf (str_buf, str_len, "ON C [MW %d]", value);
			return 4;
		case 0xB4:
			snprintf (str_buf, str_len, "X C [MW %d]", value);
			return 4;
		case 0xB5:
			snprintf (str_buf, str_len, "XN C [MW %d]", value);
			return 4;
		case 0xB6:
			snprintf (str_buf, str_len, "L C [MW %d]", value);
			return 4;
		case 0xB8:
			snprintf (str_buf, str_len, "FR C [MW %d]", value);
			return 4;
		case 0xB9:
			snprintf (str_buf, str_len, "LC C [MW %d]", value);
			return 4;
		case 0xBA:
			snprintf (str_buf, str_len, "CD C [MW %d]", value);
			return 4;
		case 0xBB:
			snprintf (str_buf, str_len, "S C [MW %d]", value);
			return 4;
		case 0xBD:
			snprintf (str_buf, str_len, "CU C [MW %d]", value);
			return 4;
		case 0xBF:
			snprintf (str_buf, str_len, "R C [MW %d]", value);
			return 4;
		case 0xC0:
			snprintf (str_buf, str_len, "A C [DBW %d]", value);
			return 4;
		case 0xC1:
			snprintf (str_buf, str_len, "AN C [DBW %d]", value);
			return 4;
		case 0xC2:
			snprintf (str_buf, str_len, "O C [DBW %d]", value);
			return 4;
		case 0xC3:
			snprintf (str_buf, str_len, "ON C [DBW %d]", value);
			return 4;
		case 0xC4:
			snprintf (str_buf, str_len, "X C [DBW %d]", value);
			return 4;
		case 0xC5:
			snprintf (str_buf, str_len, "XN C [DBW %d]", value);
			return 4;
		case 0xC6:
			snprintf (str_buf, str_len, "L C [DBW %d]", value);
			return 4;
		case 0xC8:
			snprintf (str_buf, str_len, "FR C [DBW %d]", value);
			return 4;
		case 0xC9:
			snprintf (str_buf, str_len, "LC C [DBW %d]", value);
			return 4;
		case 0xCA:
			snprintf (str_buf, str_len, "CD C [DBW %d]", value);
			return 4;
		case 0xCB:
			snprintf (str_buf, str_len, "S C [DBW %d]", value);
			return 4;
		case 0xCD:
			snprintf (str_buf, str_len, "CU C [DBW %d]", value);
			return 4;
		case 0xCF:
			snprintf (str_buf, str_len, "R C [DBW %d]", value);
			return 4;
		case 0xD0:
			snprintf (str_buf, str_len, "A C [DIW %d]", value);
			return 4;
		case 0xD1:
			snprintf (str_buf, str_len, "AN C [DIW %d]", value);
			return 4;
		case 0xD2:
			snprintf (str_buf, str_len, "O C [DIW %d]", value);
			return 4;
		case 0xD3:
			snprintf (str_buf, str_len, "ON C [DIW %d]", value);
			return 4;
		case 0xD4:
			snprintf (str_buf, str_len, "X C [DIW %d]", value);
			return 4;
		case 0xD5:
			snprintf (str_buf, str_len, "XN C [DIW %d]", value);
			return 4;
		case 0xD6:
			snprintf (str_buf, str_len, "L C [DIW %d]", value);
			return 4;
		case 0xD8:
			snprintf (str_buf, str_len, "FR C [DIW %d]", value);
			return 4;
		case 0xD9:
			snprintf (str_buf, str_len, "LC C [DIW %d]", value);
			return 4;
		case 0xDA:
			snprintf (str_buf, str_len, "CD C [DIW %d]", value);
			return 4;
		case 0xDB:
			snprintf (str_buf, str_len, "S C [DIW %d]", value);
			return 4;
		case 0xDD:
			snprintf (str_buf, str_len, "CU C [DIW %d]", value);
			return 4;
		case 0xDF:
			snprintf (str_buf, str_len, "R C [DIW %d]", value);
			return 4;
		case 0xE0:
			snprintf (str_buf, str_len, "A C [LW %d]", value);
			return 4;
		case 0xE1:
			snprintf (str_buf, str_len, "AN C [LW %d]", value);
			return 4;
		case 0xE2:
			snprintf (str_buf, str_len, "O C [LW %d]", value);
			return 4;
		case 0xE3:
			snprintf (str_buf, str_len, "ON C [LW %d]", value);
			return 4;
		case 0xE4:
			snprintf (str_buf, str_len, "X C [LW %d]", value);
			return 4;
		case 0xE5:
			snprintf (str_buf, str_len, "XN C [LW %d]", value);
			return 4;
		case 0xE6:
			snprintf (str_buf, str_len, "L C [LW %d]", value);
			return 4;
		case 0xE8:
			snprintf (str_buf, str_len, "FR C [LW %d]", value);
			return 4;
		case 0xE9:
			snprintf (str_buf, str_len, "LC C [LW %d]", value);
			return 4;
		case 0xEA:
			snprintf (str_buf, str_len, "CD C [LW %d]", value);
			return 4;
		case 0xEB:
			snprintf (str_buf, str_len, "S C [LW %d]", value);
			return 4;
		case 0xED:
			snprintf (str_buf, str_len, "CU C [LW %d]", value);
			return 4;
		case 0xEF:
			snprintf (str_buf, str_len, "R C [LW %d]", value);
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

static int s7_decode_FB(const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	switch (buffer[0]) {
	case 0x00:
		snprintf (str_buf, str_len, "O");
		return 2;
	case 0x3C:
		snprintf (str_buf, str_len, "L DBLG");
		return 2;
	case 0x3D:
		snprintf (str_buf, str_len, "L DILG");
		return 2;
	case 0x4C:
		snprintf (str_buf, str_len, "L DBNO");
		return 2;
	case 0x4D:
		snprintf (str_buf, str_len, "L DINO");
		return 2;
	case 0x7C:
		snprintf (str_buf, str_len, "CDB");
		return 2;
	default:
		break;
	}
	if (size > 2) {
		ut16 value = s7_ut16 (buffer + 1);
		switch (buffer[0]) {
		case 0x01:
			snprintf (str_buf, str_len, "L B [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x02:
			snprintf (str_buf, str_len, "L W [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x03:
			snprintf (str_buf, str_len, "L D [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x05:
			snprintf (str_buf, str_len, "T B [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x06:
			snprintf (str_buf, str_len, "T W [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x07:
			snprintf (str_buf, str_len, "T D [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x09:
			snprintf (str_buf, str_len, "L B [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0B:
			snprintf (str_buf, str_len, "L W [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0C:
			snprintf (str_buf, str_len, "L D [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0D:
			snprintf (str_buf, str_len, "T B [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0E:
			snprintf (str_buf, str_len, "T W [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x0F:
			snprintf (str_buf, str_len, "T D [AR2, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x10:
			snprintf (str_buf, str_len, "A [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x11:
			snprintf (str_buf, str_len, "AN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x12:
			snprintf (str_buf, str_len, "O [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x13:
			snprintf (str_buf, str_len, "ON [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x14:
			snprintf (str_buf, str_len, "X [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x15:
			snprintf (str_buf, str_len, "XN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x18:
			snprintf (str_buf, str_len, "A [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x19:
			snprintf (str_buf, str_len, "AN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x1A:
			snprintf (str_buf, str_len, "O [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x1B:
			snprintf (str_buf, str_len, "ON [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x1C:
			snprintf (str_buf, str_len, "X [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x1D:
			snprintf (str_buf, str_len, "XN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x20:
			snprintf (str_buf, str_len, "S [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x21:
			snprintf (str_buf, str_len, "R [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x22:
			snprintf (str_buf, str_len, "= [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x24:
			snprintf (str_buf, str_len, "FP [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x25:
			snprintf (str_buf, str_len, "FN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x28:
			snprintf (str_buf, str_len, "S [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x29:
			snprintf (str_buf, str_len, "R [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x2A:
			snprintf (str_buf, str_len, "= [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x2C:
			snprintf (str_buf, str_len, "FP [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x2D:
			snprintf (str_buf, str_len, "FN [AR1, P#%u.%u]", (value >> 3), (value & 7));
			return 4;
		case 0x30:
			snprintf (str_buf, str_len, "UC FC [MW %u]", value);
			return 4;
		case 0x31:
			snprintf (str_buf, str_len, "CC FC [MW %u]", value);
			return 4;
		case 0x32:
			snprintf (str_buf, str_len, "UC FB [MW %u]", value);
			return 4;
		case 0x33:
			snprintf (str_buf, str_len, "CC FB [MW %u]", value);
			return 4;
		case 0x38:
			snprintf (str_buf, str_len, "OPN DB [MW %u]", value);
			return 4;
		case 0x39:
			snprintf (str_buf, str_len, "OPN DI [MW %u]", value);
			return 4;
		case 0x40:
			snprintf (str_buf, str_len, "UC FC [DBW %u]", value);
			return 4;
		case 0x41:
			snprintf (str_buf, str_len, "CC FC [DBW %u]", value);
			return 4;
		case 0x42:
			snprintf (str_buf, str_len, "UC FB [DBW %u]", value);
			return 4;
		case 0x43:
			snprintf (str_buf, str_len, "CC FB [DBW %u]", value);
			return 4;
		case 0x48:
			snprintf (str_buf, str_len, "OPN DB [DBW %u]", value);
			return 4;
		case 0x49:
			snprintf (str_buf, str_len, "OPN DI [DBW %u]", value);
			return 4;
		case 0x50:
			snprintf (str_buf, str_len, "UC FC [DIW %u]", value);
			return 4;
		case 0x51:
			snprintf (str_buf, str_len, "CC FC [DIW %u]", value);
			return 4;
		case 0x52:
			snprintf (str_buf, str_len, "UC FB [DIW %u]", value);
			return 4;
		case 0x53:
			snprintf (str_buf, str_len, "CC FB [DIW %u]", value);
			return 4;
		case 0x58:
			snprintf (str_buf, str_len, "OPN DB [DIW %u]", value);
			return 4;
		case 0x59:
			snprintf (str_buf, str_len, "OPN DI [DIW %u]", value);
			return 4;
		case 0x60:
			snprintf (str_buf, str_len, "UC FC [LW %u]", value);
			return 4;
		case 0x61:
			snprintf (str_buf, str_len, "CC FC [LW %u]", value);
			return 4;
		case 0x62:
			snprintf (str_buf, str_len, "UC FB [LW %u]", value);
			return 4;
		case 0x63:
			snprintf (str_buf, str_len, "CC FB [LW %u]", value);
			return 4;
		case 0x68:
			snprintf (str_buf, str_len, "OPN DB [LW %u]", value);
			return 4;
		case 0x69:
			snprintf (str_buf, str_len, "OPN DI [LW %u]", value);
			return 4;
		case 0x70:
			snprintf (str_buf, str_len, "UC FC%u", value);
			return 4;
		case 0x71:
			snprintf (str_buf, str_len, "CC FC%u", value);
			return 4;
		case 0x72:
			snprintf (str_buf, str_len, "UC FC%u", value);
			return 4;
		case 0x73:
			snprintf (str_buf, str_len, "CC FB%u", value);
			return 4;
		case 0x74:
			snprintf (str_buf, str_len, "UC SFC%u", value);
			return 4;
		case 0x76:
			snprintf (str_buf, str_len, "UC SFB%u", value);
			return 4;
		case 0x78:
			snprintf (str_buf, str_len, "OPN DB%u", value);
			return 4;
		case 0x79:
			snprintf (str_buf, str_len, "OPN DI%u", value);
			return 4;
		case 0x80:
			snprintf (str_buf, str_len, "A [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x81:
			snprintf (str_buf, str_len, "AN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x82:
			snprintf (str_buf, str_len, "O [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x83:
			snprintf (str_buf, str_len, "ON [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x84:
			snprintf (str_buf, str_len, "X [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x85:
			snprintf (str_buf, str_len, "XN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x90:
			snprintf (str_buf, str_len, "S [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x91:
			snprintf (str_buf, str_len, "R [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x92:
			snprintf (str_buf, str_len, "= [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x94:
			snprintf (str_buf, str_len, "FP [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0x95:
			snprintf (str_buf, str_len, "FN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BOOLEAN
			return 4;
		case 0xA0:
			snprintf (str_buf, str_len, "A [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA1:
			snprintf (str_buf, str_len, "AN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA2:
			snprintf (str_buf, str_len, "O [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA3:
			snprintf (str_buf, str_len, "ON [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA4:
			snprintf (str_buf, str_len, "X [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA5:
			snprintf (str_buf, str_len, "XN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA6:
			snprintf (str_buf, str_len, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA8:
			snprintf (str_buf, str_len, "FR [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xA9:
			snprintf (str_buf, str_len, "LC [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAA:
			snprintf (str_buf, str_len, "SF [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAB:
			snprintf (str_buf, str_len, "SE [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAC:
			snprintf (str_buf, str_len, "SD [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAD:
			snprintf (str_buf, str_len, "SS [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAE:
			snprintf (str_buf, str_len, "SP [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xAF:
			snprintf (str_buf, str_len, "R [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_TIMER
			return 4;
		case 0xB0:
			snprintf (str_buf, str_len, "A [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB1:
			snprintf (str_buf, str_len, "AN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB2:
			snprintf (str_buf, str_len, "O [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB3:
			snprintf (str_buf, str_len, "ON [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB4:
			snprintf (str_buf, str_len, "X [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB5:
			snprintf (str_buf, str_len, "XN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB6:
			snprintf (str_buf, str_len, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB8:
			snprintf (str_buf, str_len, "FR [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xB9:
			snprintf (str_buf, str_len, "LC [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xBA:
			snprintf (str_buf, str_len, "CD [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xBB:
			snprintf (str_buf, str_len, "S [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xBD:
			snprintf (str_buf, str_len, "CU [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xBF:
			snprintf (str_buf, str_len, "R [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_COUNTER
			return 4;
		case 0xC1:
			snprintf (str_buf, str_len, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BYTE
			return 4;
		case 0xC2:
			snprintf (str_buf, str_len, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_WORD
			return 4;
		case 0xC3:
			snprintf (str_buf, str_len, "L [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_DWORD
			return 4;
		case 0xC5:
			snprintf (str_buf, str_len, "T [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BYTE
			return 4;
		case 0xC6:
			snprintf (str_buf, str_len, "T [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_WORD
			return 4;
		case 0xC7:
			snprintf (str_buf, str_len, "T [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_DWORD
			return 4;
		case 0xD0:
			snprintf (str_buf, str_len, "UC [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BLOCK_FC
			return 4;
		case 0xD2:
			snprintf (str_buf, str_len, "UC [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BLOCK_FB
			return 4;
		case 0xD8:
			snprintf (str_buf, str_len, "OPN [P#%u.%u]", (value >> 1), (value & 1)); // PARAMETER_BLOCK_DB
			return 4;
		case 0xE0:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "A T%u", value);
			return 4;
		case 0xE1:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "AN T%u", value);
			return 4;
		case 0xE2:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "O T%u", value);
			return 4;
		case 0xE3:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "ON T%u", value);
			return 4;
		case 0xE4:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "X T%u", value);
			return 4;
		case 0xE5:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "XN T%u", value);
			return 4;
		case 0xE6:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "L T%u", value);
			return 4;
		case 0xE8:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "FR T%u", value);
			return 4;
		case 0xE9:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "LC T%u", value);
			return 4;
		case 0xEA:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "SF T%u", value);
			return 4;
		case 0xEB:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "SE T%u", value);
			return 4;
		case 0xEC:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "SD T%u", value);
			return 4;
		case 0xED:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "SS T%u", value);
			return 4;
		case 0xEE:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "SP T%u", value);
			return 4;
		case 0xEF:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "R T%u", value);
			return 4;
		case 0xF0:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "A C%u", value);
			return 4;
		case 0xF1:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "AN C%u", value);
			return 4;
		case 0xF2:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "O C%u", value);
			return 4;
		case 0xF3:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "ON C%u", value);
			return 4;
		case 0xF4:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "X C%u", value);
			return 4;
		case 0xF5:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "XN C%u", value);
			return 4;
		case 0xF6:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "L C%u", value);
			return 4;
		case 0xF8:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "FR C%u", value);
			return 4;
		case 0xF9:
			if (value < 256) {
				return -1;
			}
			snprintf (str_buf, str_len, "LC C%u", value);
			return 4;
		case 0xFA:
			snprintf (str_buf, str_len, "CD %u", value);
			return 4;
		case 0xFB:
			snprintf (str_buf, str_len, "S %u", value);
			return 4;
		case 0xFD:
			snprintf (str_buf, str_len, "CU %u", value);
			return 4;
		case 0xFF:
			snprintf (str_buf, str_len, "R %u", value);
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

static int s7_decode_FE(const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	if ((buffer[0] & 0xF0) == 0xC0) {
		ut8 value = (buffer[0] & 0x0F);
		snprintf (str_buf, str_len, "SRD %u", value);
		return 2;
	}
	switch (buffer[0]) {
	case 0x01:
		snprintf (str_buf, str_len, "LAR1 AR2");
		return 2;
	case 0x04:
		snprintf (str_buf, str_len, "LAR1");
		return 2;
	case 0x05:
		snprintf (str_buf, str_len, "TAR1");
		return 2;
	case 0x06:
		snprintf (str_buf, str_len, "+AR1");
		return 2;
	case 0x08:
		snprintf (str_buf, str_len, "CAR");
		return 2;
	case 0x09:
		snprintf (str_buf, str_len, "TAR1 AR2");
		return 2;
	case 0x0C:
		snprintf (str_buf, str_len, "LAR2");
		return 2;
	case 0x0D:
		snprintf (str_buf, str_len, "TAR2");
		return 2;
	case 0x0E:
		snprintf (str_buf, str_len, "+AR2");
		return 2;
	default:
		break;
	}
	if (size > 2) {
		switch (buffer[0]) {
		case 0x03:
			if (size > 4) {
				ut32 value = s7_ut32 (buffer + 1);
				snprintf (str_buf, str_len, "LAR1 P#%x", value);
				return 6;
			}
			return -1;
		case 0x0B:
			if (size > 4) {
				ut32 value = s7_ut32 (buffer + 1);
				snprintf (str_buf, str_len, "LAR2 P#%x", value);
				return 6;
			}
			return -1;
		case 0x02:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "+AR1 P#%x", value);
				return 4;
			}
		case 0x0A:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "+AR2 P#%x", value);
				return 4;
			}
		case 0x33:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "LAR1 MD %u", value);
				return 4;
			}
		case 0x37:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "TAR1 MD %u", value);
				return 4;
			}
		case 0x3B:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "LAR2 MD %u", value);
				return 4;
			}
		case 0x3F:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "TAR2 MD %u", value);
				return 4;
			}
		case 0x43:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "LAR1 DBD %u", value);
				return 4;
			}
		case 0x47:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "TAR1 DBD %u", value);
				return 4;
			}
		case 0x4B:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "LAR2 DBD %u", value);
				return 4;
			}
		case 0x4F:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "TAR2 DBD %u", value);
				return 4;
			}
		case 0x53:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "LAR1 DID %u", value);
				return 4;
			}
		case 0x57:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "TAR1 DID %u", value);
				return 4;
			}
		case 0x5B:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "LAR2 DID %u", value);
				return 4;
			}
		case 0x5F:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "TAR2 DID %u", value);
				return 4;
			}
		case 0x63:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "LAR1 LD %u", value);
				return 4;
			}
		case 0x67:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "TAR1 LD %u", value);
				return 4;
			}
		case 0x6B:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "LAR2 LD %u", value);
				return 4;
			}
		case 0x6F:
			{
				ut16 value = s7_ut16 (buffer + 1);
				snprintf (str_buf, str_len, "TAR2 LD %u", value);
				return 4;
			}
		}
	}
	return -1;
}

static int s7_decode_FF(ut64 addr, const ut8* buffer, const ut64 size, char* str_buf, int str_len) {
	switch (buffer[0]) {
	case 0x00:
		snprintf (str_buf, str_len, "A OS");
		return 2;
	case 0x01:
		snprintf (str_buf, str_len, "AN OS");
		return 2;
	case 0x02:
		snprintf (str_buf, str_len, "O OS");
		return 2;
	case 0x03:
		snprintf (str_buf, str_len, "ON OS");
		return 2;
	case 0x04:
		snprintf (str_buf, str_len, "X OS");
		return 2;
	case 0x05:
		snprintf (str_buf, str_len, "XN OS");
		return 2;
	case 0x10:
		snprintf (str_buf, str_len, "A OV");
		return 2;
	case 0x11:
		snprintf (str_buf, str_len, "AN OV");
		return 2;
	case 0x12:
		snprintf (str_buf, str_len, "O OV");
		return 2;
	case 0x13:
		snprintf (str_buf, str_len, "ON OV");
		return 2;
	case 0x14:
		snprintf (str_buf, str_len, "X OV");
		return 2;
	case 0x15:
		snprintf (str_buf, str_len, "XN OV");
		return 2;
	case 0x20:
		snprintf (str_buf, str_len, "A >0");
		return 2;
	case 0x21:
		snprintf (str_buf, str_len, "AN >0");
		return 2;
	case 0x22:
		snprintf (str_buf, str_len, "O >0");
		return 2;
	case 0x23:
		snprintf (str_buf, str_len, "ON >0");
		return 2;
	case 0x24:
		snprintf (str_buf, str_len, "X >0");
		return 2;
	case 0x25:
		snprintf (str_buf, str_len, "XN >0");
		return 2;
	case 0x40:
		snprintf (str_buf, str_len, "A <0");
		return 2;
	case 0x41:
		snprintf (str_buf, str_len, "AN <0");
		return 2;
	case 0x42:
		snprintf (str_buf, str_len, "O <0");
		return 2;
	case 0x43:
		snprintf (str_buf, str_len, "ON <0");
		return 2;
	case 0x44:
		snprintf (str_buf, str_len, "X <0");
		return 2;
	case 0x45:
		snprintf (str_buf, str_len, "XN <0");
		return 2;
	case 0x50:
		snprintf (str_buf, str_len, "A UO");
		return 2;
	case 0x51:
		snprintf (str_buf, str_len, "AN UO");
		return 2;
	case 0x52:
		snprintf (str_buf, str_len, "O UO");
		return 2;
	case 0x53:
		snprintf (str_buf, str_len, "ON UO");
		return 2;
	case 0x54:
		snprintf (str_buf, str_len, "X UO");
		return 2;
	case 0x55:
		snprintf (str_buf, str_len, "XN UO");
		return 2;
	case 0x60:
		snprintf (str_buf, str_len, "A <>0");
		return 2;
	case 0x61:
		snprintf (str_buf, str_len, "AN <>0");
		return 2;
	case 0x62:
		snprintf (str_buf, str_len, "O <>0");
		return 2;
	case 0x63:
		snprintf (str_buf, str_len, "ON <>0");
		return 2;
	case 0x64:
		snprintf (str_buf, str_len, "X <>0");
		return 2;
	case 0x65:
		snprintf (str_buf, str_len, "XN <>0");
		return 2;
	case 0x80:
		snprintf (str_buf, str_len, "A ==0");
		return 2;
	case 0x81:
		snprintf (str_buf, str_len, "AN ==0");
		return 2;
	case 0x82:
		snprintf (str_buf, str_len, "O ==0");
		return 2;
	case 0x83:
		snprintf (str_buf, str_len, "ON ==0");
		return 2;
	case 0x84:
		snprintf (str_buf, str_len, "X ==0");
		return 2;
	case 0x85:
		snprintf (str_buf, str_len, "XN ==0");
		return 2;
	case 0xA0:
		snprintf (str_buf, str_len, "A >=0");
		return 2;
	case 0xA1:
		snprintf (str_buf, str_len, "AN >=0");
		return 2;
	case 0xA2:
		snprintf (str_buf, str_len, "O >=0");
		return 2;
	case 0xA3:
		snprintf (str_buf, str_len, "ON >=0");
		return 2;
	case 0xA4:
		snprintf (str_buf, str_len, "X >=0");
		return 2;
	case 0xA5:
		snprintf (str_buf, str_len, "XN >=0");
		return 2;
	case 0xC0:
		snprintf (str_buf, str_len, "A <=0");
		return 2;
	case 0xC1:
		snprintf (str_buf, str_len, "AN <=0");
		return 2;
	case 0xC2:
		snprintf (str_buf, str_len, "O <=0");
		return 2;
	case 0xC3:
		snprintf (str_buf, str_len, "ON <=0");
		return 2;
	case 0xC4:
		snprintf (str_buf, str_len, "X <=0");
		return 2;
	case 0xC5:
		snprintf (str_buf, str_len, "XN <=0");
		return 2;
	case 0xE0:
		snprintf (str_buf, str_len, "A BR");
		return 2;
	case 0xE1:
		snprintf (str_buf, str_len, "AN BR");
		return 2;
	case 0xE2:
		snprintf (str_buf, str_len, "O BR");
		return 2;
	case 0xE3:
		snprintf (str_buf, str_len, "ON BR");
		return 2;
	case 0xE4:
		snprintf (str_buf, str_len, "X BR");
		return 2;
	case 0xE5:
		snprintf (str_buf, str_len, "XN BR");
		return 2;
	case 0xF1:
		snprintf (str_buf, str_len, "AN(");
		return 2;
	case 0xF3:
		snprintf (str_buf, str_len, "ON(");
		return 2;
	case 0xF4:
		snprintf (str_buf, str_len, "X(");
		return 2;
	case 0xF5:
		snprintf (str_buf, str_len, "XN(");
		return 2;
	case 0xFF:
		snprintf (str_buf, str_len, "NOP 1");
		return 2;
	default:
		break;
	}
	if (size > 2) {
		st16 value = (st16) s7_ut16 (buffer + 1);
		addr += value;
		switch (buffer[0]) {
		case 0x08:
			snprintf (str_buf, str_len, "JOS 0x%"PFMT64x, addr);
			return 4;
		case 0x18:
			snprintf (str_buf, str_len, "JO 0x%"PFMT64x, addr);
			return 4;
		case 0x28:
			snprintf (str_buf, str_len, "JP 0x%"PFMT64x, addr);
			return 4;
		case 0x48:
			snprintf (str_buf, str_len, "JM 0x%"PFMT64x, addr);
			return 4;
		case 0x58:
			snprintf (str_buf, str_len, "JUO 0x%"PFMT64x, addr);
			return 4;
		case 0x68:
			snprintf (str_buf, str_len, "JN 0x%"PFMT64x, addr);
			return 4;
		case 0x78:
			snprintf (str_buf, str_len, "JNBI 0x%"PFMT64x, addr);
			return 4;
		case 0x88:
			snprintf (str_buf, str_len, "JZ 0x%"PFMT64x, addr);
			return 4;
		case 0x98:
			snprintf (str_buf, str_len, "JNB 0x%"PFMT64x, addr);
			return 4;
		case 0xA8:
			snprintf (str_buf, str_len, "JPZ 0x%"PFMT64x, addr);
			return 4;
		case 0xB8:
			snprintf (str_buf, str_len, "JCN 0x%"PFMT64x, addr);
			return 4;
		case 0xC8:
			snprintf (str_buf, str_len, "JMZ 0x%"PFMT64x, addr);
			return 4;
		case 0xD8:
			snprintf (str_buf, str_len, "JCB 0x%"PFMT64x, addr);
			return 4;
		case 0xE8:
			snprintf (str_buf, str_len, "JBI 0x%"PFMT64x, addr);
			return 4;
		case 0xF8:
			snprintf (str_buf, str_len, "JC 0x%"PFMT64x, addr);
			return 4;
		default:
			return -1;
		}
	}
	return -1;
}

int simatic_s7_dec_instr(const ut8* buffer, const ut64 size, const ut64 addr, char* str_buf, int str_len) {
	snprintf (str_buf, str_len, "invalid");
	if (!buffer || size < 2) {
		return -1;
	}

	switch (buffer[0]) {
	case 0x00:
		return s7_decode_bitlogic ("NOP 0", "A", "AN", buffer + 1, size - 1, str_buf, str_len);
	case 0x01:
		return s7_decode_bitlogic ("INVI", "O", "ON", buffer + 1, size - 1, str_buf, str_len);
	case 0x02:
		return s7_decode_byte ("L", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x04:
		return s7_decode_byte ("FR", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x05:
		return s7_decode_bitlogic ("BEC", "X", "XN", buffer + 1, size - 1, str_buf, str_len);
	case 0x09:
		return s7_decode_bitlogic ("NEGI", "S", "R", buffer + 1, size - 1, str_buf, str_len);
	case 0x0A:
		return s7_decode_byte ("L", "MB", buffer + 1, size - 1, str_buf, str_len);
	case 0x0B:
		return s7_decode_byte ("T", "MB", buffer + 1, size - 1, str_buf, str_len);
	case 0x0C:
		return s7_decode_byte ("LC", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x10:
		return s7_decode_byte ("BLD", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x11:
		return s7_decode_byte ("DEC", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x12:
		return s7_decode_byte ("L", "MW", buffer + 1, size - 1, str_buf, str_len);
	case 0x13:
		return s7_decode_byte ("T", "MW", buffer + 1, size - 1, str_buf, str_len);
	case 0x14:
		return s7_decode_byte ("SF", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x19:
		return s7_decode_byte ("INC", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x1A:
		return s7_decode_byte ("L", "MD", buffer + 1, size - 1, str_buf, str_len);
	case 0x1B:
		return s7_decode_byte ("T", "MD", buffer + 1, size - 1, str_buf, str_len);
	case 0x1C:
		return s7_decode_byte ("SE", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x1D:
		return s7_decode_byte ("CC", "FC", buffer + 1, size - 1, str_buf, str_len);
	case 0x20:
		return s7_decode_byte ("OPN", "DB", buffer + 1, size - 1, str_buf, str_len);
	case 0x21:
		return s7_decode_cmp ("I", buffer + 1, size - 1, str_buf, str_len);
	case 0x24:
		return s7_decode_byte ("SD", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x28:
		return s7_decode_byte ("L", "B#16#", buffer + 1, size - 1, str_buf, str_len);
	case 0x29:
		if (buffer[1] < 0x10) {
			return s7_decode_byte ("SLD", "", buffer + 1, size - 1, str_buf, str_len);
		} else {
			return -1;
		}
	case 0x2C:
		return s7_decode_byte ("SS", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x30:
		return s7_decode_lit16 (buffer + 1, size - 1, str_buf, str_len);
	case 0x31:
		return s7_decode_cmp ("R", buffer + 1, size - 1, str_buf, str_len);
	case 0x34:
		return s7_decode_byte ("SP", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x38:
		return s7_decode_lit32 (buffer + 1, size - 1, str_buf, str_len);
	case 0x39:
		return s7_decode_cmp ("D", buffer + 1, size - 1, str_buf, str_len);
	case 0x3C:
		return s7_decode_byte ("R", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0x3D:
		return s7_decode_byte ("UC", "FC", buffer + 1, size - 1, str_buf, str_len);
	case 0x41:
		return s7_decode_bitlogic ("AW", "=", NULL, buffer + 1, size - 1, str_buf, str_len);
	case 0x42:
		return s7_decode_byte ("L", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0x44:
		return s7_decode_byte ("FR", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0x49:
		return s7_decode_bitlogic ("OW", "FP", "FN", buffer + 1, size - 1, str_buf, str_len);
	case 0x4A:
		return s7_decode_byte_signed ("L", "IB", "QB", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x4B:
		return s7_decode_byte_signed ("T", "IB", "QB", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x4C:
		return s7_decode_byte ("LC", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0x51:
		return s7_decode_bitlogic_mem ("XOW", false, "A", "O", "AN", "ON", buffer + 1, size - 1, str_buf, str_len);
	case 0x52:
		return s7_decode_byte_signed ("L", "IW", "QW", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x53:
		return s7_decode_byte_signed ("T", "IW", "QW", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x54:
		return s7_decode_byte ("CD", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0x55:
		return s7_decode_byte ("CC", "FB", buffer + 1, size - 1, str_buf, str_len);
	case 0x58:
		return s7_decode_bitlogic_mem ("+", true, "X", "S", "XN", "R", buffer + 1, size - 1, str_buf, str_len);
	case 0x59:
		return s7_decode_bitlogic_mem ("-I", false, "=", "FP", NULL, "FN", buffer + 1, size - 1, str_buf, str_len);
	case 0x5A:
		return s7_decode_byte_signed ("L", "ID", "QD", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x5B:
		return s7_decode_byte_signed ("T", "ID", "QD", "", buffer + 1, size - 1, str_buf, str_len);
	case 0x5C:
		return s7_decode_byte ("S", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0x60:
		if (buffer[1] == 0x05 && size > 5) {
			st32 value = (st32) s7_ut32 (buffer + 2);
			snprintf (str_buf, str_len, "+ %d", value);
			return 6;
		} else {
			const s7_static_t ops[] = {
				{0x00, "/I"},
				{0x01, "MOD"},
				{0x02, "ABS"},
				{0x03, "/R"},
				{0x04, "*I"},
				{0x06, "NEGR"},
				{0x07, "*R"},
				{0x08, "ENT"},
				{0x09, "-D"},
				{0x0A, "*D"},
				{0x0B, "-R"},
				{0x0D, "+D"},
				{0x0E, "/D"},
				{0x0F, "+R"},
				{0x10, "SIN"},
				{0x11, "COS"},
				{0x12, "TAN"},
				{0x13, "LN"},
				{0x14, "SQRT"},
				{0x18, "ASIN"},
				{0x19, "ACOS"},
				{0x1A, "ATAN"},
				{0x1B, "EXP"},
				{0x1C, "SQR"},
				{0, NULL}
			};
			return s7_decode_static (ops, buffer + 1, size - 1, str_buf, str_len);
		}
	case 0x61:
		if (buffer[1] < 0x10) {
			return s7_decode_4bit ("SLW", false, buffer + 1, size - 1, str_buf, str_len);
		} else {
			return -1;
		}
	case 0x64:
		if (buffer[1] <= 32) {
			return s7_decode_byte ("RLD", "", buffer + 1, size - 1, str_buf, str_len);
		} else {
			return -1;
		}
	case 0x65:
		{
			const s7_static_t ops[] = {
				{0x00, "BE"},
				{0x01, "BEU"},
				{0, NULL}
			};
			return s7_decode_static (ops, buffer + 1, size - 1, str_buf, str_len);
		}
	case 0x68:
		if ((buffer[1] & 0x0F) == 0x01) {
			return s7_decode_4bit ("SSI", true, buffer + 1, size - 1, str_buf, str_len);
		} else {
			const s7_static_t ops[] = {
				{0x06, "DTR"},
				{0x07, "NEGD"},
				{0x08, "ITB"},
				{0x0A, "DTB"},
				{0x0C, "BTI"},
				{0x0E, "BTD"},
				{0x0D, "INVD"},
				{0x12, "SLW"},
				{0x13, "SLD"},
				{0x17, "RLD"},
				{0x18, "RLDA"},
				{0x1A, "CAW"},
				{0x1B, "CAD"},
				{0x1C, "CLR"},
				{0x1D, "SET"},
				{0x1E, "ITD"},
				{0x22, "SRW"},
				{0x23, "SRD"},
				{0x24, "SSI"},
				{0x25, "SSD"},
				{0x27, "RRD"},
				{0x28, "RRDA"},
				{0x2C, "SAVE"},
				{0x2D, "NOT"},
				{0x2E, "PUSH"},
				{0x37, "AD"},
				{0x3A, "MCRA"},
				{0x3B, "MCRD"},
				{0x3C, "MCR("},
				{0x3D, ")MCR"},
				{0x3E, "POP"},
				{0x47, "OD"},
				{0x4E, "LEAVE"},
				{0x57, "XOD"},
				{0x5C, "RND"},
				{0x5D, "RND-"},
				{0x5E, "RND+"},
				{0x5F, "TRUNC"},
				{0, NULL}
			};
			return s7_decode_static (ops, buffer + 1, size - 1, str_buf, str_len);
		}
	case 0x69:
		if (buffer[1] < 0x10) {
			return s7_decode_4bit ("SRW", false, buffer + 1, size - 1, str_buf, str_len);
		} else {
			return -1;
		}
	case 0x6C:
		return s7_decode_byte ("CU", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0x70:
		if (buffer[1] == 0x08) {
			return s7_decode_jump ("LOOP", addr, buffer + 1, size - 1, str_buf, str_len);
		} else if (buffer[1] == 0x09) {
			return s7_decode_jump ("JL", addr, buffer + 1, size - 1, str_buf, str_len);
		} else if (buffer[1] == 0x0B) {
			return s7_decode_jump ("JU", addr, buffer + 1, size - 1, str_buf, str_len);
		} else {
			const s7_static_t ops[] = {
				{0x02, "TAK"},
				{0x06, "L STW"},
				{0x07, "T STW"},
				{0, NULL}
			};
			return s7_decode_static (ops, buffer + 1, size - 1, str_buf, str_len);
		}
	case 0x71:
		if (buffer[1] < 0x10) {
			return s7_decode_4bit ("SSD", false, buffer + 1, size - 1, str_buf, str_len);
		} else {
			return -1;
		}
	case 0x74:
		return s7_decode_4bit ("RRD", false, buffer + 1, size - 1, str_buf, str_len);
	case 0x75:
		return s7_decode_byte ("UC", "FB", buffer + 1, size - 1, str_buf, str_len);
	case 0x79:
		return s7_decode_79 (buffer + 1, size - 1, str_buf, str_len);
	case 0x7C:
		return s7_decode_byte ("R", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0x7E:
		return s7_decode_7E (buffer + 1, size - 1, str_buf, str_len);
	case 0x80:
		return s7_decode_byte_s ("A M", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0x81:
		return s7_decode_byte_s ("A M", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0x82:
		return s7_decode_byte_s ("A M", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0x83:
		return s7_decode_byte_s ("A M", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0x84:
		return s7_decode_byte_s ("A M", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0x85:
		return s7_decode_byte_s ("A M", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0x86:
		return s7_decode_byte_s ("A M", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0x87:
		return s7_decode_byte_s ("A M", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0x88:
		return s7_decode_byte_s ("O M", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0x89:
		return s7_decode_byte_s ("O M", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0x8A:
		return s7_decode_byte_s ("O M", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0x8B:
		return s7_decode_byte_s ("O M", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0x8C:
		return s7_decode_byte_s ("O M", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0x8D:
		return s7_decode_byte_s ("O M", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0x8E:
		return s7_decode_byte_s ("O M", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0x8F:
		return s7_decode_byte_s ("O M", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0x90:
		return s7_decode_byte_s ("S M", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0x91:
		return s7_decode_byte_s ("S M", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0x92:
		return s7_decode_byte_s ("S M", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0x93:
		return s7_decode_byte_s ("S M", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0x94:
		return s7_decode_byte_s ("S M", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0x95:
		return s7_decode_byte_s ("S M", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0x96:
		return s7_decode_byte_s ("S M", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0x97:
		return s7_decode_byte_s ("S M", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0x98:
		return s7_decode_byte_s ("= M", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0x99:
		return s7_decode_byte_s ("= M", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0x9A:
		return s7_decode_byte_s ("= M", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0x9B:
		return s7_decode_byte_s ("= M", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0x9C:
		return s7_decode_byte_s ("= M", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0x9D:
		return s7_decode_byte_s ("= M", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0x9E:
		return s7_decode_byte_s ("= M", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0x9F:
		return s7_decode_byte_s ("= M", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xA0:
		return s7_decode_byte_s ("AN M", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xA1:
		return s7_decode_byte_s ("AN M", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xA2:
		return s7_decode_byte_s ("AN M", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xA3:
		return s7_decode_byte_s ("AN M", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xA4:
		return s7_decode_byte_s ("AN M", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xA5:
		return s7_decode_byte_s ("AN M", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xA6:
		return s7_decode_byte_s ("AN M", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xA7:
		return s7_decode_byte_s ("AN M", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xA8:
		return s7_decode_byte_s ("ON M", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xA9:
		return s7_decode_byte_s ("ON M", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xAA:
		return s7_decode_byte_s ("ON M", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xAB:
		return s7_decode_byte_s ("ON M", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xAC:
		return s7_decode_byte_s ("ON M", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xAD:
		return s7_decode_byte_s ("ON M", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xAE:
		return s7_decode_byte_s ("ON M", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xAF:
		return s7_decode_byte_s ("ON M", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xB0:
		return s7_decode_byte_s ("R M", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xB1:
		return s7_decode_byte_s ("R M", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xB2:
		return s7_decode_byte_s ("R M", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xB3:
		return s7_decode_byte_s ("R M", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xB4:
		return s7_decode_byte_s ("R M", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xB5:
		return s7_decode_byte_s ("R M", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xB6:
		return s7_decode_byte_s ("R M", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xB7:
		return s7_decode_byte_s ("R M", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xB8:
		return s7_decode_byte ("A", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0xB9:
		return s7_decode_byte ("O", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0xBC:
		return s7_decode_byte ("AN", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0xBD:
		return s7_decode_byte ("ON", "C", buffer + 1, size - 1, str_buf, str_len);
	case 0xBA:
		if ((buffer[1] > 0x66 && buffer[1] < 0xB0) || buffer[1] > 0xE6) {
			return -1;
		} else {
			return s7_decode_mem ("A(", "L", "T", types_b, types_b, buffer + 1, size - 1, str_buf, str_len);
		}
	case 0xBB:
		return s7_decode_mem ("O(", "L", "T", types_w, types_d, buffer + 1, size - 1, str_buf, str_len);
	case 0xBE:
		return s7_decode_BE (buffer + 1, size - 1, str_buf, str_len);
	case 0xBF:
		return s7_decode_BF (buffer + 1, size - 1, str_buf, str_len);
	case 0xC0:
		return s7_decode_byte_signed ("A", "I", "Q", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xC1:
		return s7_decode_byte_signed ("A", "I", "Q", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xC2:
		return s7_decode_byte_signed ("A", "I", "Q", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xC3:
		return s7_decode_byte_signed ("A", "I", "Q", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xC4:
		return s7_decode_byte_signed ("A", "I", "Q", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xC5:
		return s7_decode_byte_signed ("A", "I", "Q", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xC6:
		return s7_decode_byte_signed ("A", "I", "Q", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xC7:
		return s7_decode_byte_signed ("A", "I", "Q", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xC8:
		return s7_decode_byte_signed ("O", "I", "Q", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xC9:
		return s7_decode_byte_signed ("O", "I", "Q", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xCA:
		return s7_decode_byte_signed ("O", "I", "Q", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xCB:
		return s7_decode_byte_signed ("O", "I", "Q", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xCC:
		return s7_decode_byte_signed ("O", "I", "Q", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xCD:
		return s7_decode_byte_signed ("O", "I", "Q", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xCE:
		return s7_decode_byte_signed ("O", "I", "Q", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xCF:
		return s7_decode_byte_signed ("O", "I", "Q", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xD0:
		return s7_decode_byte_signed ("S", "I", "Q", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xD1:
		return s7_decode_byte_signed ("S", "I", "Q", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xD2:
		return s7_decode_byte_signed ("S", "I", "Q", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xD3:
		return s7_decode_byte_signed ("S", "I", "Q", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xD4:
		return s7_decode_byte_signed ("S", "I", "Q", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xD5:
		return s7_decode_byte_signed ("S", "I", "Q", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xD6:
		return s7_decode_byte_signed ("S", "I", "Q", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xD7:
		return s7_decode_byte_signed ("S", "I", "Q", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xD8:
		return s7_decode_byte_signed ("=", "I", "Q", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xD9:
		return s7_decode_byte_signed ("=", "I", "Q", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xDA:
		return s7_decode_byte_signed ("=", "I", "Q", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xDB:
		return s7_decode_byte_signed ("=", "I", "Q", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xDC:
		return s7_decode_byte_signed ("=", "I", "Q", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xDD:
		return s7_decode_byte_signed ("=", "I", "Q", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xDE:
		return s7_decode_byte_signed ("=", "I", "Q", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xDF:
		return s7_decode_byte_signed ("=", "I", "Q", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xE0:
		return s7_decode_byte_signed ("AN", "I", "Q", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xE1:
		return s7_decode_byte_signed ("AN", "I", "Q", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xE2:
		return s7_decode_byte_signed ("AN", "I", "Q", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xE3:
		return s7_decode_byte_signed ("AN", "I", "Q", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xE4:
		return s7_decode_byte_signed ("AN", "I", "Q", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xE5:
		return s7_decode_byte_signed ("AN", "I", "Q", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xE6:
		return s7_decode_byte_signed ("AN", "I", "Q", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xE7:
		return s7_decode_byte_signed ("AN", "I", "Q", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xE8:
		return s7_decode_byte_signed ("ON", "I", "Q", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xE9:
		return s7_decode_byte_signed ("ON", "I", "Q", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xEA:
		return s7_decode_byte_signed ("ON", "I", "Q", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xEB:
		return s7_decode_byte_signed ("ON", "I", "Q", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xEC:
		return s7_decode_byte_signed ("ON", "I", "Q", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xED:
		return s7_decode_byte_signed ("ON", "I", "Q", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xEE:
		return s7_decode_byte_signed ("ON", "I", "Q", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xEF:
		return s7_decode_byte_signed ("ON", "I", "Q", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xF0:
		return s7_decode_byte_signed ("R", "I", "Q", ".0", buffer + 1, size - 1, str_buf, str_len);
	case 0xF1:
		return s7_decode_byte_signed ("R", "I", "Q", ".1", buffer + 1, size - 1, str_buf, str_len);
	case 0xF2:
		return s7_decode_byte_signed ("R", "I", "Q", ".2", buffer + 1, size - 1, str_buf, str_len);
	case 0xF3:
		return s7_decode_byte_signed ("R", "I", "Q", ".3", buffer + 1, size - 1, str_buf, str_len);
	case 0xF4:
		return s7_decode_byte_signed ("R", "I", "Q", ".4", buffer + 1, size - 1, str_buf, str_len);
	case 0xF5:
		return s7_decode_byte_signed ("R", "I", "Q", ".5", buffer + 1, size - 1, str_buf, str_len);
	case 0xF6:
		return s7_decode_byte_signed ("R", "I", "Q", ".6", buffer + 1, size - 1, str_buf, str_len);
	case 0xF7:
		return s7_decode_byte_signed ("R", "I", "Q", ".7", buffer + 1, size - 1, str_buf, str_len);
	case 0xF8:
		return s7_decode_byte ("A", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0xF9:
		return s7_decode_byte ("O", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0xFB:
		return s7_decode_FB (buffer + 1, size - 1, str_buf, str_len);
	case 0xFC:
		return s7_decode_byte ("AN", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0xFD:
		return s7_decode_byte ("ON", "T", buffer + 1, size - 1, str_buf, str_len);
	case 0xFE:
		return s7_decode_FE (buffer + 1, size - 1, str_buf, str_len);
	case 0xFF:
		return s7_decode_FF (addr, buffer + 1, size - 1, str_buf, str_len);
	default:
		break;
	}
	return -1;
}
