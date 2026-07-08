// SPDX-FileCopyrightText: 2022-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2019-2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_types.h>
#include <rz_util.h>
#include <rz_lib.h>
#include <rz_bin.h>
#include <rz_magic.h>

/**
 * This comes from the simulator.
 *
 *             0 1  2 3  4 5  6 7  8 9  a b  c d  e f
 * 00000000:  7070 0101 0108 0001 0000 0074 0000 0000
 *            ~~~~ ++-- **.. &&&& :::: :::: ^^^^ ^^^^
 * 00000010:  02ab 2735 2d03 03a1 6383 21a7 001c 0006
 *            %%%% %%%% %%%% $$$$ $$$$ $$$$ ==== !!!!
 * 00000020:  0014 000a
 *            @@@@ ####
 *
 *  ~ block magic
 *  + block version
 *  - block attribute
 *  * block language (STL: 0x01, LAD: 0x02, FBD: 0x03, SCL: 0x04, DB: 0x05, GRAPH: 0x06, SDB: 0x07)
 *  . block type     (OB: 0x08, DB: 0x0A, SDB: 0x0B, FC: 0x0C, SFC: 0x0D, FB: 0x0E, SFB: 0x0F)
 *  & block number
 *  : block size
 *  ^ block password
 *  % block last modified date
 *  $ block interface last modified date
 *  = block interface size
 *  ! block segment table size
 *  @ block local data size
 *  # block data size
 */

#define MC7_MAGIC      0x7070
#define MC7_BLOCK_SIZE 0x24

typedef enum {
	MC7_LANG_STL = 0x01, // Statement List
	MC7_LANG_LAD = 0x02, // Ladder Logic
	MC7_LANG_FBD = 0x03, // Function Block Diagram
	MC7_LANG_SCL = 0x04, // Structured Control Language
	MC7_LANG_DB = 0x05, // Data Block
	MC7_LANG_GRAPH = 0x06, // S7-GRAPH
	MC7_LANG_SDB = 0x07, // System Data Block
} mc7_lang;

typedef enum {
	MC7_TYPE_OB = 0x08, // Organization Block
	MC7_TYPE_DB = 0x0A, // Data Block
	MC7_TYPE_SDB = 0x0B, // System Data Block
	MC7_TYPE_FC = 0x0C, // Function
	MC7_TYPE_SFC = 0x0D, // System Function (mem Instance DB)
	MC7_TYPE_FB = 0x0E, // Function Block (mem Internal)
	MC7_TYPE_SFB = 0x0F, // System Function Block (mem Internal + Instance DB)
} mc7_type;

typedef struct mc7_date_s {
	ut32 year;
	ut32 month;
	ut32 day;
	ut32 hour;
	ut32 mins;
	ut32 secs;
	ut32 millisec;
} mc7_date_t;

typedef struct mc7_block_s {
	ut16 magic;
	ut8 version;
	ut8 attribute;
	ut8 language;
	ut8 type;
	ut16 number;
	ut32 size;
	ut32 password;
	mc7_date_t last_mod_date; // last modified date
	mc7_date_t iface_last_mod_date; // last modified date
	ut16 iface_size;
	ut16 segment_size;
	ut16 local_data_size;
	ut16 data_size;
} mc7_block_t;

void mc7_days_since_1984_to_date(ut16 days, mc7_date_t *date) {
	static ut32 days_in_month[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

	// start date is always 1984/01/01
	ut32 year = 1984;
	ut32 month = 1;
	ut32 day = 1 + days;

	// adjust for leap years
	while (day > 365) {
		int days_in_year = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) ? 366 : 365;
		if (day > days_in_year) {
			day -= days_in_year;
			year++;
		} else {
			break;
		}
	}

	// adjust month
	bool is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
	ut32 i = 0;
	while (day > days_in_month[i]) {
		if (i == 1 && is_leap) {
			if (day > 29) {
				day -= 29;
				i++;
			} else {
				break;
			}
		} else {
			day -= days_in_month[i];
			i++;
		}
	}

	month = i + 1;

	date->year = year;
	date->month = month;
	date->day = day;
}

void mc7_millisecs_to_time(ut32 milliseconds, mc7_date_t *date) {
	date->hour = milliseconds / 3600000;
	milliseconds %= 3600000;

	date->mins = milliseconds / 60000;
	milliseconds %= 60000;

	date->secs = milliseconds / 1000;
	date->millisec = milliseconds % 1000;
}

static bool mc7_parse_s7_date(RzBuffer *b, ut64 *offset, mc7_date_t *date) {
	// AA AA AA AA BB BB
	// where:
	//   A: 32 bits (big-endian), number of milliseconds in the days (range: 0 to 86400000)
	//   B: 16 bits (big-endian), number of days since Jan 1 1984
	// example:
	//   00 00 EA 60 00 01 represents the timestamp Jan 2 1984 00:01:00.000
	ut32 millisec = 0;
	ut16 days = 0;

	bool ok = rz_buf_read_be32_offset(b, offset, &millisec) &&
		rz_buf_read_be16_offset(b, offset, &days);

	if (!ok) {
		return false;
	}

	mc7_days_since_1984_to_date(days, date);
	mc7_millisecs_to_time(days, date);
	return true;
}

static bool mc7_parse_block(RzBuffer *b, ut64 *offset, mc7_block_t *blk) {
	return rz_buf_read_be16_offset(b, offset, &blk->magic) &&
		rz_buf_read8_offset(b, offset, &blk->version) &&
		rz_buf_read8_offset(b, offset, &blk->attribute) &&
		rz_buf_read8_offset(b, offset, &blk->language) &&
		rz_buf_read8_offset(b, offset, &blk->type) &&
		rz_buf_read_be16_offset(b, offset, &blk->number) &&
		rz_buf_read_be32_offset(b, offset, &blk->size) &&
		rz_buf_read_be32_offset(b, offset, &blk->password) &&
		mc7_parse_s7_date(b, offset, &blk->last_mod_date) &&
		mc7_parse_s7_date(b, offset, &blk->iface_last_mod_date) &&
		rz_buf_read_be16_offset(b, offset, &blk->iface_size) &&
		rz_buf_read_be16_offset(b, offset, &blk->segment_size) &&
		rz_buf_read_be16_offset(b, offset, &blk->local_data_size) &&
		rz_buf_read_be16_offset(b, offset, &blk->data_size);
}

static bool mc7_load_buffer(RzBinFile *bf, RzBinObject *bin_obj, RzBuffer *b, Sdb *sdb) {
	ut64 offset = 0;

	mc7_block_t *blk = RZ_NEW0(mc7_block_t);
	if (!blk || !mc7_parse_block(b, &offset, blk)) {
		free(blk);
		return false;
	}

	bin_obj->bin_obj = blk;
	return true;
}

static bool mc7_check_buffer(RzBuffer *b) {
	rz_return_val_if_fail(b, false);
	ut16 magic = 0;
	ut64 offset = 0;
	if (!rz_buf_read_be16_offset(b, &offset, &magic)) {
		return false;
	}

	return magic == MC7_MAGIC;
}

static void mc7_destroy(RzBinFile *bf) {
	free(bf->o->bin_obj);
	bf->o->bin_obj = NULL;
	return;
}

static ut64 mc7_baddr(RzBinFile *bf) {
	return 0;
}

static const char *mc7_language_to_string(const mc7_block_t *blk) {
	switch (blk->language) {
	case MC7_LANG_STL: return "statement list (STL)";
	case MC7_LANG_LAD: return "ladder logic (LAD)";
	case MC7_LANG_FBD: return "function block diagram (FBD)";
	case MC7_LANG_SCL: return "structured control language (SCL)";
	case MC7_LANG_DB: return "data block (DB)";
	case MC7_LANG_GRAPH: return "s7-graph (GRAPH)";
	case MC7_LANG_SDB: return "system data block (SDB)";
	default: return NULL;
	}
}

static const char *mc7_type_to_string(const mc7_block_t *blk) {
	switch (blk->type) {
	case MC7_TYPE_OB: return "organization block (OB)";
	case MC7_TYPE_DB: return "data block (DB)";
	case MC7_TYPE_SDB: return "system data block (SDB)";
	case MC7_TYPE_FC: return "function (FC)";
	case MC7_TYPE_SFC: return "system function (SFC)";
	case MC7_TYPE_FB: return "function block (FB)";
	case MC7_TYPE_SFB: return "system function block (SFB)";
	default: return NULL;
	}
}

static void mc7_s7date_to_string(char *output, size_t o_size, const mc7_date_t *date) {
	snprintf(output, o_size, "%u/%02u/%02u %02u:%02u:%02u.%u",
		date->year,
		date->month,
		date->day,
		date->hour,
		date->mins,
		date->secs,
		date->millisec);
}

static RzBinInfo *mc7_info(RzBinFile *bf) {
	mc7_block_t *blk = bf->o->bin_obj;
	if (!blk) {
		return NULL;
	}

	RzBinInfo *ret = RZ_NEW0(RzBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->lang = rz_str_dup(mc7_language_to_string(blk));
	ret->bclass = rz_str_dup(mc7_type_to_string(blk));
	ret->file = rz_str_dup(bf->file);
	ret->type = rz_str_dup("mc7");
	ret->machine = rz_str_dup("Siemens Step7");
	ret->arch = rz_str_dup("mc7");
	ret->cpu = rz_str_dup("s7-300");
	ret->bits = 32;
	ret->big_endian = true;
	ret->dbg_info = RZ_BIN_DBG_STRIPPED;
	ret->has_va = false;

	return ret;
}

static RzPVector *mc7_entries(RzBinFile *bf) {
	RzPVector *ret;
	RzBinAddr *ptr = NULL;
	if (!(ret = rz_pvector_new(NULL))) {
		return NULL;
	}
	if (!(ptr = RZ_NEW0(RzBinAddr))) {
		return ret;
	}
	ptr->paddr = MC7_BLOCK_SIZE;
	rz_pvector_push(ret, ptr);
	return ret;
}

static bool mc7_bin_section_add(RzPVector /*<RzBinSection *>*/ *sections, const char *name, ut64 addr, size_t size, ut32 perm, bool is_data) {
	if (size < 1) {
		return true;
	}

	RzBinSection *sec = rz_bin_section_new(name);
	if (!sec) {
		return false;
	}

	sec->paddr = addr;
	sec->size = size;
	sec->vaddr = addr;
	sec->vsize = size;
	sec->perm = perm;
	sec->is_data = is_data;

	if (!rz_pvector_push(sections, sec)) {
		rz_bin_section_free(sec);
		return false;
	}

	return true;
}

static RzPVector /*<RzBinSection *>*/ *mc7_sections(RzBinFile *bf) {
	mc7_block_t *blk = bf->o->bin_obj;
	if (!blk) {
		return NULL;
	}

	RzPVector *ret = rz_pvector_new((RzPVectorFree)rz_bin_section_free);
	if (!ret) {
		return NULL;
	}

	const bool is_data = blk->type == MC7_TYPE_DB || blk->type == MC7_TYPE_SDB;

	ut64 offset = MC7_BLOCK_SIZE;
	if (!mc7_bin_section_add(ret, "interface", offset, blk->iface_size, is_data ? RZ_PERM_RW : RZ_PERM_RX, is_data)) {
		return ret;
	}
	offset += blk->iface_size;

	if (!mc7_bin_section_add(ret, "segment", offset, blk->segment_size, is_data ? RZ_PERM_RW : RZ_PERM_RX, is_data)) {
		return ret;
	}
	offset += blk->segment_size;

	if (!mc7_bin_section_add(ret, "data_local", offset, blk->local_data_size, RZ_PERM_RW, true)) {
		return ret;
	}
	offset += blk->local_data_size;

	mc7_bin_section_add(ret, "data", offset, blk->data_size, RZ_PERM_RW, true);
	return ret;
}

static RzStructuredData *mc7_structure(RzBinFile *bf) {
	mc7_block_t *blk = bf->o->bin_obj;
	if (!blk) {
		return NULL;
	}

	char block_date[128];
	char iface_date[128];

	const char *language = mc7_language_to_string(blk);
	const char *btype = mc7_type_to_string(blk);
	mc7_s7date_to_string(block_date, sizeof(block_date), &blk->last_mod_date);
	mc7_s7date_to_string(iface_date, sizeof(iface_date), &blk->iface_last_mod_date);

	RzStructuredData *info = rz_structured_data_new_map();
	if (!info) {
		return NULL;
	}

	RzStructuredData *root = rz_structured_data_map_add_map(info, "mc7_block");
	if (!root) {
		rz_structured_data_free(info);
		return NULL;
	}

	rz_structured_data_map_add_unsigned(root, "magic", blk->magic, true);
	rz_structured_data_map_add_unsigned(root, "version", blk->version, false);
	rz_structured_data_map_add_unsigned(root, "attribute", blk->attribute, true);
	if (language) {
		rz_structured_data_map_add_string(root, "language", language);
	} else {
		rz_structured_data_map_add_unsigned(root, "language", blk->language, true);
	}
	if (btype) {
		rz_structured_data_map_add_string(root, "type", btype);
	} else {
		rz_structured_data_map_add_unsigned(root, "type", blk->type, true);
	}
	rz_structured_data_map_add_unsigned(root, "number", blk->number, true);
	rz_structured_data_map_add_unsigned(root, "size", blk->size, false);
	rz_structured_data_map_add_unsigned(root, "password", blk->password, true);
	rz_structured_data_map_add_string(root, "last_modified_date", block_date);

	RzStructuredData *iface = rz_structured_data_map_add_map(root, "interface");
	if (iface) {
		rz_structured_data_map_add_string(iface, "last_modified_date", iface_date);
		rz_structured_data_map_add_unsigned(iface, "size", blk->iface_size, false);
	}

	rz_structured_data_map_add_unsigned(root, "segment_size", blk->segment_size, false);
	rz_structured_data_map_add_unsigned(root, "local_data_size", blk->local_data_size, false);
	rz_structured_data_map_add_unsigned(root, "data_size", blk->data_size, false);

	return info;
}

struct rz_bin_plugin_t rz_bin_plugin_mc7 = {
	.name = "mc7",
	.desc = "Simatic S7 disassembler",
	.license = "LGPL",
	.load_buffer = &mc7_load_buffer,
	.check_buffer = &mc7_check_buffer,
	.destroy = &mc7_destroy,
	.baddr = &mc7_baddr,
	.entries = &mc7_entries,
	.sections = &mc7_sections,
	.maps = rz_bin_maps_of_file_sections,
	.info = &mc7_info,
	.bin_structure = &mc7_structure,
};

RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_BIN,
	.data = &rz_bin_plugin_mc7,
	.version = RZ_VERSION
};
