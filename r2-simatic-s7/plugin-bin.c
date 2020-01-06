#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_magic.h>

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
 *  ~ block signature
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

typedef R_PACKED (struct _mc7_block {
    ut16 signature;
    ut8  version;
    ut8  attribute;
    ut8  language;
    ut8  type;
    ut16 number;
    ut32 size;
    ut32 password;
    ut8  last_mod_date[6];       // last modified date
    ut8  iface_last_mod_date[6]; // last modified date
    ut16 iface_size;
    ut16 segment_size;
    ut16 local_data_size;
    ut16 data_size;
}) mc7_block_t;

static ut16 read16(const ut8* b) {
    ut16 a = b[1];
    a |= (b[0] << 8);
    return a;
}

static ut32 read32(const ut8* b) {
    ut32 a = read16 (b);
    a |= read16 (b + 2) << 16;
    return a;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *b, ut64 loadaddr, Sdb *sdb) {
    ut64 size;
    const ut8 *buf = r_buf_data (b, &size);
    r_return_val_if_fail (buf && size >= sizeof (mc7_block_t), false);
    mc7_block_t* blk = R_NEW0 (mc7_block_t);
    if (*bin_obj && blk) {
        blk->signature           = read16 (buf);
        blk->version             = buf[0x2];
        blk->attribute           = buf[0x3];
        blk->language            = buf[0x4];
        blk->type                = buf[0x5];
        blk->number              = read16 (buf + 0x6);
        blk->size                = read32 (buf + 0x8);
        blk->password            = read32 (buf + 0xC);
        memcpy (blk->last_mod_date      , buf + 0x10, 0x6);
        memcpy (blk->iface_last_mod_date, buf + 0x16, 0x6);
        blk->iface_size          = read16 (buf + 0x1C);
        blk->segment_size        = read16 (buf + 0x1E);
        blk->local_data_size     = read16 (buf + 0x20);
        blk->data_size           = read16 (buf + 0x22);
        *bin_obj = (void*) blk;
    }
    return *bin_obj != NULL;
}

static void destroy(RBinFile *bf) {
    free (bf->o->bin_obj);
    bf->o->bin_obj = NULL;
    return;
}

static ut64 baddr(RBinFile *bf) {
    return 0;
}

static RList *strings(RBinFile *bf) {
    return NULL;
}

static bool check_buffer(RBuffer *b) {
    r_return_val_if_fail (b, false);
    ut64 size;
    const ut8 *buf = r_buf_data (b, &size);
    r_return_val_if_fail (buf && size >= 2, false);
    return buf[0] == 0x70 && buf[1] == 0x70;
}

static RBinInfo* info(RBinFile *arch) {
    RBinInfo* ret = R_NEW0 (RBinInfo);
    r_return_val_if_fail (ret, NULL);

    if (!arch) {
        free (ret);
        return NULL;
    }
    ret->file = strdup (arch->file);
    ret->type = strdup ("mc7");
    ret->machine = strdup ("Siemens Step7");
    ret->arch = strdup ("mc7");
    ret->bits = 32;

    return ret;
}

static RList* entries(RBinFile *bf) {
    RList *ret;
    RBinAddr *ptr = NULL;
    if (!(ret = r_list_new ())) {
        return NULL;
    }
    if (!(ptr = R_NEW0 (RBinAddr))) {
        return ret;
    }
    ptr->paddr = sizeof (mc7_block_t);
    r_list_append (ret, ptr);
    return ret;
}

struct r_bin_plugin_t r_bin_plugin_mc7 = {
    .name = "mc7",
    .desc = "Simatic S7 disassembler",
    .license = "LGPL",
    .get_sdb = NULL,
    .load_buffer = &load_buffer,
    .destroy = &destroy,
    .check_buffer = &check_buffer,
    .baddr = &baddr,
    .strings = &strings,
    .entries = &entries,
    .sections = NULL,
    .info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
    .type = R_LIB_TYPE_BIN,
    .data = &r_bin_plugin_mc7,
    .version = R2_VERSION
};
#endif