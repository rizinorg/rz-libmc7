/* radare2 - LGPL - Copyright 2019 - deroad */

#include <r_asm.h>
#include <r_lib.h>
#include <simatic.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	s7_instr_t instr = {0};
	int read = simatic_s7_dec_instr (buf, len, a->pc, &instr);
	if (read < 0) {
		r_asm_op_set_asm (op, "invalid");
		op->size = 2;
	} else {
		r_asm_op_set_asm (op, instr.assembly);
		op->size = read;
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_simatic_mc7 = {
	.name = "mc7",
	.desc = "Simatic S7 disassembler",
	.license = "LGPL",
	.author = "deroad",
	.arch = "mc7",
	.cpus = "s7-300,s7-400",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_simatic_mc7,
	.version = R2_VERSION
};
#endif