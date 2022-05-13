// SPDX-FileCopyrightText: 2021 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2019-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <simatic.h>

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	S7Instr instr = { 0 };
	int read = simatic_s7_decode_instruction(buf, len, a->pc, &instr);
	if (read < 0) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 2;
	} else {
		rz_asm_op_set_asm(op, instr.assembly);
		op->size = read;
	}
	return op->size;
}

RzAsmPlugin rz_asm_plugin_simatic_mc7 = {
	.name = "mc7",
	.desc = "Simatic S7 disassembler",
	.license = "LGPL",
	.author = "deroad",
	.arch = "mc7",
	.cpus = "s7-300,s7-400",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct radare_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_simatic_mc7,
	.version = RZ_VERSION
};
#endif