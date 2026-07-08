// SPDX-FileCopyrightText: 2021-2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2019-2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_asm.h>
#include <rz_lib.h>
#include <simatic.h>

static int disassemble_mc7(const RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	ut64 pc = rz_asm_get_pc(a);

	S7Instr instr = { 0 };
	int read = simatic_s7_decode_instruction(buf, len, pc, &instr);
	if (read < 0) {
		rz_asm_op_set_asm(op, "invalid");
		op->size = 2;
	} else {
		rz_asm_op_set_asm(op, instr.assembly);
		op->size = read;
	}
	return op->size;
}

static RzAsmPlugin rz_asm_plugin_mc7 = {
	.name = "mc7",
	.desc = "Simatic S7 disassembler",
	.license = "LGPL",
	.author = "deroad",
	.arch = "mc7",
	.cpus = "s7-300,s7-400",
	.bits = 32,
	.endian = RZ_SYS_ENDIAN_BIG,
	.disassemble = &disassemble_mc7,
};
