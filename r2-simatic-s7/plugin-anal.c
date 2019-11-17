/* radare - LGPL - Copyright 2019 - deroad */

#include <r_anal.h>
#include <r_types.h>
#include <r_lib.h>

#include <simatic.h>

static int s7_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	memset (op, '\0', sizeof(RAnalOp));

	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->size = -1;

	s7_instr_t instr = {0};
	int read = simatic_s7_dec_instr (data, len, addr, &instr);
	if (read > 0) {
		op->size = read;
		if (instr.jump != UT64_MAX) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = instr.jump;
			op->fail = addr + op->size;
		}
		op->eob = instr.is_return;
	}
	return op->size;
}

static int mc7_set_reg_profile(RAnal* anal){
	return r_reg_set_profile_string(anal->reg, "");
}

static int archinfo(RAnal *a, int q) {
	return 2;
}

RAnalPlugin r_anal_plugin_null = {
	.name = "mc7",
	.desc = "Simatic S7 analysis plugin",
	.arch = "mc7",
	.license = "LGPL3",
	.bits = 32,
	.archinfo = archinfo,
	.op = &s7_anal,
	.set_reg_profile = &mc7_set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_null,
	.version = R2_VERSION
};
#endif
