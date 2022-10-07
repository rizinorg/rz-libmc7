// SPDX-FileCopyrightText: 2022 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2019-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_analysis.h>
#include <rz_types.h>
#include <rz_lib.h>

#include <simatic.h>

static int s7_analysis(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *data, int len, RzAnalysisOpMask mask) {
	S7Instr instr = { 0 };
	int read = simatic_s7_decode_instruction(data, len, addr, &instr);
	if (read > 0) {
		op->size = read;
		if (instr.jump != UT64_MAX) {
			op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
			op->jump = instr.jump;
			op->fail = addr + op->size;
		}
		op->eob = instr.is_return;
	}
	return op->size;
}

static int s7_archinfo(RzAnalysis *a, RzAnalysisInfoType q) {
	switch (q) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 6;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		/* fall-thru */
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 0;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_mc7 = {
	.name = "mc7",
	.desc = "Simatic S7 analysis plugin",
	.arch = "mc7",
	.license = "LGPL3",
	.bits = 32,
	.archinfo = s7_archinfo,
	.op = &s7_analysis,
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_mc7,
	.version = RZ_VERSION
};
#endif
