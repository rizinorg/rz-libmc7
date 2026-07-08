// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2026 deroad <deroad@kumo.xn--q9jyb4c>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_arch.h>
#include <rz_lib.h>

#include "plugin_asm.c"
#include "plugin_analysis.c"

static RzArchPlugin rz_arch_plugin_mc7 = {
	.p_asm = &rz_asm_plugin_mc7,
	.p_analysis = &rz_analysis_plugin_mc7,
	.p_parse = NULL,
};

RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ARCH,
	.data = &rz_arch_plugin_mc7,
	.version = RZ_VERSION
};
