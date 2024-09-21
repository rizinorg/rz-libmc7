#include <stdlib.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_cmd.h>
#include <rz_core.h>
#include <rz_cons.h>
#include <rz_analysis.h>

#include <simatic.h>

#undef RZ_API
#define RZ_API static
#undef RZ_IPI
#define RZ_IPI           static
#define SETDESC(x, y)    rz_config_node_desc(x, y)
#define SETPREF(x, y, z) SETDESC(rz_config_set(cfg, x, y), z)

#define name_args(name)    (internal_##name##_args)
#define name_help(name)    (internal_##name##_help)
#define name_handler(name) (internal_##name##_handler)

#define command_handler(name, arg) \
	RZ_IPI RzCmdStatus name_handler(name)(RzCore * core, int argc, const char **argv) { \
		if (argc != 1) { \
			return RZ_CMD_STATUS_WRONG_ARGS; \
		} \
		libcm7_main(core, arg); \
		return RZ_CMD_STATUS_OK; \
	}
#define static_description_no_args(command, description) \
	static const RzCmdDescArg name_args(command)[] = { \
		{ 0 }, \
	}; \
	static const RzCmdDescHelp name_help(command) = { \
		.summary = description, \
		.args = name_args(command), \
	}
#define rz_cmd_desc_argv_new_warn(rcmd, root, cmd) \
	rz_warn_if_fail(rz_cmd_desc_argv_new(rcmd, root, #cmd, name_handler(cmd), &name_help(cmd)))

static const RzCmdDescHelp pdd_usage = {
	.summary = "Core plugin for libmc7",
};

static bool libcm7_main(RzCore *core, const char *arg) {



	void * bed = rz_cons_sleep_begin();

	rz_cons_sleep_end(bed);


	return 0;
}


static_description_no_args(pdd, "decompile block");
static_description_no_args(pddi, "print block info");
command_handler(pdd, NULL);
command_handler(pddi, "--info");

static bool rz_cmd_pdd_init(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzConfig *cfg = core->config;
	RzCmdDesc *root_cd = rz_cmd_get_desc(rcmd, "pd");
	if (!root_cd) {
		rz_warn_if_reached();
		return false;
	}

	rz_config_lock(cfg, false);
	SETPREF("libcm7.test", "false", "a test config item.");
	rz_config_lock(cfg, true);

	RzCmdDesc *pdd = rz_cmd_desc_group_new(rcmd, root_cd, "pdd", name_handler(pdd), &name_help(pdd), &pdd_usage);
	if (!pdd) {
		rz_warn_if_reached();
		return false;
	}

	rz_cmd_desc_argv_new_warn(rcmd, pdd, pddi);



	return true;
}

static bool rz_cmd_pdd_fini(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *cd = rz_cmd_get_desc(rcmd, "pdd");
	return rz_cmd_desc_remove(rcmd, cd);
}


RzCorePlugin rz_core_plugin_jsdec = {
	.name = "libcm7",
	.author = "JeGeVa (based on wargio work & code)",
	.desc = "Simatic S7 decopiler",
	.license = "LGPL",
	.init = rz_cmd_pdd_init,
	.fini = rz_cmd_pdd_fini,
};

#ifdef _MSC_VER
#define _RZ_API __declspec(dllexport)
#else
#define _RZ_API
#endif

#ifndef CORELIB
_RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_jsdec,
	.version = RZ_VERSION,
};
#endif
