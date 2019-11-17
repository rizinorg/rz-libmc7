/* libmc7 - LGPL - Copyright 2019 - deroad */

#ifndef R_SIMATIC_H
#define R_SIMATIC_H

#include <r_util.h>

#ifdef __cplusplus
extern "C" {
#endif

#define S7_INSTRUCTION_LEN 128

typedef struct {
	char assembly[S7_INSTRUCTION_LEN];
	ut64 jump;
	bool is_return;
} s7_instr_t;

R_API int simatic_s7_dec_instr(const ut8* buffer, const ut64 size, const ut64 addr, s7_instr_t* instr);

#ifdef __cplusplus
}
#endif

#endif /* R_SIMATIC_H */