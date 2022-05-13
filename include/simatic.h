// SPDX-FileCopyrightText: 2019-2022 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef LIB_SIMATIC_H
#define LIB_SIMATIC_H

#include <simatic_types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define S7_INSTRUCTION_LEN 128

typedef struct s7_instr_t {
	char assembly[S7_INSTRUCTION_LEN];
	ut64_t jump;
	bool_t is_return;
} S7Instr;

int simatic_s7_decode_instruction(const ut8_t *buffer, const ut64_t size, const ut64_t addr, S7Instr *instr);

#ifdef __cplusplus
}
#endif

#endif /* LIB_SIMATIC_H */