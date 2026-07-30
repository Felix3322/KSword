#pragma once

#include "ark/ark_mutation.h"

EXTERN_C_START

/*
 * Inputs: none. Processing: exposes the fixed response size used by mutation
 * handlers. Return: macro expands to the byte size of KSWORD_ARK_MUTATION_RESPONSE.
 */
#define KSWORD_ARK_MUTATION_RESPONSE_FIXED_SIZE sizeof(KSWORD_ARK_MUTATION_RESPONSE)

EXTERN_C_END
