#include <stdint.h>
#include "defs.h"

#define SEED 0xDEADDEAD
#define HASH(API)(crc32b((uint8_t *)API))

uint32_t crc32b(const uint8_t *str);

void *get_proc_address_by_hash(void *dll_address, uint32_t function_hash);
