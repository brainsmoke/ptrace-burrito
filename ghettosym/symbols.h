#ifndef SYMBOLS_H
#define SYMBOLS_H

#include <stdint.h>

const char *get_symbol(const char *symbol, intptr_t *offset);
const char *get_symbol_from_lib(const char *filename, const char *symbol, intptr_t *offset);

#endif /* SYMBOLS_H */
