
/* This file is part of ptrace-burrito
 *
 * Copyright 2010-2018 Erik Bosman <erik@minemu.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SYMBOLS_H
#define SYMBOLS_H

#include <stdint.h>

/* Get the canonical filename & file-offset of a symbol
 * Very hackish, uses dlsym() in combination with parsing /proc/self/maps
 */
const char *get_symbol(const char *symbol, uintptr_t *offset);
const char *get_symbol_from_lib(const char *filename, const char *symbol, uintptr_t *offset);

#endif /* SYMBOLS_H */
