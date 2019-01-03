
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

#ifndef ERRORS_H
#define ERRORS_H

#include <stdlib.h>

/* aborts the program in case of a failure */
void *try_malloc(size_t size);
void *try_realloc(void *buf, size_t size);
void *try_strdup(const char *s);

/* print error message and exit program immediately.
 * calls abort instead so that gdb will still have
 * a stack to work with
 */
void fatal_error(const char *fmt, ...);

/* same as fatal_error(), except that exit(EXIT_FAILURE) is called
 * instead of abort
 */
void die(const char *fmt, ...);

#endif
