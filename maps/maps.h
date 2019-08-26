
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

#ifndef MAPS_H
#define MAPS_H

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

/* Tagging support for file-backed memory.  Useful for code-coverage
 *
 */

typedef uint64_t tag_t;

tag_t *tag(pid_t pid, uintptr_t address);
void reset_tags(void);
void print_tags(FILE *f);

/* get filename / file offset of an address in memory,
 * result is valid until the next reset_maps(same_pid), should not be freed.
 */
const char *map_name(pid_t pid, uintptr_t address, uintptr_t *offset);

/* clear stale data (for example in case of an exec) */
void reset_maps(pid_t pid);

/* TODO: range unmap */

#endif /* MAPS_H */
