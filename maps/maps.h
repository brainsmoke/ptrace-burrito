
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
#include <stdio.h>
#include <stdint.h>

typedef uint64_t tag_t;

typedef struct
{
	char *name;
	uintptr_t base;
	uintptr_t size;
	uintptr_t file_offset;
	tag_t *tags;
} mmap_region_t;


tag_t *tag(pid_t pid, uintptr_t address);
const char *map_name(pid_t pid, uintptr_t address, uintptr_t *offset);
void reset_maps(pid_t pid);

/* values in r are trusted :-P, no 64 bit overflow nonsense */
static inline int inside(uintptr_t address, mmap_region_t *r)
{
	return ( (address - r->base) < r->size );
}

void print_tags(FILE *f);

uintptr_t find_code_address(pid_t pid, const char *filename, uintptr_t offset);

#endif /* MAPS_H */
