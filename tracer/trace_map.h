
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

#ifndef TRACE_MAP_H
#define TRACE_MAP_H

#include <stddef.h>

#include "trace.h"

/* Very simple hash-table to store trace states for
 * multiple processes
 *
 */

typedef struct trace_map_s trace_map_t;

unsigned int trace_map_count(trace_map_t *map);

trace_map_t *create_trace_map(void);
void free_trace_map(trace_map_t *map);

trace_t *get_trace(trace_map_t *map, pid_t pid);
void put_trace(trace_map_t *map, trace_t *trace);
trace_t *pop_trace(trace_map_t *map, pid_t pid);
void del_trace(trace_map_t *map, pid_t pid);

trace_t **trace_list(trace_map_t *map, size_t *size);

#endif /* TRACE_MAP_H */
