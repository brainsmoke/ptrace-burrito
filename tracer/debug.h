
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

#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>

#include "trace.h"

/* Various debugging functions with neat color-coding */

/* must be set first */
void debug_init(FILE *debug_out);
FILE *debug_out(void);

void printhex(const void *data, int len);
void printhex_diff(const void *data1, ssize_t len1,
                   const void *data2, ssize_t len2, int grane);

void print_trace(trace_t *t);
void print_trace_diff(trace_t *new, trace_t *old);
void print_trace_if_diff(trace_t *new, trace_t *old);

void print_registers(registers_t *regs);
void print_registers_diff(registers_t *new, registers_t *old);
void print_registers_if_diff(registers_t *new, registers_t *old);

void print_steptrace_debug(trace_t *t, registers_t *cmp);

struct stat64;
void print_stat(const struct stat64 *s);

#endif /* DEBUG_H */
