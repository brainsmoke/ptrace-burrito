
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

#ifndef DEBUG_SYSCALLS_H
#define DEBUG_SYSCALLS_H

#include "trace.h"

/* get the name of a syscall */
const char *syscall_name(long no);

const char *socketcall_name(long no);

/* get the name of a syscall */
const char *signal_name(int no);
int signal_no(const char *name);

void print_flags(int flags);
void print_call(long call, long args[], int argc);
void print_trace_call(trace_t *t);
void print_trace_return(trace_t *t);

#endif /* DEBUG_SYSCALLS_H */
