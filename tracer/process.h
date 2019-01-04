
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

#ifndef PROCESS_H
#define PROCESS_H

#include <sys/types.h>
#include <stdio.h>

/* attach to existing process */
void trace_attach(pid_t pid);

/* trace a new process */
pid_t run_traceable(char *path, char *args[], int no_randomize, int notsc);

pid_t run_traceable_env(char *path, char *args[], char *envp[],
                        int no_randomize, int notsc);


FILE *open_maps(pid_t pid);

int parse_region(FILE *f, uintptr_t *base,
                          uintptr_t *end,
                          uintptr_t *file_offset,
                          char *filename_buf, size_t maxlen);

uintptr_t find_code_address(pid_t pid, const char *filename, uintptr_t offset);

/* caller frees */
const char *get_proc_exe(pid_t pid);
const char *get_proc_cwd(pid_t pid);
const char *get_proc_fd(pid_t pid, int fd);

#endif /* PROCESS_H */
