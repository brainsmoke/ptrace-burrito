
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

#ifndef SIGNAL_INFO_H
#define SIGNAL_INFO_H

#include <signal.h>

/* The 'signal number' for not delivering a signal */
#define NO_SIGNAL (0)

#define ERESTARTSYS (512)
#define ERESTART_RESTARTBLOCK (516)

int is_synchronous(siginfo_t *info);

int signal_pending(long syscall, long retval);
int signal_restartsys(long syscall, long retval);

#endif /* SIGNAL_INFO_H */
