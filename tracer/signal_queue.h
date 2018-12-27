
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

#ifndef SIGNAL_QUEUE_H
#define SIGNAL_QUEUE_H

#include <signal.h>

#include "trace.h"

/* Trivial queue datastructure to store unhandled signals
 *
 */

typedef struct signal_queue_s signal_queue_t;

signal_queue_t *add_signal_queue(trace_t *t);
void del_signal_queue(trace_t *t);
signal_queue_t *signal_queue(trace_t *t);

void enqueue_signal(signal_queue_t *q, long signal, siginfo_t *info);
int dequeue_signal(signal_queue_t *q, long *signal, siginfo_t *info);
int signal_waiting(signal_queue_t *q);

#endif /* SIGNAL_QUEUE_H */
