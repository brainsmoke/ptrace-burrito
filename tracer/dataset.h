
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

#ifndef DATASET_H
#define DATASET_H

#include <sys/types.h>

/* Tiny framework to define and attach arbitrary data t a set at runtime */

typedef struct data_header_s *dataset_t;
long register_type(size_t size); /* not thread-safe */

void *add_data(dataset_t *d, long type);
void *get_data(dataset_t *d, long type);
int has_data(dataset_t *d, long type);
void del_data(dataset_t *d, long type);
void free_dataset(dataset_t *d);

#endif /* DATASET_H */
