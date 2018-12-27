
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


#include "dataset.h"
#include "errors.h"

struct data_header_s
{
	long type;
	dataset_t next;
};

#define MAX_TYPES 256
static int n_types = 0;
static size_t type_size[MAX_TYPES];

long register_type(size_t size)
{
	if (n_types >= MAX_TYPES) 
		fatal_error("too many data types registered for dataset");

	type_size[n_types] = size;
	n_types++;

	return n_types-1;
}

void *add_data(dataset_t *d, long type)
{
	struct data_header_s **i, *hdr;

	if ( type < 0 || type >= n_types ) 
		fatal_error("cannot add unknown type");

	for (i=d; *i; i=&(**i).next)
		if ( (**i).type == type )
			fatal_error("cannot add the same type twice");

	*i = try_malloc( sizeof(struct data_header_s) + type_size[type] );
	hdr = *i;
	*hdr = (struct data_header_s)
	{
		.type = type,
		.next = NULL,
	};
	return (void *)&hdr[1];
}

void *get_data(dataset_t *d, long type)
{
	struct data_header_s *i;

	for (i=*d; i; i=i->next)
		if ( i->type == type )
			return (void *)&i[1];

	return NULL;
}

int has_data(dataset_t *d, long type)
{
	return get_data(d, type) ? 1:0;
}

void del_data(dataset_t *d, long type)
{
	struct data_header_s **i, *del;

	for (i=d; *i; i=&(**i).next)
		if ( (**i).type == type )
		{
			del = *i;
			*i = (**i).next;
			free(del);
			break;
		}
}

void free_dataset(dataset_t *d)
{
	while (*d)
		del_data(d, (**d).type);
}

