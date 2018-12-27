
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

#include <stdlib.h>

#include "trace_map.h"
#include "errors.h"

/* Very simple hash-table to store trace states for
 * multiple processes
 *
 */

typedef struct trace_ll_s trace_ll_t;
struct trace_ll_s
{
	trace_t *trace;
	trace_ll_t *next;
};

#define TRACE_MAP_BUCKETS (137)
struct trace_map_s
{
	trace_ll_t *bucket[TRACE_MAP_BUCKETS];
	unsigned int count;

};

struct trace_iter_s
{
	trace_map_t *map;
	unsigned int cur_bucket;
	trace_ll_t *cur;
};

static unsigned int free_trace_ll(trace_ll_t *list)
{
	unsigned int c = 0;
	trace_ll_t *del;
	while ( (del = list) )
	{
		list = list->next;
		free(del->trace);
		free(del);
		c++;
	}

	return c;
}

static unsigned int hash_pid(pid_t pid)
{
	return (unsigned int)pid % TRACE_MAP_BUCKETS;
}

unsigned int trace_map_count(trace_map_t *map)
{
	return map->count;
}

trace_map_t *create_trace_map(void)
{
	int i;
	trace_map_t *map = (trace_map_t*)try_malloc(sizeof(trace_map_t));

	for (i=0; i<TRACE_MAP_BUCKETS; i++)
		map->bucket[i] = NULL;

	map->count = 0;

	return map;
}

void free_trace_map(trace_map_t *map)
{
	int i;

	for (i=0; i<TRACE_MAP_BUCKETS; i++)
		map->count -= free_trace_ll(map->bucket[i]);

	free(map);
}

trace_t *get_trace(trace_map_t *map, pid_t pid)
{
	trace_ll_t *list = map->bucket[hash_pid(pid)];

	while (list)
	{
		if ( list->trace->pid == pid )
			return list->trace;

		list = list->next;
	}

	//fatal_error("no trace with pid %d", pid);
	return NULL;
}

void put_trace(trace_map_t *map, trace_t *t)
{
	unsigned int hash = hash_pid(t->pid);
	trace_ll_t *list = try_malloc(sizeof(trace_ll_t));

	*list = (trace_ll_t){ t, map->bucket[hash] };

	map->bucket[hash] = list;

	if ( list->trace == NULL )
		fatal_error("inserting NULL-pointer as trace object");

	while ( (list = list->next) )
		if ( list->trace->pid == t->pid )
			fatal_error("inserting already present trace with pid %d", t->pid);

	map->count++;
}

trace_t *pop_trace(trace_map_t *map, pid_t pid)
{
	unsigned int hash = hash_pid(pid);
	trace_ll_t prev = (trace_ll_t){ NULL, map->bucket[hash] };
	trace_ll_t *iter = &prev, *del;

	while (iter->next)
	{
		if (iter->next->trace->pid == pid)
		{
			del = iter->next;
			iter->next = iter->next->next;
			trace_t *t = del->trace;
			free(del);
			map->count--;
			map->bucket[hash] = prev.next;
			return t;
		}
		iter = iter->next;
	}

	return NULL;
}

void del_trace(trace_map_t *map, pid_t pid)
{
	trace_t *t = pop_trace(map, pid);
	if (t == NULL)
		fatal_error("no trace with pid %d to remove", pid);
	free(t);
}

static int cmp_trace_by_pid(const void *a, const void *b)
{
	return (*(trace_t**)a)->pid - (*(trace_t**)b)->pid;
}

trace_t **trace_list(trace_map_t *map, size_t *size)
{
	trace_t **list = try_malloc(sizeof(trace_t*)*map->count);
	*size = map->count;
	int i,c=0;
	trace_ll_t *ll;
	for (i=0; i<TRACE_MAP_BUCKETS; i++)
		for (ll=map->bucket[i]; ll; ll=ll->next)
		{
			if (c >= map->count)
				fatal_error("trace_map_t contains more traces than map->count");
			list[c++] = ll->trace;
		}

	if (c != map->count)
		fatal_error("trace_map_t contains less traces than map->count");

	qsort(list, map->count, sizeof(trace_t*), cmp_trace_by_pid);

	return list;
}

