
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

	fatal_error("no trace with pid %d", pid);
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

void del_trace(trace_map_t *map, pid_t pid)
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
			free(del->trace);
			free(del);
			map->count--;
			map->bucket[hash] = prev.next;
			return;
		}
		iter = iter->next;
	}

	fatal_error("no trace with pid %d to remove", pid);
}

