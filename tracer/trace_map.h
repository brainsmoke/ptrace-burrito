#ifndef TRACE_MAP_H
#define TRACE_MAP_H

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
void del_trace(trace_map_t *map, pid_t pid);

#endif /* TRACE_MAP_H */
