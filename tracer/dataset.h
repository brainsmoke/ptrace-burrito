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
