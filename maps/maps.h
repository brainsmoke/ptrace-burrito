#ifndef MAPS_H
#define MAPS_H

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>

typedef uint64_t tag_t;

typedef struct
{
	char *name;
	uintptr_t base;
	uintptr_t size;
	uintptr_t file_offset;
	tag_t *tags;
} mmap_region_t;


tag_t *tag(pid_t pid, uintptr_t address);
void reset_maps(pid_t pid);

/* values in r are trusted :-P, no 64 bit overflow nonsense */
static inline int inside(uintptr_t address, mmap_region_t *r)
{
	return ( (address - r->base) < r->size );
}

void print_tags(FILE *f);

uintptr_t find_code_address(pid_t pid, const char *filename, uintptr_t offset);

#endif /* MAPS_H */
