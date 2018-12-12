
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>

#include "maps.h"
#include "errors.h"

#define MAX_REGIONS 65536


typedef struct process_list_s process_list_t;
        struct process_list_s
{
	pid_t pid;
	mmap_region_t *regions, *last, *regions_retired;
	int n_regions;
	int n_regions_retired;
	process_list_t *next;
};

static process_list_t *list = NULL;
static pid_t lastpid=0;
static mmap_region_t *lastregion=NULL;

static FILE *open_maps(pid_t pid)
{
	int maxlen = 64;
	char name[maxlen];
	int len = snprintf(name, maxlen, "/proc/%u/maps", pid);

	if ( (len >= maxlen) || (len < 0) )
		fatal_error("%s: snprintf failed where it shouldn't", __func__);

	FILE *f = fopen(name, "r");
	if (f == NULL)
		fatal_error("%s: cannot open %s", __func__, name);

	return f;
}

void print_mmap_region(mmap_region_t *r)
{
	printf("{ %016lx[%016lx] @ %s[%016lx] }\n", r->base, r->size, r->name, r->file_offset);
}

static int parse_region(FILE *f, mmap_region_t *r)
{
	uintptr_t end=0;
	int n = fscanf(f, "%lx-%lx %*s %lx %*s %*s", &r->base, &end, &r->file_offset);
	if (n != 3)
		return 0;

	int c;
	while ( (c = fgetc(f)) == ' ' );
	ungetc(c, f);

	if (!fgets(r->name, 4098, f))
		return 0;

	r->size = end-r->base;

	int len = strlen(r->name);
	if (len>0 && r->name[len-1] == '\n')
		r->name[len-1] = '\0';

	return 1;
}

mmap_region_t *get_mmap_region(pid_t pid, uintptr_t address, mmap_region_t *r)
{
	FILE *f = open_maps(pid);
	*r = (mmap_region_t) { .name = try_malloc(4098) };
	r->name[0] = '\0';
	while (parse_region(f, r))
		if (inside(address, r))
		{
			r->tags = try_malloc(r->size*sizeof(tag_t));
			memset(r->tags, 0, r->size*sizeof(tag_t));
			fclose(f);
			return r;
		}
	fatal_error("%s: %lx MAP NOT FOUND", __func__, address);
	free(r->name);
	r->name = NULL;
	fclose(f);
	return NULL;
}

static process_list_t *find_process(pid_t pid)
{
	process_list_t *l = list;
	for (l=list; l; l=l->next)
	{
		if (l->pid == pid)
			return l;
	}
	process_list_t *old_head=list;
	list = try_malloc(sizeof(process_list_t));
	*list = (process_list_t)
	{
		.next=old_head,

		.pid = pid,
		.regions = try_malloc(MAX_REGIONS*sizeof(mmap_region_t)),
		.n_regions = 0,
		.n_regions_retired = 0,
		.regions_retired = NULL,
		.last = NULL,
	};
	return list;
}

mmap_region_t *find_mmap_region(process_list_t *l, uintptr_t address)
{
	int i;
	for (i=0; i<l->n_regions;i++)
		if (inside(address, &l->regions[i]))
			return &l->regions[i];

	return NULL;
}

tag_t *tag(pid_t pid, uintptr_t address)
{
	/* fastpath */
	if (lastpid && (pid == lastpid) && inside(address, lastregion) )
		return &lastregion->tags[address-lastregion->base];

	process_list_t *l = find_process(pid);
	if (!l->last || !inside(address, l->last))
	{
		l->last = find_mmap_region(l, address);
		if (!l->last)
		{
			if (l->n_regions < MAX_REGIONS)
				l->last = get_mmap_region(pid, address, &l->regions[l->n_regions++]);
			else
				fatal_error("%s: MAX_REGIONS reached", __func__);
		}
	}

	if (l->last)
	{
		lastpid = pid;
		lastregion = l->last;
		return &l->last->tags[address-l->last->base];
	}
	else
	{
		lastpid = 0;
		return NULL;
	}
}

void reset_maps(pid_t pid)
{
	process_list_t *l = find_process(pid);
	l->regions_retired = try_realloc(l->regions_retired, (l->n_regions + l->n_regions_retired) * sizeof(mmap_region_t));
	memcpy(&l->regions_retired[l->n_regions_retired], &l->regions[0], l->n_regions*sizeof(mmap_region_t));
	l->n_regions_retired += l->n_regions;
	l->n_regions = 0;
	lastpid = 0;
}

void print_regions(FILE *f, mmap_region_t *regions, int n_regions)
{
	int i;
	uintptr_t j;
	for (i=0; i<n_regions;i++)
	{
		mmap_region_t *r = &regions[i];
		uintptr_t size = r->size;
		for (j=0; j<size; j++)
			if (r->tags[j])
				fprintf(f, "%s [ %lx ] = %" PRIu64 "\n", r->name, r->file_offset+j, r->tags[j]);
	}
}

void print_tags(FILE *f)
{
	process_list_t *l;
	for (l=list; l; l=l->next)
	{
		print_regions(f, l->regions, l->n_regions);
		print_regions(f, l->regions_retired, l->n_regions_retired);
	}
}

