
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


#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>

#include "maps.h"
#include "process.h"
#include "errors.h"

#define MAX_REGIONS 65536

typedef struct file_tags_s file_tags_t;
        struct file_tags_s
{
	char *name;
	uintptr_t size;
	tag_t *tags;

	file_tags_t *next;
};


typedef struct
{
	char *name;
	uintptr_t base;
	uintptr_t size;
	uintptr_t file_offset;
	tag_t *tags;
	file_tags_t *file_tags;

} mmap_region_t;


typedef struct process_list_s process_list_t;
        struct process_list_s
{
	pid_t pid;
	mmap_region_t *regions, *last;
	int n_regions;
	process_list_t *next;
};

static process_list_t *list = NULL;
static pid_t last_tag_pid=0, last_name_pid=0;
static mmap_region_t *last_tag_region, *last_name_region;
static file_tags_t *tags_list;

/* values in r are trusted :-P, no 64 bit overflow nonsense */
static inline int inside(uintptr_t address, mmap_region_t *r)
{
	return ( (address - r->base) < r->size );
}

void print_mmap_region(mmap_region_t *r)
{
	printf("{ %016lx[%016lx] @ %s[%016lx] }\n", r->base, r->size, r->name, r->file_offset);
}

static mmap_region_t *get_mmap_region(pid_t pid, uintptr_t address, mmap_region_t *r)
{
	FILE *f = open_maps(pid);
	char name[4098];
	uintptr_t base, end, file_offset;
	while (parse_region(f, &base, &end, &file_offset, name, 4098))
		if (address >= base && address < end)
		{
			fclose(f);
			*r = (mmap_region_t)
			{
				.base = base,
				.size = end-base,
				.file_offset = file_offset,
				.name = try_strdup(name),
			};
			return r;
		}
	r->name = NULL;
	fclose(f);
	fatal_error("%s: %lx MAP NOT FOUND", __func__, address);
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

static void update_region_tags(file_tags_t *f)
{
	process_list_t *l = list;
	int i;
	for (l=list; l; l=l->next)
		for (i=0; i<l->n_regions; i++)
		{
			mmap_region_t *r = &l->regions[i];
			if (r->file_tags == f)
				r->tags = &f->tags[r->file_offset];
		}
}

static void update_file_tags(mmap_region_t *r)
{
	file_tags_t *f = tags_list;
	for (f=tags_list; f; f=f->next)
		if (strcmp(f->name, r->name) == 0)
			break;

	uintptr_t size = r->file_offset + r->size;

	if (!f)
	{
		f = try_malloc(sizeof(file_tags_t));
		*f = (file_tags_t)
		{
			.name = strdup(r->name),
			.size = size,
			.tags = try_malloc(size*sizeof(tag_t)),
			.next = tags_list,
		};
		tags_list = f;
		memset(f->tags, 0, size*sizeof(tag_t));
	}

	if (f->size < size)
	{
		tag_t *old_buf = f->tags;
		f->tags = try_realloc(f->tags, size*sizeof(tag_t));
		memset(&f->tags[f->size], 0, (size-f->size)*sizeof(tag_t));
		f->size = size;

		if (f->tags != old_buf)
			update_region_tags(f);
	}

	r->file_tags = f;
	r->tags = &f->tags[r->file_offset];
}

tag_t *tag(pid_t pid, uintptr_t address)
{
	/* fastpath */
	if (last_tag_pid && (pid == last_tag_pid) && inside(address, last_tag_region) )
		return &last_tag_region->tags[address-last_tag_region->base];

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
		if (!l->last->tags)
			update_file_tags(l->last);

		last_tag_pid = pid;
		last_tag_region = l->last;
		return &l->last->tags[address-l->last->base];
	}
	else
	{
		last_tag_pid = 0;
		return NULL;
	}
}

const char *map_name(pid_t pid, uintptr_t address, uintptr_t *offset)
{
	/* fastpath */
	if (last_name_pid && (pid == last_name_pid) && inside(address, last_name_region) )
	{
		if (offset) *offset = address-last_name_region->base+last_name_region->file_offset;
		return last_name_region->name;
	}

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
		last_name_pid = pid;
		last_name_region = l->last;
		if (offset) *offset = address-last_name_region->base+last_name_region->file_offset;
		return last_name_region->name;
	}
	else
	{
		last_name_pid = 0;
		if (offset) *offset = address;
		return "<unknown>";
	}
}

void reset_maps(pid_t pid)
{
	last_tag_pid = last_name_pid = 0;
	process_list_t *l = find_process(pid);

	int i;
	for (i=0; i<l->n_regions; i++)
		free(l->regions[i].name);
	l->n_regions = 0;
}

void reset_tags(void)
{
	last_tag_pid = 0;
	file_tags_t *f;
	for (f=tags_list; f; f=f->next)
	{
		if (f->tags)
		{
			free(f->tags);
			f->tags = NULL;
			f->size = 0;
		}
	}

	process_list_t *l = list;
	int i;
	for (l=list; l; l=l->next)
		for (i=0; i<l->n_regions; i++)
		{
			mmap_region_t *r = &l->regions[i];
			r->tags = NULL;
			r->file_tags = NULL;
		}
}

void print_tags(FILE *f)
{
	file_tags_t *it;
	uintptr_t j;
	for (it=tags_list; it; it=it->next)
		for (j=0; j<it->size; j++)
			if (it->tags[j])
				fprintf(f, "%s [ %lx ] = %" PRIu64 "\n", it->name, j, it->tags[j]);
}

