
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


#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "errors.h"

/* aborts the program in case of a failure */
void *try_malloc(size_t size)
{
	void *p = malloc(size);

	if ( p == NULL )
		fatal_error("malloc failed");

	return p;
}

void *try_realloc(void *buf, size_t size)
{
	void *p = realloc(buf, size);

	if ( p == NULL )
		fatal_error("realloc failed");

	return p;
}

void *try_strdup(const char *s)
{
	void *p = strdup(s);

	if ( p == NULL )
		fatal_error("strdup failed");

	return p;
}

/* print error, abort immediately */
void fatal_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "fatal error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	fflush(stderr);
	exit(EXIT_FAILURE);
}

/* print error, die immediately */
void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fprintf(stderr, "error: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	fflush(stderr);
	exit(EXIT_FAILURE);
}


