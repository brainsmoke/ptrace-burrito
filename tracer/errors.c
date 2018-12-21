
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "errors.h"

typedef struct cb_ll_s cb_ll_t;
struct cb_ll_s
{
	error_callback_t func;
	void *data;
	cb_ll_t *next;
};
static cb_ll_t *error_callbacks = NULL;

static void call_error_callbacks(void)
{
	cb_ll_t *i;
	for (i = error_callbacks; i; i=i->next)
		i->func(i->data);
}

void add_error_callback(error_callback_t func, void *data)
{
	cb_ll_t *cb = try_malloc(sizeof(cb_ll_t));
	*cb = (cb_ll_t) { .func = func, .data = data, .next = error_callbacks };
	error_callbacks = cb;
}

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
	call_error_callbacks();
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
	call_error_callbacks();
	exit(EXIT_FAILURE);
}


