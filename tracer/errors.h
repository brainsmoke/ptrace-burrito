#ifndef ERRORS_H
#define ERRORS_H

#include <stdlib.h>

/* aborts the program in case of a failure */
void *try_malloc(size_t size);
void *try_realloc(void *buf, size_t size);
void *try_strdup(const char *s);

/* insert a callback, to be called on exit */
typedef void (*error_callback_t)(void *);
void add_error_callback(error_callback_t func, void *data);

/* print error message and exit program immediately.
 * calls abort instead so that gdb will still have
 * a stack to work with
 */
void fatal_error(const char *fmt, ...);

/* same as fatal_error(), except that exit(EXIT_FAILURE) is called
 * instead of abort
 */
void die(const char *fmt, ...);

#endif
