
#include <dlfcn.h>

#include <stdint.h>
#include <unistd.h>

#include "symbols.h"
#include "maps.h"

const char *get_symbol(const char *symbol, intptr_t *offset)
{
	return get_symbol_from_lib(NULL, symbol, offset);
}

const char *get_symbol_from_lib(const char *filename, const char *symbol, intptr_t *offset)
{
	if (offset)
		*offset = 0;

	void *handle = dlopen(filename, RTLD_LAZY);

	if (!handle)
		return NULL;

	void *addr = dlsym(handle, symbol);

	const char *libname = map_name(getpid(), (uintptr_t)addr, offset);

	dlclose(handle);

	return libname;
}
