#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdlib.h>
#include <error.h>
#include <errno.h>
#include <string.h>

/** Allocate memory and make its contents all-zero
 * exit(100) on out of memory
 */
static inline void *ut_malloc(size_t size)
{
	void *ptr = malloc(size);

	if (ptr == NULL)
		error(100, -ENOMEM, "Out of memory");
	else
		memset(ptr, 0, size);

	return ptr;
}

#endif
