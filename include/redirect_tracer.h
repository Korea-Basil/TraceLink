#ifndef REDIRECT_TRACER_H
#define REDIRECT_TRACER_H

#include <stddef.h>

/*
 * Trace redirects using HEAD requests only. On success, final_url is allocated
 * by this function and must be released with free().
 */
int redirect_trace(const char *input_url, char **final_url,
                   char *error, size_t error_size);

#endif
