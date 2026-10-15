#ifndef URL_PARSER_H
#define URL_PARSER_H

#include <stddef.h>

typedef struct {
    char *scheme;
    char *host;
    char *path;
    char *query;
    int has_userinfo;
} ParsedUrl;

int url_parse(const char *text, ParsedUrl *parsed, char *error, size_t error_size);
void url_parsed_cleanup(ParsedUrl *parsed);
int url_host_is_or_under(const char *host, const char *domain);
int url_is_ip_address(const char *host);
int url_path_has_extension(const char *path, const char *const *extensions,
                           size_t extension_count);

#endif
