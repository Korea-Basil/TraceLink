#include "url_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define strcasecmp _stricmp
#else
#include <arpa/inet.h>
#include <strings.h>
#endif

static char *get_url_part(CURLU *url, CURLUPart part)
{
    char *value = NULL;
    if (curl_url_get(url, part, &value, 0) != CURLUE_OK)
        return NULL;
    return value;
}

int url_parse(const char *text, ParsedUrl *parsed, char *error, size_t error_size)
{
    CURLU *url;
    CURLUcode result;

    if (parsed == NULL || text == NULL) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "URL input is missing.");
        return 0;
    }
    memset(parsed, 0, sizeof(*parsed));

    url = curl_url();
    if (url == NULL) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "Unable to allocate URL parser.");
        return 0;
    }

    result = curl_url_set(url, CURLUPART_URL, text, 0);
    if (result != CURLUE_OK) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "Invalid URL: %s", curl_url_strerror(result));
        curl_url_cleanup(url);
        return 0;
    }

    parsed->scheme = get_url_part(url, CURLUPART_SCHEME);
    parsed->host = get_url_part(url, CURLUPART_HOST);
    parsed->path = get_url_part(url, CURLUPART_PATH);
    parsed->query = get_url_part(url, CURLUPART_QUERY);
    {
        char *user = get_url_part(url, CURLUPART_USER);
        char *password = get_url_part(url, CURLUPART_PASSWORD);
        parsed->has_userinfo = user != NULL || password != NULL;
        if (user != NULL)
            curl_free(user);
        if (password != NULL)
            curl_free(password);
    }
    curl_url_cleanup(url);

    if (parsed->scheme == NULL || parsed->host == NULL) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "The URL must include a scheme and a host.");
        url_parsed_cleanup(parsed);
        return 0;
    }
    if (strcasecmp(parsed->scheme, "http") != 0 &&
        strcasecmp(parsed->scheme, "https") != 0) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "Unsupported protocol '%s'; use HTTP or HTTPS.",
                     parsed->scheme);
        url_parsed_cleanup(parsed);
        return 0;
    }
    return 1;
}

void url_parsed_cleanup(ParsedUrl *parsed)
{
    if (parsed == NULL)
        return;
    if (parsed->scheme != NULL)
        curl_free(parsed->scheme);
    if (parsed->host != NULL)
        curl_free(parsed->host);
    if (parsed->path != NULL)
        curl_free(parsed->path);
    if (parsed->query != NULL)
        curl_free(parsed->query);
    memset(parsed, 0, sizeof(*parsed));
}

int url_host_is_or_under(const char *host, const char *domain)
{
    size_t host_length;
    size_t domain_length;

    if (host == NULL || domain == NULL)
        return 0;
    host_length = strlen(host);
    domain_length = strlen(domain);
    if (host_length < domain_length ||
        strcasecmp(host + host_length - domain_length, domain) != 0)
        return 0;
    return host_length == domain_length ||
           host[host_length - domain_length - 1] == '.';
}

int url_is_ip_address(const char *host)
{
    struct in_addr ipv4;
    struct in6_addr ipv6;
    char unbracketed[INET6_ADDRSTRLEN + 1];
    size_t length;
    const char *address;

    if (host == NULL)
        return 0;
    length = strlen(host);
    address = host;
    if (length >= 2 && host[0] == '[' && host[length - 1] == ']' &&
        length - 2 < sizeof(unbracketed)) {
        memcpy(unbracketed, host + 1, length - 2);
        unbracketed[length - 2] = '\0';
        address = unbracketed;
    }

    return inet_pton(AF_INET, address, &ipv4) == 1 ||
           inet_pton(AF_INET6, address, &ipv6) == 1;
}

int url_path_has_extension(const char *path, const char *const *extensions,
                           size_t extension_count)
{
    const char *dot;
    const char *slash;
    size_t i;

    if (path == NULL)
        return 0;
    dot = strrchr(path, '.');
    slash = strrchr(path, '/');
    if (dot == NULL || (slash != NULL && dot < slash))
        return 0;
    for (i = 0; i < extension_count; ++i) {
        if (strcasecmp(dot, extensions[i]) == 0)
            return 1;
    }
    return 0;
}
