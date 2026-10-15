#include "redirect_tracer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#define MAX_REDIRECTS 10L

int redirect_trace(const char *input_url, char **final_url,
                   char *error, size_t error_size)
{
    CURL *curl;
    CURLcode result;
    char *effective_url = NULL;

    if (final_url == NULL)
        return 0;
    *final_url = NULL;
    curl = curl_easy_init();
    if (curl == NULL) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "Unable to initialize libcurl.");
        return 0;
    }

#define SET_CURL_OPTION(option, value) do { \
        result = curl_easy_setopt(curl, option, value); \
        if (result != CURLE_OK) \
            goto option_error; \
    } while (0)

    SET_CURL_OPTION(CURLOPT_URL, input_url);
    SET_CURL_OPTION(CURLOPT_NOBODY, 1L);
    SET_CURL_OPTION(CURLOPT_FOLLOWLOCATION, 1L);
    SET_CURL_OPTION(CURLOPT_MAXREDIRS, MAX_REDIRECTS);
    SET_CURL_OPTION(CURLOPT_CONNECTTIMEOUT, 5L);
    SET_CURL_OPTION(CURLOPT_TIMEOUT, 15L);
    SET_CURL_OPTION(CURLOPT_NOSIGNAL, 1L);
    SET_CURL_OPTION(CURLOPT_USERAGENT, "URLThreatAnalyzer/1.0");
#if LIBCURL_VERSION_NUM >= 0x075500
    SET_CURL_OPTION(CURLOPT_PROTOCOLS_STR, "http,https");
    SET_CURL_OPTION(CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    SET_CURL_OPTION(CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    SET_CURL_OPTION(CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif

    result = curl_easy_perform(curl);
    if (result == CURLE_OK) {
        result = curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url);
        if (result == CURLE_OK && effective_url != NULL) {
            *final_url = malloc(strlen(effective_url) + 1);
            if (*final_url != NULL)
                strcpy(*final_url, effective_url);
            else
                result = CURLE_OUT_OF_MEMORY;
        }
    }

#undef SET_CURL_OPTION

    if (result != CURLE_OK || *final_url == NULL) {
        if (error != NULL && error_size > 0)
            snprintf(error, error_size, "%s",
                     result == CURLE_OK ? "Unable to store final URL." :
                     curl_easy_strerror(result));
        free(*final_url);
        *final_url = NULL;
        curl_easy_cleanup(curl);
        return 0;
    }

    curl_easy_cleanup(curl);
    return 1;

option_error:
    if (error != NULL && error_size > 0)
        snprintf(error, error_size, "Unable to configure HEAD request: %s",
                 curl_easy_strerror(result));
    curl_easy_cleanup(curl);
    return 0;
}
