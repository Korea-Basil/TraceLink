#include "security_check.h"

#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#ifdef _WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp
#else
#include <strings.h>
#endif

static const char *const shortener_hosts[] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at"
};

static const char *const brand_labels[] = {
    "amazon", "apple", "facebook", "google", "microsoft",
    "netflix", "paypal", "twitter"
};

static const char *const image_extensions[] = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"
};

static const char *const executable_extensions[] = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".js", ".hta",
    ".scr", ".apk", ".jar", ".vbs", ".com"
};

static const char *const redirect_parameters[] = {
    "target", "url", "dest", "destination", "redirect", "redirect_url",
    "return", "return_url", "continue", "next", "forward", "out"
};

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
    int failed;
} Report;

static void report_append(Report *report, const char *format, ...)
{
    va_list arguments;
    va_list copy;
    int required;
    size_t needed;

    if (report->failed)
        return;

    va_start(arguments, format);
    va_copy(copy, arguments);
    required = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (required < 0) {
        report->failed = 1;
        va_end(arguments);
        return;
    }

    needed = report->length + (size_t)required + 1;
    if (needed > report->capacity) {
        size_t capacity = report->capacity == 0 ? 512 : report->capacity;
        char *data;
        while (capacity < needed) {
            if (capacity > (size_t)-1 / 2) {
                report->failed = 1;
                va_end(arguments);
                return;
            }
            capacity *= 2;
        }
        data = realloc(report->data, capacity);
        if (data == NULL) {
            report->failed = 1;
            va_end(arguments);
            return;
        }
        report->data = data;
        report->capacity = capacity;
    }

    vsnprintf(report->data + report->length, report->capacity - report->length,
              format, arguments);
    report->length += (size_t)required;
    va_end(arguments);
}

static int is_redirect_parameter(const char *key)
{
    size_t i;
    for (i = 0; i < sizeof(redirect_parameters) / sizeof(redirect_parameters[0]); ++i) {
        if (strcasecmp(key, redirect_parameters[i]) == 0)
            return 1;
    }
    return 0;
}

static char *decode_component(const char *text, size_t length)
{
    int decoded_length = 0;
    if (length > (size_t)INT_MAX)
        return NULL;
    return curl_easy_unescape(NULL, text, (int)length, &decoded_length);
}

static int host_is_shortener(const char *host)
{
    size_t i;
    for (i = 0; i < sizeof(shortener_hosts) / sizeof(shortener_hosts[0]); ++i) {
        if (url_host_is_or_under(host, shortener_hosts[i]))
            return 1;
    }
    return 0;
}

static size_t count_labels(const char *host)
{
    size_t count = 1;
    const char *cursor;
    for (cursor = host; *cursor != '\0'; ++cursor) {
        if (*cursor == '.')
            ++count;
    }
    return count;
}

static int edit_distance_one(const char *left, const char *right)
{
    size_t left_length = strlen(left);
    size_t right_length = strlen(right);
    size_t i = 0;
    size_t j = 0;
    int differences = 0;

    if (left_length > right_length + 1 || right_length > left_length + 1)
        return 0;
    while (i < left_length && j < right_length) {
        if (tolower((unsigned char)left[i]) == tolower((unsigned char)right[j])) {
            ++i;
            ++j;
        } else if (++differences > 1) {
            return 0;
        } else if (left_length > right_length) {
            ++i;
        } else if (right_length > left_length) {
            ++j;
        } else {
            ++i;
            ++j;
        }
    }
    if (i < left_length || j < right_length)
        ++differences;
    return differences == 1;
}

static int has_brand_typo(const char *host)
{
    const char *label = host;
    const char *cursor = host;

    while (1) {
        if (*cursor == '.' || *cursor == '\0') {
            size_t length = (size_t)(cursor - label);
            char current[256];
            size_t i;
            if (length > 0 && length < sizeof(current)) {
                memcpy(current, label, length);
                current[length] = '\0';
                for (i = 0; i < sizeof(brand_labels) / sizeof(brand_labels[0]); ++i) {
                    if (length >= 4 && edit_distance_one(current, brand_labels[i]))
                        return 1;
                }
            }
            if (*cursor == '\0')
                break;
            label = cursor + 1;
        }
        ++cursor;
    }
    return 0;
}

static int is_discord_host(const char *host)
{
    return url_host_is_or_under(host, "discord.com") ||
           url_host_is_or_under(host, "discordapp.com") ||
           url_host_is_or_under(host, "discord.gg");
}

static int is_image_path(const char *path)
{
    return url_path_has_extension(path, image_extensions,
                                  sizeof(image_extensions) / sizeof(image_extensions[0]));
}

static int contains_image_extension(const char *text)
{
    size_t i;
    const char *cursor;

    if (text == NULL)
        return 0;
    for (cursor = text; *cursor != '\0'; ++cursor) {
        for (i = 0; i < sizeof(image_extensions) / sizeof(image_extensions[0]); ++i) {
            size_t extension_length = strlen(image_extensions[i]);
            if (strncasecmp(cursor, image_extensions[i], extension_length) == 0)
                return 1;
        }
    }
    return 0;
}

static int is_executable_path(const char *path)
{
    return url_path_has_extension(
        path, executable_extensions,
        sizeof(executable_extensions) / sizeof(executable_extensions[0]));
}

static int parse_candidate_url(const char *value, ParsedUrl *candidate)
{
    char *normalized = NULL;
    char error[256];
    int result;
    const char *input = value;

    if (strncmp(value, "//", 2) == 0) {
        normalized = malloc(strlen(value) + 7);
        if (normalized == NULL)
            return 0;
        snprintf(normalized, strlen(value) + 7, "https:%s", value);
        input = normalized;
    } else if (strstr(value, "://") == NULL &&
               value[0] != '/' && strchr(value, '.') != NULL) {
        normalized = malloc(strlen(value) + 9);
        if (normalized == NULL)
            return 0;
        snprintf(normalized, strlen(value) + 9, "https://%s", value);
        input = normalized;
    }

    result = url_parse(input, candidate, error, sizeof(error));
    free(normalized);
    return result;
}

static void inspect_query(const ParsedUrl *url, Language language, Report *report)
{
    const char *item = url->query;
    char *decoded_query;
    int image_marker;

    if (item == NULL)
        return;
    decoded_query = decode_component(item, strlen(item));
    image_marker = is_image_path(url->path) ||
                   contains_image_extension(decoded_query == NULL ? item : decoded_query);
    if (decoded_query != NULL)
        curl_free(decoded_query);
    while (*item != '\0') {
        const char *end = strchr(item, '&');
        const char *equals;
        size_t item_length = end == NULL ? strlen(item) : (size_t)(end - item);
        size_t key_length;
        size_t value_length;
        const char *value;
        char *key;
        char *decoded_value;

        equals = memchr(item, '=', item_length);
        key_length = equals == NULL ? item_length : (size_t)(equals - item);
        value = equals == NULL ? item + item_length : equals + 1;
        value_length = equals == NULL ? 0 : item_length - key_length - 1;
        key = decode_component(item, key_length);
        decoded_value = decode_component(value, value_length);

        if (key != NULL && decoded_value != NULL) {
            ParsedUrl candidate = {0};
            int recognized = is_redirect_parameter(key);
            int looks_like_url = strstr(decoded_value, "://") != NULL ||
                                 strncmp(decoded_value, "//", 2) == 0 ||
                                 (strchr(decoded_value, '.') != NULL &&
                                  (recognized || strchr(decoded_value, '/') != NULL));
            int parsed = looks_like_url &&
                         parse_candidate_url(decoded_value, &candidate);

            if (recognized)
                report_append(report, i18n_get(language, TEXT_REDIRECT_PARAMETER), key);
            if (recognized)
                report_append(report, "\n");
            if (parsed && candidate.host != NULL &&
                !url_host_is_or_under(candidate.host, url->host) &&
                !url_host_is_or_under(url->host, candidate.host)) {
                if (recognized)
                    report_append(report, i18n_get(language, TEXT_QUERY_HOST_MISMATCH),
                                  candidate.host);
                if (recognized)
                    report_append(report, "\n");
                if (image_marker &&
                    (!is_image_path(candidate.path) || is_executable_path(candidate.path))) {
                    report_append(report, i18n_get(language, TEXT_IMAGE_QUERY_WARNING),
                                  candidate.host);
                    report_append(report, "\n");
                }
            }

            url_parsed_cleanup(&candidate);
        }

        if (key != NULL)
            curl_free(key);
        if (decoded_value != NULL)
            curl_free(decoded_value);
        if (end == NULL)
            break;
        item = end + 1;
    }
}

char *security_check_report(const ParsedUrl *url, const char *final_url,
                            Language language)
{
    Report report = {0};
    ParsedUrl final = {0};
    char error[256];
    int has_final = final_url != NULL &&
                    url_parse(final_url, &final, error, sizeof(error));

    if (url == NULL || url->scheme == NULL || url->host == NULL) {
        url_parsed_cleanup(&final);
        return NULL;
    }

    report_append(&report, "%s\n\n", i18n_get(language, TEXT_REPORT_TITLE));
    if (final_url != NULL && !has_final)
        report_append(&report, "%s\n", i18n_get(language, TEXT_FINAL_PARSE_WARNING));
    if (strcasecmp(url->scheme, "http") == 0)
        report_append(&report, "%s\n", i18n_get(language, TEXT_HTTP_WARNING));
    else
        report_append(&report, "%s\n", i18n_get(language, TEXT_HTTPS_INFO));

    if (url_is_ip_address(url->host))
        report_append(&report, "%s\n", i18n_get(language, TEXT_IP_WARNING));
    if (count_labels(url->host) > 4)
        report_append(&report, i18n_get(language, TEXT_SUBDOMAIN_WARNING),
                      count_labels(url->host));
    if (count_labels(url->host) > 4)
        report_append(&report, "\n");
    if (strstr(url->host, "xn--") != NULL)
        report_append(&report, "%s\n", i18n_get(language, TEXT_IDN_WARNING));
    if (has_brand_typo(url->host))
        report_append(&report, "%s\n", i18n_get(language, TEXT_TYPO_WARNING));
    if (host_is_shortener(url->host))
        report_append(&report, "%s\n", i18n_get(language, TEXT_SHORTENER_WARNING));
    if (url->has_userinfo)
        report_append(&report, "%s\n", i18n_get(language, TEXT_USERINFO_WARNING));

    inspect_query(url, language, &report);

    if (has_final) {
        if (is_discord_host(url->host) &&
            !is_discord_host(final.host)) {
            report_append(&report, i18n_get(language, TEXT_DISCORD_REDIRECT_WARNING),
                          final.host);
            report_append(&report, "\n");
        }
        if (is_image_path(url->path) &&
            !url_host_is_or_under(url->host, final.host) &&
            !url_host_is_or_under(final.host, url->host) &&
            (!is_image_path(final.path) || is_executable_path(final.path))) {
            report_append(&report, i18n_get(language, TEXT_IMAGE_REDIRECT_WARNING),
                          final.host);
            report_append(&report, "\n");
        }
        if (is_executable_path(final.path))
            report_append(&report, "%s\n",
                          i18n_get(language, TEXT_EXECUTABLE_WARNING));
        url_parsed_cleanup(&final);
    }

    if (!report.failed) {
        report_append(&report, "\n%s\n%s\n",
                      i18n_get(language, TEXT_HEURISTIC_NOTE),
                      i18n_get(language, TEXT_HEAD_ONLY_NOTE));
    }
    if (report.failed) {
        free(report.data);
        return NULL;
    }
    if (report.data == NULL) {
        report.data = malloc(1);
        if (report.data == NULL)
            return NULL;
        report.data[0] = '\0';
    }
    return report.data;
}
