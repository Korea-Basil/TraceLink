#include "redirect_tracer.h"
#include "security_check.h"
#include "url_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#define URL_BUFFER_SIZE 8192

int main(void)
{
    char input_url[URL_BUFFER_SIZE];
    char error[256];
    char *final_url = NULL;
    char *report = NULL;
    ParsedUrl parsed = {0};
    size_t length;
    int exit_status = EXIT_SUCCESS;

#ifdef _WIN32
    WSADATA winsock_data;
    if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
        fprintf(stderr, "Unable to initialize Winsock.\n");
        return EXIT_FAILURE;
    }
#endif

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Unable to initialize libcurl.\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    printf("Enter a website URL (including http:// or https://): ");
    if (fgets(input_url, sizeof(input_url), stdin) == NULL) {
        fprintf(stderr, "No URL was provided.\n");
        exit_status = EXIT_FAILURE;
        goto cleanup;
    }

    length = strcspn(input_url, "\r\n");
    input_url[length] = '\0';
    if (length == 0 || length == sizeof(input_url) - 1) {
        fprintf(stderr, "URL is empty or too long.\n");
        exit_status = EXIT_FAILURE;
        goto cleanup;
    }
    if (!url_parse(input_url, &parsed, error, sizeof(error))) {
        fprintf(stderr, "%s\n", error);
        exit_status = EXIT_FAILURE;
        goto cleanup;
    }

    printf("\nAnalyzing: %s\n", input_url);
    printf("Host: %s\n", parsed.host);
    if (redirect_trace(input_url, &final_url, error, sizeof(error))) {
        printf("Final URL (HEAD redirect trace): %s\n", final_url);
    } else {
        fprintf(stderr, "HEAD redirect trace unavailable: %s\n", error);
        printf("Continuing with URL-only checks.\n");
    }

    report = security_check_report(&parsed, final_url, LANGUAGE_ENGLISH);
    if (report == NULL) {
        fprintf(stderr, "Unable to generate the security report.\n");
        exit_status = EXIT_FAILURE;
        goto cleanup;
    }
    printf("\n%s", report);

cleanup:
    free(report);
    free(final_url);
    url_parsed_cleanup(&parsed);
    curl_global_cleanup();
#ifdef _WIN32
    WSACleanup();
#endif
    return exit_status;
}
