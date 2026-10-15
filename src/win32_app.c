#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include "i18n.h"
#include "redirect_tracer.h"
#include "security_check.h"
#include "url_parser.h"

#include <winsock2.h>
#include <windows.h>
#include <commctrl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#define APP_CLASS_NAME L"TraceLinkUrlAnalyzerWindow"
#define URL_BUFFER_SIZE 8192
#define TIMER_SCAN 1

enum {
    CONTROL_TITLE = 100,
    CONTROL_TAGLINE,
    CONTROL_URL_LABEL,
    CONTROL_URL,
    CONTROL_SCAN,
    CONTROL_LANGUAGE,
    CONTROL_RESULTS_LABEL,
    CONTROL_RESULTS,
    CONTROL_STATUS
};

typedef struct {
    char url[URL_BUFFER_SIZE];
    char *final_url;
    char error[256];
    int success;
} ScanTask;

static HWND app_window;
static HWND title_control;
static HWND tagline_control;
static HWND url_label_control;
static HWND url_control;
static HWND scan_control;
static HWND language_control;
static HWND results_label_control;
static HWND results_control;
static HWND status_control;
static HFONT normal_font;
static HFONT title_font;
static HBRUSH background_brush;
static HBRUSH edit_brush;
static Language current_language = LANGUAGE_ENGLISH;
static HANDLE scan_thread;
static ScanTask *scan_task;
static char *last_input_url;
static char *last_final_url;
static char last_scan_error[256];
static int last_scan_succeeded;
static int scan_in_progress;

static void finish_scan(void);

static wchar_t *utf8_to_wide(const char *text)
{
    int length;
    wchar_t *wide;

    if (text == NULL)
        return NULL;
    length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1, NULL, 0);
    if (length == 0)
        return NULL;
    wide = malloc((size_t)length * sizeof(*wide));
    if (wide == NULL)
        return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text, -1,
                            wide, length) == 0) {
        free(wide);
        return NULL;
    }
    return wide;
}

static char *wide_to_utf8(const wchar_t *text)
{
    int length;
    char *utf8;

    length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1,
                                 NULL, 0, NULL, NULL);
    if (length == 0)
        return NULL;
    utf8 = malloc((size_t)length);
    if (utf8 == NULL)
        return NULL;
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1,
                            utf8, length, NULL, NULL) == 0) {
        free(utf8);
        return NULL;
    }
    return utf8;
}

static void set_localized_text(HWND control, TextId id)
{
    wchar_t *text = utf8_to_wide(i18n_get(current_language, id));
    if (text != NULL) {
        SetWindowTextW(control, text);
        free(text);
    }
}

static DWORD WINAPI scan_worker(LPVOID parameter)
{
    ScanTask *task = parameter;
    task->success = redirect_trace(task->url, &task->final_url,
                                   task->error, sizeof(task->error));
    return 0;
}

static void append_results(void)
{
    ParsedUrl parsed = {0};
    char parse_error[256];
    char *report;
    char *combined;
    size_t needed;
    size_t report_length;
    size_t line_break_count = 0;
    size_t i;
    int header_length = 0;
    wchar_t *wide_results;
    TextId message_id = last_scan_succeeded ? TEXT_FINAL_URL_LABEL :
                                               TEXT_SCAN_ERROR_LABEL;

    if (last_input_url == NULL) {
        set_localized_text(results_control, TEXT_EMPTY_RESULTS);
        return;
    }
    if (scan_in_progress) {
        set_localized_text(results_control, TEXT_RESULTS_SCANNING);
        return;
    }

    if (!url_parse(last_input_url, &parsed, parse_error, sizeof(parse_error))) {
        set_localized_text(results_control, TEXT_INVALID_URL);
        return;
    }

    report = security_check_report(&parsed, last_final_url, current_language);
    url_parsed_cleanup(&parsed);
    if (report == NULL) {
        set_localized_text(results_control, TEXT_REPORT_ERROR);
        return;
    }

    if (last_scan_succeeded && last_final_url != NULL) {
        const char *format = i18n_get(current_language, message_id);
        header_length = snprintf(NULL, 0, "%s: %s\r\n\r\n",
                                 format, last_final_url);
    } else if (last_scan_error[0] != '\0') {
        const char *format = i18n_get(current_language, message_id);
        header_length = snprintf(NULL, 0, "%s: %s\r\n\r\n",
                                 format, last_scan_error);
    }
    if (header_length < 0) {
        free(report);
        set_localized_text(results_control, TEXT_REPORT_ERROR);
        return;
    }
    report_length = strlen(report);
    for (i = 0; i < report_length; i++) {
        if (report[i] == '\n' && (i == 0 || report[i - 1] != '\r'))
            line_break_count++;
    }
    if (line_break_count == (size_t)-1 ||
        (size_t)header_length > (size_t)-1 - line_break_count - 1 ||
        report_length > (size_t)-1 - (size_t)header_length -
                        line_break_count - 1) {
        free(report);
        set_localized_text(results_control, TEXT_REPORT_ERROR);
        return;
    }
    needed = (size_t)header_length + report_length + line_break_count + 1;
    combined = malloc(needed);
    if (combined == NULL) {
        free(report);
        set_localized_text(results_control, TEXT_REPORT_ERROR);
        return;
    }

    if (last_scan_succeeded && last_final_url != NULL) {
        snprintf(combined, needed, "%s: %s\r\n\r\n",
                 i18n_get(current_language, message_id), last_final_url);
    } else if (last_scan_error[0] != '\0') {
        snprintf(combined, needed, "%s: %s\r\n\r\n",
                 i18n_get(current_language, message_id), last_scan_error);
    } else {
        combined[0] = '\0';
    }
    {
        char *destination = combined + header_length;
        for (i = 0; i < report_length; i++) {
            if (report[i] == '\n' && (i == 0 || report[i - 1] != '\r'))
                *destination++ = '\r';
            *destination++ = report[i];
        }
        *destination = '\0';
    }
    free(report);

    wide_results = utf8_to_wide(combined);
    if (wide_results != NULL) {
        SetWindowTextW(results_control, wide_results);
        free(wide_results);
    } else {
        set_localized_text(results_control, TEXT_REPORT_ERROR);
    }
    free(combined);
}

static void apply_language(void)
{
    wchar_t *placeholder;

    set_localized_text(app_window, TEXT_APP_TITLE);
    set_localized_text(title_control, TEXT_APP_TITLE);
    set_localized_text(tagline_control, TEXT_TAGLINE);
    set_localized_text(url_label_control, TEXT_URL_LABEL);
    set_localized_text(scan_control, TEXT_SCAN_BUTTON);
    set_localized_text(language_control, TEXT_LANGUAGE_BUTTON);
    set_localized_text(results_label_control, TEXT_RESULTS_LABEL);
    if (last_input_url == NULL)
        set_localized_text(status_control, TEXT_STATUS_READY);
    else if (scan_in_progress)
        set_localized_text(status_control, TEXT_STATUS_SCANNING);
    else
        set_localized_text(status_control, last_scan_succeeded ?
                           TEXT_STATUS_COMPLETE : TEXT_STATUS_SCAN_FAILED);

    placeholder = utf8_to_wide(i18n_get(current_language, TEXT_URL_PLACEHOLDER));
    if (placeholder != NULL) {
        SendMessageW(url_control, EM_SETCUEBANNER, TRUE, (LPARAM)placeholder);
        free(placeholder);
    }
    append_results();
}

static void layout_controls(HWND window)
{
    RECT client;
    int width;
    int height;
    int margin = 28;
    int button_width = 132;
    int language_width = 116;
    int content_width;
    int bottom;

    GetClientRect(window, &client);
    width = client.right - client.left;
    height = client.bottom - client.top;
    content_width = width - margin * 2;
    bottom = height - 28;

    MoveWindow(title_control, margin, 24, content_width - language_width - 12, 36, TRUE);
    MoveWindow(language_control, width - margin - language_width, 22,
               language_width, 34, TRUE);
    MoveWindow(tagline_control, margin, 63, content_width, 26, TRUE);
    MoveWindow(url_label_control, margin, 111, content_width, 22, TRUE);
    MoveWindow(url_control, margin, 138, content_width - button_width - 12, 36, TRUE);
    MoveWindow(scan_control, width - margin - button_width, 138,
               button_width, 36, TRUE);
    MoveWindow(results_label_control, margin, 194, content_width, 24, TRUE);
    MoveWindow(results_control, margin, 222, content_width,
               height - 222 - 70, TRUE);
    MoveWindow(status_control, margin, bottom - 24, content_width, 22, TRUE);
}

static void begin_scan(void)
{
    int length = GetWindowTextLengthW(url_control);
    wchar_t *wide_input;
    char *utf8_input;
    ParsedUrl parsed = {0};
    char parse_error[256];

    if (length <= 0) {
        wchar_t *message = utf8_to_wide(i18n_get(current_language, TEXT_URL_REQUIRED));
        wchar_t *title = utf8_to_wide(i18n_get(current_language, TEXT_APP_TITLE));
        if (message != NULL) {
            MessageBoxW(app_window, message,
                        title == NULL ? L"TraceLink" : title,
                        MB_OK | MB_ICONINFORMATION);
        }
        free(message);
        free(title);
        SetFocus(url_control);
        return;
    }
    if (length >= URL_BUFFER_SIZE) {
        set_localized_text(status_control, TEXT_INVALID_URL);
        return;
    }

    wide_input = malloc(((size_t)length + 1) * sizeof(*wide_input));
    if (wide_input == NULL) {
        set_localized_text(status_control, TEXT_REPORT_ERROR);
        return;
    }
    GetWindowTextW(url_control, wide_input, length + 1);
    utf8_input = wide_to_utf8(wide_input);
    free(wide_input);
    if (utf8_input == NULL) {
        set_localized_text(status_control, TEXT_INVALID_URL);
        return;
    }
    if (!url_parse(utf8_input, &parsed, parse_error, sizeof(parse_error))) {
        set_localized_text(status_control, TEXT_INVALID_URL);
        url_parsed_cleanup(&parsed);
        free(utf8_input);
        return;
    }
    url_parsed_cleanup(&parsed);

    if (strlen(utf8_input) >= URL_BUFFER_SIZE) {
        set_localized_text(status_control, TEXT_INVALID_URL);
        free(utf8_input);
        return;
    }
    scan_task = calloc(1, sizeof(*scan_task));
    if (scan_task == NULL) {
        set_localized_text(status_control, TEXT_REPORT_ERROR);
        free(utf8_input);
        return;
    }
    strcpy(scan_task->url, utf8_input);
    free(last_input_url);
    last_input_url = utf8_input;
    free(last_final_url);
    last_final_url = NULL;
    last_scan_error[0] = '\0';
    last_scan_succeeded = 0;
    scan_in_progress = 1;
    set_localized_text(status_control, TEXT_STATUS_SCANNING);
    set_localized_text(results_control, TEXT_RESULTS_SCANNING);
    EnableWindow(scan_control, FALSE);

    scan_thread = CreateThread(NULL, 0, scan_worker, scan_task, 0, NULL);
    if (scan_thread == NULL) {
        snprintf(last_scan_error, sizeof(last_scan_error),
                 "Unable to start the scan worker.");
        free(scan_task);
        scan_task = NULL;
        scan_in_progress = 0;
        EnableWindow(scan_control, TRUE);
        set_localized_text(status_control, TEXT_STATUS_SCAN_FAILED);
        append_results();
        return;
    }
    if (SetTimer(app_window, TIMER_SCAN, 100, NULL) == 0) {
        WaitForSingleObject(scan_thread, INFINITE);
        finish_scan();
    }
}

static void finish_scan(void)
{
    if (scan_thread == NULL ||
        WaitForSingleObject(scan_thread, 0) != WAIT_OBJECT_0)
        return;

    KillTimer(app_window, TIMER_SCAN);
    CloseHandle(scan_thread);
    scan_thread = NULL;
    scan_in_progress = 0;

    last_scan_succeeded = scan_task->success;
    if (scan_task->success) {
        last_final_url = scan_task->final_url;
        scan_task->final_url = NULL;
        last_scan_error[0] = '\0';
    } else {
        strncpy(last_scan_error, scan_task->error, sizeof(last_scan_error) - 1);
        last_scan_error[sizeof(last_scan_error) - 1] = '\0';
    }
    free(scan_task->final_url);
    free(scan_task);
    scan_task = NULL;

    EnableWindow(scan_control, TRUE);
    set_localized_text(status_control, last_scan_succeeded ?
                       TEXT_STATUS_COMPLETE : TEXT_STATUS_SCAN_FAILED);
    append_results();
}

static HWND create_control(DWORD ex_style, const wchar_t *class_name,
                           const wchar_t *text, DWORD style, int control_id,
                           HWND parent, HINSTANCE instance)
{
    HWND control = CreateWindowExW(
        ex_style, class_name, text, style,
        0, 0, 0, 0, parent, (HMENU)(INT_PTR)control_id, instance, NULL);
    if (control != NULL && normal_font != NULL)
        SendMessageW(control, WM_SETFONT, (WPARAM)normal_font, TRUE);
    return control;
}

static int create_controls(HWND window, HINSTANCE instance)
{
    title_control = create_control(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                  CONTROL_TITLE, window, instance);
    tagline_control = create_control(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                     CONTROL_TAGLINE, window, instance);
    url_label_control = create_control(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                       CONTROL_URL_LABEL, window, instance);
    url_control = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                 CONTROL_URL, window, instance);
    scan_control = create_control(0, L"BUTTON", L"",
                                  WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                  CONTROL_SCAN, window, instance);
    language_control = create_control(0, L"BUTTON", L"",
                                      WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                      CONTROL_LANGUAGE, window, instance);
    results_label_control = create_control(0, L"STATIC", L"",
                                           WS_CHILD | WS_VISIBLE,
                                           CONTROL_RESULTS_LABEL, window, instance);
    results_control = create_control(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                     WS_CHILD | WS_VISIBLE | WS_TABSTOP |
                                     ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY |
                                     WS_VSCROLL, CONTROL_RESULTS, window, instance);
    status_control = create_control(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE,
                                    CONTROL_STATUS, window, instance);

    return title_control != NULL && tagline_control != NULL &&
           url_label_control != NULL && url_control != NULL &&
           scan_control != NULL && language_control != NULL &&
           results_label_control != NULL && results_control != NULL &&
           status_control != NULL;
}

static LRESULT CALLBACK window_procedure(HWND window, UINT message,
                                         WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_CREATE: {
        CREATESTRUCTW *creation = (CREATESTRUCTW *)lparam;
        HINSTANCE instance = creation->hInstance;
        normal_font = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                  CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  DEFAULT_PITCH | FF_DONTCARE, L"Malgun Gothic");
        title_font = CreateFontW(-25, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                 CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                 DEFAULT_PITCH | FF_DONTCARE, L"Malgun Gothic");
        if (normal_font == NULL || title_font == NULL ||
            !create_controls(window, instance))
            return -1;
        SendMessageW(title_control, WM_SETFONT, (WPARAM)title_font, TRUE);
        SendMessageW(results_control, EM_SETLIMITTEXT, 200000, 0);
        apply_language();
        layout_controls(window);
        return 0;
    }
    case WM_NCCREATE:
        app_window = window;
        return DefWindowProcW(window, message, wparam, lparam);
    case WM_SIZE:
        layout_controls(window);
        return 0;
    case WM_GETMINMAXINFO: {
        MINMAXINFO *info = (MINMAXINFO *)lparam;
        info->ptMinTrackSize.x = 620;
        info->ptMinTrackSize.y = 500;
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wparam) == CONTROL_SCAN && HIWORD(wparam) == BN_CLICKED) {
            begin_scan();
            return 0;
        }
        if (LOWORD(wparam) == CONTROL_LANGUAGE && HIWORD(wparam) == BN_CLICKED) {
            current_language = current_language == LANGUAGE_ENGLISH ?
                               LANGUAGE_KOREAN : LANGUAGE_ENGLISH;
            apply_language();
            return 0;
        }
        break;
    case WM_TIMER:
        if (wparam == TIMER_SCAN) {
            finish_scan();
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wparam;
        SetTextColor(dc, RGB(31, 41, 55));
        SetBkMode(dc, TRANSPARENT);
        return (LRESULT)background_brush;
    }
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wparam;
        SetTextColor(dc, RGB(31, 41, 55));
        SetBkColor(dc, RGB(255, 255, 255));
        return (LRESULT)edit_brush;
    }
    case WM_ERASEBKGND: {
        RECT client;
        GetClientRect(window, &client);
        FillRect((HDC)wparam, &client, background_brush);
        return 1;
    }
    case WM_CLOSE:
        if (scan_thread != NULL) {
            KillTimer(window, TIMER_SCAN);
            WaitForSingleObject(scan_thread, INFINITE);
            CloseHandle(scan_thread);
            scan_thread = NULL;
        }
        if (scan_task != NULL) {
            free(scan_task->final_url);
            free(scan_task);
            scan_task = NULL;
        }
        DestroyWindow(window);
        return 0;
    case WM_DESTROY:
        free(last_input_url);
        free(last_final_url);
        if (normal_font != NULL)
            DeleteObject(normal_font);
        if (title_font != NULL)
            DeleteObject(title_font);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wparam, lparam);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous_instance,
                    PWSTR command_line, int show_command)
{
    INITCOMMONCONTROLSEX common_controls;
    WNDCLASSEXW window_class;
    MSG message;
    int result;
#ifdef _WIN32
    WSADATA winsock_data;
#endif

    (void)previous_instance;
    (void)command_line;

#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
        MessageBoxW(NULL, L"Unable to initialize network support.",
                    L"TraceLink", MB_OK | MB_ICONERROR);
        return EXIT_FAILURE;
    }
#endif
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        MessageBoxW(NULL, L"Unable to initialize libcurl.",
                    L"TraceLink", MB_OK | MB_ICONERROR);
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

    common_controls.dwSize = sizeof(common_controls);
    common_controls.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&common_controls);

    background_brush = CreateSolidBrush(RGB(244, 246, 250));
    edit_brush = CreateSolidBrush(RGB(255, 255, 255));
    if (background_brush == NULL || edit_brush == NULL) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

    ZeroMemory(&window_class, sizeof(window_class));
    window_class.cbSize = sizeof(window_class);
    window_class.style = CS_HREDRAW | CS_VREDRAW;
    window_class.lpfnWndProc = window_procedure;
    window_class.hInstance = instance;
    window_class.hCursor = LoadCursorW(NULL, IDC_ARROW);
    window_class.hbrBackground = background_brush;
    window_class.lpszClassName = APP_CLASS_NAME;
    if (RegisterClassExW(&window_class) == 0) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

    app_window = CreateWindowExW(
        0, APP_CLASS_NAME, L"TraceLink URL Analyzer",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 820, 680,
        NULL, NULL, instance, NULL);
    if (app_window == NULL) {
        result = EXIT_FAILURE;
        goto cleanup;
    }

    ShowWindow(app_window, show_command);
    UpdateWindow(app_window);
    while ((result = (int)GetMessageW(&message, NULL, 0, 0)) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    result = result == -1 ? EXIT_FAILURE : (int)message.wParam;

cleanup:
    curl_global_cleanup();
#ifdef _WIN32
    WSACleanup();
#endif
    if (background_brush != NULL)
        DeleteObject(background_brush);
    if (edit_brush != NULL)
        DeleteObject(edit_brush);
    return result;
}
