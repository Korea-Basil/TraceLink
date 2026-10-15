cmake_minimum_required(VERSION 3.28)
project(url_threat_analyzer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(WIN32)
    enable_language(RC)
    # Prefer static libcurl so the Windows GUI can be shipped as one executable.
    set(CURL_USE_STATIC_LIBS ON)
endif()
find_package(CURL 7.62 REQUIRED)

set(ANALYZER_CORE_SOURCES
    src/url_parser.c
    src/security_check.c
    src/redirect_tracer.c
    src/i18n.c
)

if(WIN32)
    add_executable(url_analyzer WIN32
        src/win32_app.c
        resources/app.rc
        ${ANALYZER_CORE_SOURCES}
    )
    target_compile_definitions(url_analyzer PRIVATE UNICODE _UNICODE CURL_STATICLIB)
    target_link_libraries(url_analyzer PRIVATE
        CURL::libcurl
        comctl32
        user32
        gdi32
        ws2_32
        crypt32
        secur32
        bcrypt
        advapi32
        wldap32
        normaliz
    )

    if(MINGW)
        target_link_options(url_analyzer PRIVATE -static -municode)
    endif()
    if(MSVC)
        target_compile_options(url_analyzer PRIVATE /utf-8 /W4)
        set_property(TARGET url_analyzer PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        
        # 매니페스트 중복 병합 오류 방지 설정
        set_target_properties(url_analyzer PROPERTIES
            LINK_FLAGS "/MANIFEST:NO"
        )
    endif()
    set_target_properties(url_analyzer PROPERTIES
        OUTPUT_NAME "TraceLinkAnalyzer"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/output/$<CONFIG>"
    )
else()
    add_executable(url_analyzer
        src/main.c
        ${ANALYZER_CORE_SOURCES}
    )
    target_link_libraries(url_analyzer PRIVATE CURL::libcurl)
endif()

target_include_directories(url_analyzer PRIVATE include resources)