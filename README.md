# TraceLink URL Analyzer

TraceLink is a small C URL checker. On Windows it opens a native desktop
application with English/Korean language switching. On other platforms CMake
builds the original console interface.

## Project layout

```text
include/
  i18n.h
  redirect_tracer.h
  security_check.h
  url_parser.h
resources/
  app.manifest
  app.rc
src/
  i18n.c
  main.c
  redirect_tracer.c
  security_check.c
  url_parser.c
  win32_app.c
CMakeLists.txt
```

## Windows GUI build

Install CMake 3.28+, a C11 compiler (Visual Studio or MinGW-w64), and the **static**
libcurl 7.62+ development package. Make sure CMake can find that package and
its static dependencies. Then, from the project directory:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

With Visual Studio, the application is produced at
`build\Release\TraceLinkAnalyzer.exe`. With a single-configuration MinGW
generator, it is at `build\TraceLinkAnalyzer.exe`. The Windows target is a GUI
subsystem application and CMake prefers static libcurl; MinGW links statically
to its runtime as well. A static libcurl build and its TLS dependencies are
required for a single-file executable. If the selected libcurl package is
shared-only, the executable will need its DLL dependencies alongside it.

For example, to select the MinGW generator:

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build --config Release
```

## Non-Windows console build

Install a C11 compiler, CMake, and libcurl development files, then run:

```sh
cmake -S . -B build
cmake --build build
```

## Modules

- `win32_app.c` builds the Windows UI using native Win32 controls and runs
  network scans on a worker thread so the window stays responsive.
- `i18n.c` stores the English and Korean UI/report strings. The language button
  switches language at runtime, including an already displayed report.
- `url_parser.c` parses HTTP(S) URLs and provides shared host, IP, and path
  helpers.
- `redirect_tracer.c` follows at most ten redirects using `HEAD` requests,
  with connection and total timeouts, and restricts schemes to HTTP(S).
- `security_check.c` reports URL indicators, including shorteners, IP hosts,
  suspicious subdomains/typos, redirect query parameters, Discord redirects,
  image-like URLs, and executable destinations.
- `main.c` retains the console entry point used on non-Windows builds.

The checks are heuristic, not a definitive safety verdict. A HEAD request still
contacts the entered URL and its redirect destinations; only analyze URLs you
are comfortable contacting. No page body is downloaded.
