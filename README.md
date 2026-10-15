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

Install CMake 3.28+, a C11 compiler (Visual Studio or MinGW-w64), and vcpkg at
`C:\vcpkg` with the `curl:x64-windows-static` package installed. From
PowerShell in the project directory, run:

```powershell
.\build-release.ps1
```

The script builds the Release GUI executable in a temporary project-root build
directory, copies `TraceLinkAnalyzer.exe` directly into the project root, then
removes the `build\`, `bin\`, and `obj\` directories even if configuration or
compilation fails. CMake is configured automatically with the vcpkg toolchain
and `x64-windows-static` triplet. Once the build succeeds, double-click
`TraceLinkAnalyzer.exe` in the root folder to start the application. The static
triplet and static C runtime allow the application to be distributed as a
single executable.

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
