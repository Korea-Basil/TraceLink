$ErrorActionPreference = "Stop"

$projectRoot = $PSScriptRoot
$outputExecutable = Join-Path $projectRoot "TraceLinkAnalyzer.exe"
$vcpkgToolchain = "C:/vcpkg/scripts/buildsystems/vcpkg.cmake"
$buildDirectory = Join-Path $projectRoot "build"
$scratchDirectory = Join-Path $buildDirectory ("TraceLink-build-" + [guid]::NewGuid())

if ($env:OS -ne "Windows_NT") {
    throw "This script builds the Windows GUI executable and must run on Windows."
}

try {
    if (-not (Test-Path -LiteralPath $vcpkgToolchain -PathType Leaf)) {
        throw "The vcpkg toolchain was not found at $vcpkgToolchain. Install vcpkg at C:\vcpkg."
    }

    $configureArguments = @(
        "-S", $projectRoot,
        "-B", $scratchDirectory,
        "-DCMAKE_BUILD_TYPE=Release",
        "-DCURL_USE_STATIC_LIBS=ON",
        "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain",
        "-DVCPKG_TARGET_TRIPLET=x64-windows-static"
    )
    & cmake @configureArguments
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configuration failed with exit code $LASTEXITCODE."
    }

    & cmake --build $scratchDirectory --config Release --target url_analyzer
    if ($LASTEXITCODE -ne 0) {
        throw "The Release build failed with exit code $LASTEXITCODE."
    }

    $builtOutputDirectory = Join-Path $scratchDirectory "output\Release"
    $builtExecutable = Join-Path $builtOutputDirectory "TraceLinkAnalyzer.exe"
    if (-not (Test-Path -LiteralPath $builtExecutable -PathType Leaf)) {
        throw "Build completed without producing the expected executable: $builtExecutable"
    }

    $buildOutput = @(Get-ChildItem -LiteralPath $builtOutputDirectory -Force)
    if ($buildOutput.Count -ne 1 -or $buildOutput[0].FullName -ne $builtExecutable) {
        throw "The build produced runtime dependencies or other files beside the executable; verify that libcurl and its dependencies are static."
    }

    Copy-Item -LiteralPath $builtExecutable -Destination $outputExecutable -Force

    if (-not (Test-Path -LiteralPath $outputExecutable -PathType Leaf)) {
        throw "The executable was not copied to the project root: $outputExecutable"
    }
}
finally {
    $cleanupErrors = @()
    foreach ($directoryName in @("build", "bin", "obj")) {
        $directoryPath = Join-Path $projectRoot $directoryName
        if (Test-Path -LiteralPath $directoryPath -PathType Container) {
            $removed = $false
            for ($attempt = 1; $attempt -le 3 -and -not $removed; $attempt++) {
                try {
                    Remove-Item -LiteralPath $directoryPath -Recurse -Force -ErrorAction Stop
                    $removed = $true
                }
                catch {
                    if ($attempt -eq 3) {
                        $cleanupErrors += $_
                    }
                    else {
                        Start-Sleep -Milliseconds 500
                    }
                }
            }
        }
    }
    if ($cleanupErrors.Count -gt 0) {
        throw "Failed to remove generated directories: $($cleanupErrors.Exception.Message -join '; ')"
    }
}
