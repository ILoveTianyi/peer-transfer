# Compile and run the Android-free core tests with plain javac/java.
# No Gradle, no third-party dependencies, no network, no device.
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'src'
$out = Join-Path $PSScriptRoot 'build\classes'

if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Force -Path $out | Out-Null

$javaHome = 'D:\AndroidS\jbr'
$javac = if (Test-Path (Join-Path $javaHome 'bin\javac.exe')) { Join-Path $javaHome 'bin\javac.exe' } else { 'javac' }
$java = if (Test-Path (Join-Path $javaHome 'bin\java.exe')) { Join-Path $javaHome 'bin\java.exe' } else { 'java' }

$sourceFiles = @(Get-ChildItem -Recurse -File -Filter *.java (Join-Path $src 'main') |
        ForEach-Object { $_.FullName }) + @(Get-ChildItem -Recurse -File -Filter *.java (Join-Path $src 'test') |
        ForEach-Object { $_.FullName })
if ($sourceFiles.Count -eq 0) { throw 'no java sources found' }

$javacArgs = @('-encoding', 'UTF-8', '-Xlint:all', '-Werror', '-d', $out) + $sourceFiles
& $javac $javacArgs
if ($LASTEXITCODE -ne 0) { throw "javac failed with exit code $LASTEXITCODE" }

& $java '-cp' $out 'dev.peertransfer.CoreTests'
if ($LASTEXITCODE -ne 0) { throw "core tests failed with exit code $LASTEXITCODE" }
