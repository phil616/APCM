$ErrorActionPreference = 'Stop'

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found.'
}

$visualStudio = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $visualStudio) {
    throw 'A Visual Studio installation with the MSVC x64 toolchain is required.'
}

$developerPrompt = Join-Path $visualStudio 'Common7\Tools\VsDevCmd.bat'
$repository = Split-Path -Parent $PSScriptRoot

if (-not $env:QT_ROOT) {
    $env:QT_ROOT = 'D:\Qt\6.8.3\msvc2022_64'
}
if (-not (Test-Path -LiteralPath (Join-Path $env:QT_ROOT 'lib\cmake\Qt6\Qt6Config.cmake'))) {
    throw "Qt 6 was not found at QT_ROOT=$env:QT_ROOT"
}
$deployTool = Join-Path $env:QT_ROOT 'bin\windeployqt.exe'

if (-not $env:VCPKG_ROOT) {
    $env:VCPKG_ROOT = 'D:\Tools\vcpkg'
}
if (-not (Test-Path -LiteralPath (Join-Path $env:VCPKG_ROOT 'scripts\buildsystems\vcpkg.cmake'))) {
    throw "vcpkg was not found at VCPKG_ROOT=$env:VCPKG_ROOT"
}

$command = 'call "{0}" -arch=x64 -host_arch=x64 && cd /d "{1}" && cmake --preset windows-msvc-debug && cmake --build --preset windows-msvc-debug && "{2}" --debug --no-translations --qmldir "{1}\src\ui" "{1}\build\debug\CertificateManager.exe" && cmake --build build/debug --target all_qmllint && ctest --preset windows-msvc-debug' -f $developerPrompt, $repository, $deployTool

& cmd.exe /d /s /c $command
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
