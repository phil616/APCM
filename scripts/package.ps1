[CmdletBinding()]
param(
    [string]$Version
)

$ErrorActionPreference = 'Stop'

$repository = Split-Path -Parent $PSScriptRoot
$cmakeProject = Get-Content -LiteralPath (Join-Path $repository 'CMakeLists.txt') -Raw
if ($cmakeProject -notmatch '(?ms)^project\(\s*CertificateManager\s+VERSION\s+([0-9]+\.[0-9]+\.[0-9]+)\b') {
    throw 'Could not read the CertificateManager project version from CMakeLists.txt.'
}
$projectVersion = $Matches[1]
if (-not $Version) {
    $Version = $projectVersion
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "The MSI version must use the numeric major.minor.patch format: $Version"
}
if ($Version -ne $projectVersion) {
    throw "The requested MSI version ($Version) does not match CMakeLists.txt ($projectVersion)."
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw 'Visual Studio Installer (vswhere.exe) was not found.'
}

$visualStudio = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $visualStudio) {
    throw 'A Visual Studio installation with the MSVC x64 toolchain is required.'
}
$developerPrompt = Join-Path $visualStudio 'Common7\Tools\VsDevCmd.bat'

if (-not $env:QT_ROOT) {
    $env:QT_ROOT = 'D:\Qt\6.8.3\msvc2022_64'
}
if (-not (Test-Path -LiteralPath (Join-Path $env:QT_ROOT 'lib\cmake\Qt6\Qt6Config.cmake'))) {
    throw "Qt 6 was not found at QT_ROOT=$env:QT_ROOT"
}

if (-not $env:VCPKG_ROOT) {
    $env:VCPKG_ROOT = 'D:\Tools\vcpkg'
}
if (-not (Test-Path -LiteralPath (Join-Path $env:VCPKG_ROOT 'scripts\buildsystems\vcpkg.cmake'))) {
    throw "vcpkg was not found at VCPKG_ROOT=$env:VCPKG_ROOT"
}

$buildDirectory = Join-Path $repository 'build\release'
$packageDirectory = Join-Path $repository 'build\package'
$stageDirectory = Join-Path $packageDirectory 'stage'
$resolvedBuildRoot = [System.IO.Path]::GetFullPath((Join-Path $repository 'build'))
$resolvedStage = [System.IO.Path]::GetFullPath($stageDirectory)
if (-not $resolvedStage.StartsWith($resolvedBuildRoot + [System.IO.Path]::DirectorySeparatorChar,
                                  [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean a staging directory outside the build tree: $resolvedStage"
}
if (Test-Path -LiteralPath $resolvedStage) {
    Remove-Item -LiteralPath $resolvedStage -Recurse -Force
}
New-Item -ItemType Directory -Path $resolvedStage -Force | Out-Null
New-Item -ItemType Directory -Path $packageDirectory -Force | Out-Null

$nativeBuild = 'call "{0}" -arch=x64 -host_arch=x64 && cd /d "{1}" && cmake --preset windows-msvc-release && cmake --build --preset windows-msvc-release && cmake --build build/release --target all_qmllint && copy /Y "{2}\vcpkg_installed\x64-windows\bin\libssl-3-x64.dll" "{2}" >nul && ctest --preset windows-msvc-release && cmake --install "{2}" --prefix "{3}" --config Release' -f $developerPrompt, $repository, $buildDirectory, $resolvedStage
& cmd.exe /d /s /c $nativeBuild
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$applicationDirectory = Join-Path $resolvedStage 'bin'
$mainExecutable = Join-Path $applicationDirectory 'CertificateManager.exe'
$helperExecutable = Join-Path $applicationDirectory 'CertificateManager.Helper.exe'
if (-not (Test-Path -LiteralPath $mainExecutable) -or -not (Test-Path -LiteralPath $helperExecutable)) {
    throw 'The staged package is missing the main executable or elevation helper.'
}

# A single MSI cannot chain Qt's vc_redist executable. Use Microsoft's supported
# application-local layout, but discover the current toolset instead of assuming VC143.
$redistRoot = Join-Path $visualStudio 'VC\Redist\MSVC'
$runtimeDirectory = Get-ChildItem -LiteralPath $redistRoot -Directory |
    Where-Object { $_.Name -match '^\d+(?:\.\d+)+$' } |
    Sort-Object { [version]$_.Name } -Descending |
    ForEach-Object {
        $architectureDirectory = Join-Path $_.FullName 'x64'
        if (Test-Path -LiteralPath $architectureDirectory) {
            Get-ChildItem -LiteralPath $architectureDirectory -Directory |
                Where-Object { $_.Name -match '^Microsoft\.VC\d+\.CRT$' } |
                Sort-Object Name -Descending
        }
    } |
    Select-Object -First 1
if (-not $runtimeDirectory) {
    throw "An x64 Microsoft.VC*.CRT redistribution directory was not found below $redistRoot"
}
$runtimeFiles = Get-ChildItem -LiteralPath $runtimeDirectory.FullName -Filter '*.dll' -File
if (-not $runtimeFiles) {
    throw "MSVC runtime DLLs were not found below $($runtimeDirectory.FullName)"
}
Copy-Item -LiteralPath $runtimeFiles.FullName -Destination $applicationDirectory -Force

$vcpkgRuntimeDirectory = Join-Path $buildDirectory 'vcpkg_installed\x64-windows\bin'
foreach ($runtimeName in @('libsodium.dll', 'sqlcipher.dll', 'libcrypto-3-x64.dll', 'libssl-3-x64.dll')) {
    $runtimePath = Join-Path $vcpkgRuntimeDirectory $runtimeName
    if (-not (Test-Path -LiteralPath $runtimePath)) {
        throw "Required runtime dependency is missing: $runtimePath"
    }
    Copy-Item -LiteralPath $runtimePath -Destination $applicationDirectory -Force
}

Push-Location $repository
try {
    dotnet tool restore
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet tool run wix -- extension add WixToolset.UI.wixext/5.0.2
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $msiPath = Join-Path $packageDirectory ("APCM-{0}-x64.msi" -f $Version)
    $wixPdbPath = [System.IO.Path]::ChangeExtension($msiPath, '.wixpdb')
    if (Test-Path -LiteralPath $wixPdbPath) {
        Remove-Item -LiteralPath $wixPdbPath -Force
    }
    dotnet tool run wix -- build 'installer\Product.wxs' -arch x64 `
        -ext WixToolset.UI.wixext `
        -culture zh-CN `
        -ct 2 `
        -d "SourceDir=$resolvedStage" `
        -d "ProductVersion=$Version" `
        -d "IconPath=$(Join-Path $repository 'resources\apcm.ico')" `
        -d "LicensePath=$(Join-Path $repository 'installer\License.rtf')" `
        -pdbtype none `
        -o $msiPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    dotnet tool run wix -- msi validate $msiPath
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Output $msiPath
}
finally {
    Pop-Location
}
