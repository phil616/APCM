[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$FixtureDirectory
)
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
$revision = '53b528d1e7d7f3cb6824eb4bb2d315dec63589c1'
$upstream = Join-Path ([System.IO.Path]::GetTempPath()) ('apcm-pki-interop-' + [guid]::NewGuid().ToString('N'))
$previousFixtures = $env:APCM_CSR_FIXTURE_DIR
try {
    foreach ($algorithm in @('ECDSA-P256', 'ECDSA-P384', 'RSA-2048', 'RSA-3072', 'RSA-4096')) {
        foreach ($suffix in @('.csr', '.request.json')) {
            if (-not (Test-Path -LiteralPath (Join-Path $FixtureDirectory ($algorithm + $suffix)))) {
                throw "Missing native Windows fixture: $algorithm$suffix"
            }
        }
    }
    git init $upstream
    if ($LASTEXITCODE -ne 0) { throw 'Could not create upstream verification checkout.' }
    git -C $upstream remote add origin https://github.com/phil616/altasci-public-pki.git
    if ($LASTEXITCODE -ne 0) { throw 'Could not configure upstream verification remote.' }
    git -C $upstream fetch --depth 1 origin $revision
    if ($LASTEXITCODE -ne 0) { throw 'Could not fetch the reviewed upstream revision.' }
    git -C $upstream checkout --detach FETCH_HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Could not check out upstream verification source.' }
    $actual = git -C $upstream rev-parse HEAD
    if ($LASTEXITCODE -ne 0 -or $actual.Trim() -ne $revision) { throw 'Upstream verification revision mismatch.' }
    Copy-Item -LiteralPath (Join-Path $repository 'tests/interop/apcm_signing_test.go') -Destination (Join-Path $upstream 'console/signing/apcm_compat_test.go')
    Copy-Item -LiteralPath (Join-Path $repository 'tests/interop/apcm_http_test.go') -Destination (Join-Path $upstream 'console/httpapi/apcm_compat_test.go')
    $env:APCM_CSR_FIXTURE_DIR = (Resolve-Path -LiteralPath $FixtureDirectory).Path
    Push-Location $upstream
    try {
        go test ./console/signing ./console/httpapi -run '^TestAPCMNative' -count=1 -v -timeout 3m
        if ($LASTEXITCODE -ne 0) { throw 'Native Windows CSR failed the real upstream parser, HTTP decoder, or issuer.' }
    } finally { Pop-Location }
} finally {
    $env:APCM_CSR_FIXTURE_DIR = $previousFixtures
    if (Test-Path -LiteralPath $upstream) { Remove-Item -LiteralPath $upstream -Recurse -Force }
}
