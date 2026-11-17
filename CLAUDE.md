# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

APCM (AltasCI multi-Platform Certificate Manager) — a Qt 6 / C++20 native Windows certificate-management and enrollment GUI. It enumerates Windows certificate stores and CNG/KSP keys, generates PKCS#10 requests via CertEnroll (including TPM-backed keys), installs certificates and P12/PFX, and persists encrypted application metadata via SQLCipher. It does not perform CA signing or persist CA signing keys; explicit independent-signing Owner import can upload a user-selected CA key to its server. UI, README, and docs are written in Chinese; code identifiers are English.

## Build & test

All builds require the MSVC x64 Developer environment; the wrapper scripts locate it via `vswhere`. Dependency paths default to `D:\Qt\6.8.3\msvc2022_64` and `D:\Tools\vcpkg`, overridable via `QT_ROOT` / `VCPKG_ROOT`. The vcpkg registry baseline is pinned in `vcpkg-configuration.json`.

```powershell
.\scripts\build.ps1        # configure + build debug, windeployqt, qmllint, run ctest
.\scripts\package.ps1      # release build + qmllint + tests + WiX MSI -> build\package\APCM-<ver>-x64.msi
.\build\debug\CertificateManager.exe   # run the app (debug; build.ps1 already ran windeployqt)
```

Underlying presets (useful for individual steps inside a dev prompt):
```powershell
cmake --preset windows-msvc-debug        # or windows-msvc-release
cmake --build --preset windows-msvc-debug
ctest --preset windows-msvc-debug
```

Test targets are `certmgr_tests` (`certmgr_core_tests`), `certmgr_signing_tests`, and `certmgr_signing_vault_tests`. Run a single QtTest slot by name (slots in `tests/TestCore.cpp`):
```powershell
.\build\debug\certmgr_tests.exe deviceTemplateEnforcesTpmInvariant
```

Tests that touch real OS state are opt-in via environment variables and otherwise `QSKIP`:
- `CERTMGR_TEST_ENROLLMENT=1` — real CNG PKCS#10 + response association.
- `CERTMGR_TEST_TPM=1` — force the TPM provider in the enrollment test.
- `CERTMGR_TEST_P12` / `CERTMGR_TEST_P12_PASSWORD` — external P12 fixture inspection.

Release process: bump the three-part `project(... VERSION)` in `CMakeLists.txt`, push to `main`; the GitHub workflow (`.github/workflows/release.yml`) builds and publishes a `vX.Y.Z` tag + MSI only if that tag does not yet exist.

## Architecture

Full detail lives in `docs/ARCHITECTURE.md` and `docs/SECURITY.md` — read those for the security invariants. The big picture:

**CMake targets** (`CMakeLists.txt`):
- `certmgr_core` — static library: domain, services, persistence, and all `src/platform/windows/*` backends. Links Qt6::Core/Network, tl::expected, libsodium, sqlcipher, OpenSSL Crypto, and Windows system libs (Crypt32/Ncrypt/Bcrypt/Ole32/OleAut32/Shell32).
- `CertificateManager` — the GUI (`WIN32`), links `certmgr_core` + Qt6::Gui/Quick/QuickControls2.
- `CertificateManager.Helper` (target `CertificateManagerHelper`) — the elevated helper, `WIN32`, links only `certmgr_core` + Qt6::Core.
- `certmgr_tests` — `tests/TestCore.cpp`, links `certmgr_core` + Qt6::Test.

**Layering** — top to bottom: QML (`src/ui`, module URI `CertManager`) → `AppController` (single `QObject` facade, exposed to QML as context property `"App"`) → platform interfaces → Windows backends. Namespaces mirror the layers: `certmgr::domain`, `certmgr::services`, `certmgr::persistence`, `certmgr::platform` (interfaces) and `certmgr::platform::windows` (impls), `certmgr::app`.

**Platform boundary is enforced by convention, not build config**: `src/domain` and `src/services` must not include Windows headers. Windows handles, COM interfaces, and native error codes are confined to `src/platform/windows`. Future Linux/macOS support = implement the interfaces in `src/platform/interfaces/*.h` (`IVault`, `IAuditLog`, `ICertificateStore`, `IKeyProvider`, `IEnrollmentBackend`) in a new `src/platform/<os>/` directory; do not leak platform paths into domain.

**Error handling** — nearly every fallible function returns `tl::expected<T, certmgr::domain::AppError>`. `AppError` (`src/domain/AppError.h`) carries `category`, string `code`, `nativeCode`, `message`, `details`. Convert Win32 failures with `platform::windows::winError(...)`; the elevated helper's `main` returns the native `DWORD` as its process exit code.

**RAII** — `src/platform/windows/common/WinRaii.h` provides handle wrappers (`CertStoreHandle`, `CertContextPtr`, `NCryptKeyHandle`, `ComPtr`, `BStr`, `LocalAllocPtr`) and is the source of `<Windows.h>` / `<wincrypt.h>` / `<ncrypt.h>` / `<wrl/client.h>`. Prefer these over raw handles. `SecureBuffer` (`src/persistence/SecureBuffer.h`) is a move-only, sodium-`sodium_memzero`-cleared buffer for keys/secrets.

**Key identity** — a certificate's internal `id` is `scope | role | SHA256(DER)`; CN is display-only. See the store-mapping table in `docs/ARCHITECTURE.md`.

**Vault envelope** — master password → Argon2id KEK; a random DB key wrapped with XChaCha20-Poly1305 in `vault.meta`; SQLCipher opens `vault.db` with that key. Schema version 3 (auto-migrates from v1/v2), including independent signing profiles and durable operation records. Private keys are never stored; only provider/container references, CSR text, and hashes. `certificate_references` records only fingerprint + scope + role (management ownership, not authority).

**Elevation** — the GUI runs non-elevated. Machine-scoped CSR creation, response install, cert/P12/PFX import shell out to `CertificateManager.Helper.exe` via `runas` UAC (`ElevatedHelperLauncher`). The helper accepts only allowlisted commands, re-parses files, and verifies the SHA-256 fingerprint shown pre-elevation; machine CSR config/results cross via auto-deleted JSON temp files, and machine P12 passwords cross only as DPAPI-wrapped temp files (never on the command line).

**Single instance** — kernel mutex + `QLocalServer` IPC (`SingleInstanceGuard`); a secondary launch signals the primary to restore/raise its window.

## Conventions

- C++20, `/W4 /permissive- /utf-8 /EHsc`, `NOMINMAX` and `WIN32_LEAN_AND_MEAN` defined per-target. Source files are UTF-8 (Chinese string literals are common).
- QML types exposed to QML are declared as `Q_PROPERTY`/`Q_INVOKABLE` on `AppController`; data crossing to QML is `QVariantList`/`QVariantMap`. `Theme.qml` is a QML singleton (`QT_QML_SINGLETON_TYPE`).

**Independent signing** — `App.signing` exposes `IndependentSigningController`; protocol and TLS helpers are in `src/domain/signing` and `src/services/SigningHttpClient.*`. Keep HTTP mTLS identity, HTTPS server roots and business certificate roots separate. See `docs/INDEPENDENT_SIGNING.md`.
