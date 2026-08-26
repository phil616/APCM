# Security model

## Invariants enforced by code

1. SQLCipher schema does not contain private-key material.
2. Hardware-required templates reject exportable keys.
3. Certificate inventory is rebuilt from Windows stores on every refresh.
4. Key inventory is rebuilt from CNG providers on every refresh.
5. Certificate deletion calls only `CertDeleteCertificateFromStore`; it never calls `NCryptDeleteKey`.
6. Trusted-root installation rejects certificates without `BasicConstraints CA=true`.
7. Machine-root installation requires an explicit UI confirmation and UAC.
8. Elevated helper commands are allowlisted and cannot execute a shell command.
9. The helper binds elevated installation to the SHA-256 fingerprint shown before elevation.
10. Audit entries contain hashes/references, never passwords or API tokens.
11. Persisted CSR text is public request material; SQLCipher stores it for workflow continuity but never stores the corresponding private key.
12. APCM managed-root records are fingerprint references and cannot silently change Windows trust.
13. Every certificate installed through APCM is registered by SHA-256 fingerprint in the encrypted management list.
14. P12/PFX passwords are never persisted or audited; machine-import passwords cross elevation only as temporary DPAPI-protected data.
15. Root-store installation always requires explicit confirmation and rejects any non-CA certificate in the package.
16. Cloudflare OAuth tokens are stored only in Windows Credential Manager; PKI passwords, TOTP values, cookies, and CSRF tokens are never persisted or audited.
17. OAuth uses discovered HTTPS endpoints, a one-shot 127.0.0.1 loopback callback, fresh PKCE S256/state values, and the system browser; API redirects are not followed automatically.
18. Private-PKI submission uploads only the public PKCS#10 CSR. Downloaded certificates must pass the existing CNG public-key comparison before installation.

## Explicit non-goals

- This application is not a CA and never holds a CA signing key.
- Client templates are usability policy, not an authorization boundary.
- Local SQLCipher audit data is not advertised as tamper-proof against local administrators.
- V1 does not silently delete orphaned keys. Key deletion requires a separate future danger-zone workflow.

## Operational notes

Machine-level operations may fail when UAC is denied or enterprise policy blocks store changes. TPM CSR generation may display provider UI or fail if the TPM is unavailable, unprovisioned, locked, or restricted by policy. These failures must remain visible to the user and must not fall back to an exportable software key.
