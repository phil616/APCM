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

16. Independent signing persists the exact public CSR JSON bytes, original endpoint, credential digest and Idempotency-Key before sending; retries never generate a replacement identity.
17. Holder Bearer tokens live in Windows Credential Manager; Owner passwords, cookies/CSRF and transport identity passwords are never persisted. Locking clears in-memory network identities and sensitive dialogs.
18. Holder and Owner have independent network sessions, client TLS identities and server roots. Holder requests do not use cookies; Owner requests never carry the signing Bearer token.
19. HTTPS hostname/chain verification is mandatory; redirects are blocked. A downloaded issuer certificate is never promoted to a trust anchor.
20. Installing a signing result requires matching CSR public key, Subject and SAN, expected EKUs, fingerprint, decimal serial, valid dates, trusted business chain and non-revoked status; CNG public-key matching is repeated at installation.
21. Certificate revocation needs explicit UI confirmation; the original reason is persisted before sending and cannot change while the result is unresolved.
22. Export uses atomic replacement and rejects aliases/hard links to the vault, configured TLS identity/root files and imported CSR files.
23. Owner CA import explicitly confirms that the CA private key is uploaded and stored by the server; it is not the leaf-key or transport-mTLS flow.

## Explicit non-goals

- This application does not perform CA signing or persist CA signing keys. Explicit Owner CA import reads a user-selected key transiently for upload to the configured server.
- Client templates are usability policy, not an authorization boundary.
- Local SQLCipher audit data is not advertised as tamper-proof against local administrators.
- V1 does not silently delete orphaned keys. Key deletion requires a separate future danger-zone workflow.

## Operational notes

Machine-level operations may fail when UAC is denied or enterprise policy blocks store changes. TPM CSR generation may display provider UI or fail if the TPM is unavailable, unprovisioned, locked, or restricted by policy. These failures must remain visible to the user and must not fall back to an exportable software key.
