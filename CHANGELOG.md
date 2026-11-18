# Changelog

## 1.1.2+6 — 2026-11-18

- Support local Android Release signing through the git-ignored `android/key.properties` file as well as CI environment variables.
- Validate the GitHub Actions JKS file, password, alias, private-key entry, and certificate chain before running the Release build.
- Validate that the manually supplied Worker API base URL uses HTTPS.

## 1.1.2+5 — 2026-11-18

- Require an exact same-origin `Origin` header for abuse-report form submissions to prevent cross-site report forgery.
- Add regression tests for missing and cross-origin report submissions.

## 1.1.2+4 — 2026-11-17

- Embed the AES-256-GCM IV and ciphertext in the share URL path; the server key is never included.
- Validate the embedded payload against D1 before decryption, while preserving old ID-only share links.
- Update the app-side share URL validation and explain that the original destination opens normally after confirmation.

## 1.1.1+3 — 2026-11-17

- Added a destination warning page and same-origin POST confirmation before web-share redirects.
- Added abuse-report submission with bounded payloads and a separate rate limiter.
- Rejected Unicode format/control characters in Dart and the Worker.
- Added versioned server master keys and a D1 migration for key IDs/report storage.
- Disabled Android backup/device-transfer restoration for app data.
- Added device-local app authentication on startup and resume where supported.
- Removed debug-key signing from Release builds; a private keystore is now required.
- Stored up to 100 share management tokens securely instead of only the latest share.
- Corrected cryptography descriptions and clarified recovery-code handling.
- Added GitHub Actions CI for worker tests, Flutter checks, and debug APK build.
