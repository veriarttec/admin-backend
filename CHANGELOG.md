# Changelog

All notable changes to the VeriART admin backend (FastAPI).

## [Unreleased]

### Security
- `get_signed_url` no longer falls back to public URLs when signing fails —
  failures now return 404 instead of exposing documents.

### Added
- `GET /api/admin/documents/signed-url` accepts a `url` param (stored storage
  URL) in addition to `bucket`/`path`, so legacy stored URLs resolve server-side.

## [Gate 1] - 2026-06-12

### Security
- CORS now enforces the `ALLOWED_ORIGINS` allowlist (was `["*"]`).
- Admin login rate-limited (10/minute, slowapi).

### Added
- Duplicate-phone check on admin donor creation.
