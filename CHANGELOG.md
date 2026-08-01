# Changelog

## 0.3.0 - 2026-08-01

-   Support for Python 3.11, 3.12, 3.13, and 3.14 in CI

## 0.2.2 - 2026-05-27

### Fixed

-   Sent `rm-filename` on blob reads with the stored filename so `GET /sync/v3/files/{hash}` works against the current cloud validation.
-   Accepted `201 Created` as a successful response for browser-style uploads on `POST /doc/v2/files`.

## 0.2.1 - 2026-04-24

### Fixed

-   Accepted `202 Accepted` as a successful response for immutable blob uploads on `PUT /sync/v3/files/{hash}`.
-   Fixed `Client.put_pdf()` and `Client.put_folder()` on live backends that acknowledge blob writes with HTTP 202.

## 0.2.0 - 2026-04-24

### Changed

-   `Client.list_items()` now returns lightweight `IndexedItem` summaries instead of fully hydrated entries.
-   `Client.list_directory()` now returns lightweight directory children by default.

### Added

-   `Client.list_hydrated_items()` for explicit full-library hydration.
-   `Client.list_directory_hydrated()` for explicit hydrated directory listings.

### Notes

-   This is a breaking API release intended to make cheap lookup and listing workflows match the default method behavior.
