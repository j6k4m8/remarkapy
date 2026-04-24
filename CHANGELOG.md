# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0 - 2026-04-24

### Changed

- `Client.list_items()` now returns lightweight `IndexedItem` summaries instead of fully hydrated entries.
- `Client.list_directory()` now returns lightweight directory children by default.

### Added

- `Client.list_hydrated_items()` for explicit full-library hydration.
- `Client.list_directory_hydrated()` for explicit hydrated directory listings.

### Notes

- This is a breaking API release intended to make cheap lookup and listing workflows match the default method behavior.
