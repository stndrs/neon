# Changelog

## Unreleased

### Breaking

- Added `CertificateRequired` variant to `TlsAlert` type (may break exhaustive
  pattern matches).

### Added

- `connect_cert` function for mTLS client-certificate authentication during
  SSL/TLS connections.
- Server-side client-certificate verification via `handshake_cacerts`. The
  handshake now sets `verify_peer` with `fail_if_no_peer_cert` when CA
  certificates are provided.

### Changed

- Updated `gleam_stdlib` to v1.0.0

## v2.0.0

### Breaking

- Added `InvalidPid` error variant to TCP, UDP, and SSL modules (may break exhaustive pattern matches on error types).

### Added

- `controlling_process` function for TCP and SSL modules, allowing socket ownership transfer between processes.
- `controlling_process` function for the UDP module.
- Support for connecting to an IP address with SSL (not just hostnames).
- `InvalidPid` error variant for TCP, UDP, and SSL modules.
- Comprehensive test coverage for TCP, UDP, SSL, and net modules.

### Changed

- Differentiated invalid PID errors from closed socket errors.
- Handle invalid socket errors in `accept`.
- Updated dependencies.

### Fixed

- SSL `verify_peer` now works correctly with IP addresses.
- Fixed test assertions across modules.
