# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.1] — 2026-10-01

### Added

- `ClientConfig.ServerUID *uint32`: a uid a unix-socket server may run as,
  trusted besides the client's own and root's. Forbidden for TCP.

### Fixed

- `Dial` over a unix socket now checks the server's peer uid (kernel peer
  credentials) and refuses a server running as any uid other than the
  client's, root's or `ServerUID`: an impostor that bound the socket first
  in a directory others can write no longer receives the CLI's commands.
  Not checked where the platform has no peer credentials (Windows, the
  BSDs other than FreeBSD).

## [v0.1.0] — 2026-09-29

### Added

- `Config`, `Config.Check` and `Listen`: the listener for a daemon's gRPC
  admin API — a unix socket left at mode 0600 and never exposed while
  binding, or TCP with mandatory mutual TLS (loopback included).
- A stale socket file is replaced only when connecting to it is refused; a
  live one, an unprobeable one, and anything that is not a socket are left
  alone.
- `Caller`: `uid=<uid>` for a unix peer (from the kernel: `SO_PEERCRED` on
  Linux, `LOCAL_PEERCRED` on darwin and FreeBSD), `cn=<subject CN>` for an
  mTLS one, `unix` where the platform has no uid, `unknown` otherwise.
- `ClientConfig` and `Dial`, for CLIs and tests.
- CI on Linux (amd64, arm64), darwin and Windows, with the race detector and
  a 100% statement-coverage gate on Linux and darwin.
