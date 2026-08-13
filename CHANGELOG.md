# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- **Lambda jump-host backend (`-jump`).** Target-agnostic, multi-region egress
  that deploys one Lambda per region and runs a local MITM proxy rotating
  outbound calls across them, so a scanning tool's requests egress from
  different regions. Point tools at it with their native proxy flag
  (`-proxy http://127.0.0.1:8008`).
- `tmt down -jump -regions ...` to sweep orphaned jump-host Lambdas/roles.
- `make lambda` / `make clean` targets: `lambda` cross-compiles the jump-host
  function (Linux/arm64) and zips it as `bootstrap` into
  `internal/jump/lambdafn.zip`, which is embedded into the binary via
  `//go:embed`. `make build` and `make test` now depend on it.

### Notes

- The local jump-host proxy terminates TLS with an in-memory CA; scanning tools
  no longer verify the target's real certificate.
- Lambda synchronous invokes cap response bodies at ~4 MB.
