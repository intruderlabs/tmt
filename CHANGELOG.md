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
- **Named resources and teardown by name.** `up ... -n NAME` records what was
  created; `down -n NAME -ak ... -sk ...` destroys it without needing to
  remember the original target/regions. Applies to both backends.
- **`tmt --list`** shows every resource tmt is tracking (name, backend, regions,
  resources, and the command used to create it) from a local ledger.

### Changed

- New startup banner: an ANSI-Shadow "TMT" with a magenta→indigo 256-color
  gradient, replacing the previous low-legibility half-block art. Color is
  TTY-aware and honors `NO_COLOR`.
- Local ledger at `~/.tmt/state.json` (override the directory with `TMT_HOME`),
  written `0600`. Every `up` records an entry; every `down` removes it.

### Security

- AWS credentials are never persisted: the `-ak`/`-sk`/`-st` flags (and their
  values) are stripped from the command recorded in the ledger.

### Documentation

- Rewrote the README for open-source use: updated tagline for both backends,
  added an authorized-use notice, requirements (Go 1.25+, per-backend IAM
  permissions), a build note that `make` is required (embedded zip), and
  documented `-n` / `down -n` / `tmt --list` and the local ledger.

### Notes

- The local jump-host proxy terminates TLS with an in-memory CA; scanning tools
  no longer verify the target's real certificate.
- Lambda synchronous invokes cap response bodies at ~4 MB.
- `tmt --list` reads only the local ledger; it does not call AWS.
