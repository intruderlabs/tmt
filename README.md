# tmt

	▄▖▖  ▖▄▖      ▄▖        ▗   ▖  ▖    ▄▖        ▗ 
	▐ ▛▖▞▌▐   ▄▖  ▐ ▀▌▛▘▛▌█▌▜▘  ▛▖▞▌▌▌  ▐ ▀▌▛▘▛▌█▌▜▘
	▐ ▌▝ ▌▐       ▐ █▌▌ ▙▌▙▖▐▖  ▌▝ ▌▙▌  ▐ █▌▌ ▙▌▙▖▐▖
                    	▄▌          ▄▌        ▄▌    
	AWS API Gateway reverse proxy for security testing

TMT (Target my Target) stands up an AWS API Gateway REST API that proxies all traffic to a target URL, so requests appear to originate from AWS instead of your own
infrastructure. Built for authorized security testing engagements.

## Advantages

- **Hard to block by IP.** The proxy uses a public `HTTP_PROXY` integration with no VPC Link/NAT/EIP, so outbound requests to the target egress through AWS's dynamic, shared IP pool for the region. The source IP varies between requests, so a target blocking a single IP (`/32`) won't reliably block the traffic. Note this isn't foolproof: blocking by AWS IP range/ASN (published in `ip-ranges.json`) or by cloud/datacenter reputation is still possible.
- **Cheap per-region "VPN".** The `-r` flag picks the AWS region traffic egresses from, so tmt doubles as a low-cost way to route requests through a specific geographic region without standing up VPN infrastructure.

TMT has two backends. The **API Gateway** proxy (default) fronts a single target
URL. The **Lambda jump-host** (`-jump`) is a target-agnostic, multi-region egress:
it deploys one Lambda per region and runs a local proxy that rotates outbound
calls across them, so a scanning tool's requests egress from different regions.

## Build

```
make build
```

`make build` first runs `make lambda`, which compiles the jump-host function
(Linux/arm64) and zips it as `bootstrap` into `internal/jump/lambdafn.zip`; that
zip is embedded into the `tmt` binary via `//go:embed`. Bare `go build` without
the zip present will fail — use `make`.

## Usage — API Gateway proxy (per-target)

```
tmt up   -ak ACCESS_KEY -sk SECRET_KEY -t https://api.example.com [-st SESSION_TOKEN] [-r REGION]
tmt down -ak ACCESS_KEY -sk SECRET_KEY -t https://api.example.com [-st SESSION_TOKEN] [-r REGION] [-y]
```

Options:

- `-ak` AWS access key ID (required)
- `-sk` AWS secret access key (required)
- `-st` AWS session token, for temporary/STS credentials (optional)
- `-t` target URL to proxy to (required)
- `-r` AWS region (default: `sa-east-1`)
- `-y` skip the confirmation prompt (`down` only)

Example:

```
tmt up   -ak AKIA... -sk wJalr... -t https://api.example.com -r us-east-1
tmt down -ak AKIA... -sk wJalr... -t https://api.example.com -r us-east-1
```

## Usage — Lambda jump-host (rotating multi-region egress)

```
tmt up   -jump -regions sa-east-1,us-east-1,eu-west-1 -ak ACCESS_KEY -sk SECRET_KEY [-st TOKEN] [-port 8008]
```

`up -jump` deploys one jump-host Lambda per region, starts a local MITM proxy,
and **stays in the foreground**. Point your tool at it via its native proxy
flag; each request rotates to a different region:

```
nuclei -u https://target.example.com -proxy http://127.0.0.1:8008
```

`Ctrl-C` tears the whole pool down. If `up -jump` was killed abruptly, sweep any
orphans with:

```
tmt down -jump -regions sa-east-1,us-east-1,eu-west-1 -ak AKIA... -sk wJalr...
```

Extra options: `-regions` (comma-separated, required), `-port` (local proxy port,
default `8008`).

Requires `lambda:*` plus `iam:CreateRole`/`PassRole` in the AWS account.

### Caveats

- **TLS is MITM'd locally.** The local proxy terminates TLS with its own
  in-memory CA so it can read each request and turn it into a `lambda.Invoke`.
  This means the scanning tool no longer verifies the target's real certificate.
  nuclei typically skips target-cert verification, so no CA trust setup is
  needed; tools that do verify can trust the CA the proxy prints/exposes.
- **6 MB response cap.** A Lambda synchronous invoke returns at most ~6 MB, so
  the jump host caps response bodies at 4 MB and returns an error above that.
  Fine for scanning; large downloads won't fit.

## Naming, teardown by name, and `--list`

Both backends normally require you to remember the exact `up` command to tear
down (the target/region for API Gateway, the region list for jump). To avoid
orphaned AWS resources, tmt keeps a local **ledger** of everything it creates at
`~/.tmt/state.json` (override the directory with `TMT_HOME`).

- Name a resource on `up` with `-n NAME` (if omitted, a name is auto-generated).
- Tear it down later with just the name plus credentials — no need to recall the
  original flags:

```
tmt up   -jump -regions sa-east-1,us-east-1 -n scan -ak AKIA... -sk wJalr...
tmt down -n scan -ak AKIA... -sk wJalr...
```

- List everything tmt is tracking, with the (credential-stripped) command used
  to create each:

```
tmt --list
```

`--list` reads only the local ledger — it does not call AWS. **Credentials are
never written to disk:** the `-ak`/`-sk`/`-st` flags are stripped before the
command is recorded, and the ledger file is created `0600`.

## Author / License

Copyright (C) 2026 alacerda (IntruderLabs). Licensed under the GNU General
Public License v3.0 — see [LICENSE](LICENSE).
