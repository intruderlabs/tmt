# tmt

	▄▖▖  ▖▄▖      ▄▖        ▗   ▖  ▖    ▄▖        ▗ 
	▐ ▛▖▞▌▐   ▄▖  ▐ ▀▌▛▘▛▌█▌▜▘  ▛▖▞▌▌▌  ▐ ▀▌▛▘▛▌█▌▜▘
	▐ ▌▝ ▌▐       ▐ █▌▌ ▙▌▙▖▐▖  ▌▝ ▌▙▌  ▐ █▌▌ ▙▌▙▖▐▖
                    	▄▌          ▄▌        ▄▌    

**TMT (Target my Target)** routes your security-testing traffic through AWS so it
egresses from AWS IP space instead of your own infrastructure. It offers two
backends: a **per-target API Gateway reverse proxy**, and a **rotating,
multi-region Lambda jump-host** that spreads outbound requests across regions.

Everything ships as a single self-contained Go binary.

> ⚠️ **Authorized use only.** tmt is built for authorized security-testing
> engagements (pentests, red teams, bug-bounty within scope). You are
> responsible for having explicit permission to test the target and to create
> resources in the AWS account you use. Don't use it against systems you don't
> own or aren't authorized to assess.

## Why tmt

- **Two egress backends.** A simple per-target API Gateway proxy, or a
  target-agnostic Lambda jump-host that rotates requests across many regions.
- **Hard to block by IP.** Traffic egresses through AWS's dynamic, shared IP
  pool, so the source IP varies between requests — a target blocking a single
  `/32` won't reliably stop it. (Not foolproof: blocking by AWS IP range/ASN
  from `ip-ranges.json`, or by datacenter reputation, is still possible.)
- **Pick your region.** Route traffic through a specific geographic region
  without standing up VPN infrastructure.
- **Named resources + safe teardown.** Name what you create, tear it down by
  name, and list everything tmt is tracking — no more orphaned AWS resources.
- **Credentials never touch disk.** AWS keys are never written to the local
  ledger.

## Requirements

- **Go 1.25+** to build.
- **AWS credentials** with permission to create the resources:
  - API Gateway backend → `apigateway:*`
  - Lambda jump-host backend → `lambda:*` plus `iam:CreateRole` / `iam:PassRole`

## Build

```
make build
```

`make build` runs `make lambda` first: it cross-compiles the jump-host function
(Linux/arm64), zips it as `bootstrap` into `internal/jump/lambdafn.zip`, and that
zip is embedded into the `tmt` binary via `//go:embed`.

> Bare `go build` / `go install` will **fail** without the embedded zip. Always
> build with `make`.

## Usage — API Gateway backend (per-target)

Stands up an API Gateway REST API that proxies all traffic to one target URL.

```
tmt up   -ak ACCESS_KEY -sk SECRET_KEY -t https://api.example.com [-st SESSION_TOKEN] [-r REGION]
tmt down -ak ACCESS_KEY -sk SECRET_KEY -t https://api.example.com [-st SESSION_TOKEN] [-r REGION] [-y]
```

| Flag  | Meaning |
|-------|---------|
| `-ak` | AWS access key ID (required) |
| `-sk` | AWS secret access key (required) |
| `-st` | AWS session token, for temporary/STS credentials (optional) |
| `-t`  | Target URL to proxy to (required) |
| `-r`  | AWS region (default: `sa-east-1`) |
| `-y`  | Skip the confirmation prompt (`down` only) |

Example:

```
tmt up   -ak AKIA... -sk wJalr... -t https://api.example.com -r us-east-1
tmt down -ak AKIA... -sk wJalr... -t https://api.example.com -r us-east-1
```

`up` prints the public invoke URL (`https://<id>.execute-api.<region>.amazonaws.com/prod`).
Send your requests there and they reach the target from AWS.

## Usage — Lambda jump-host backend (rotating multi-region egress)

Deploys one jump-host Lambda per region and runs a **local MITM proxy** that
rotates each outbound request to a different region. Point any tool at it with
its native proxy flag.

```
tmt up -jump -regions sa-east-1,us-east-1,eu-west-1 -ak ACCESS_KEY -sk SECRET_KEY [-st TOKEN] [-port 8008]
```

`up -jump` **stays in the foreground**. In another shell, aim your tool at the
local proxy — each request egresses from a different region:

```
nuclei -u https://target.example.com -proxy http://127.0.0.1:8008
```

`Ctrl-C` tears the whole pool down. If `up -jump` was killed abruptly, sweep any
orphans:

```
tmt down -jump -regions sa-east-1,us-east-1,eu-west-1 -ak AKIA... -sk wJalr...
```

| Flag       | Meaning |
|------------|---------|
| `-jump`    | Use the Lambda jump-host backend |
| `-regions` | Comma-separated AWS regions to deploy to (required) |
| `-port`    | Local MITM proxy port (default: `8008`) |

## Managing resources (`-n`, `down -n`, `--list`)

Normally you'd have to remember the exact `up` command to tear a resource down.
Instead, tmt keeps a local **ledger** of everything it creates at
`~/.tmt/state.json` (override the directory with `TMT_HOME`).

Name a resource on `up`, then destroy it later with just the name plus
credentials — no need to recall the target or regions:

```
tmt up   -jump -regions sa-east-1,us-east-1 -n scan -ak AKIA... -sk wJalr...
tmt down -n scan -ak AKIA... -sk wJalr...
```

`-n` works with both backends. If omitted, a name is auto-generated.

List everything tmt is tracking, with the command used to create each:

```
tmt --list
```

`--list` reads only the local ledger — it never calls AWS.

> **Credentials are never persisted.** The `-ak` / `-sk` / `-st` flags are
> stripped before the command is recorded, and the ledger file is written
> `0600`.

## Caveats

- **Jump-host TLS is MITM'd locally.** The local proxy terminates TLS with its
  own in-memory CA so it can relay each request as a `lambda.Invoke`. Your tool
  therefore no longer verifies the target's real certificate. Scanners like
  nuclei typically skip target-cert verification, so no CA setup is needed;
  tools that do verify can trust the CA the proxy exposes.
- **~6 MB response cap (jump-host).** A Lambda synchronous invoke returns at most
  ~6 MB, so the jump host caps response bodies at 4 MB and errors above that.
  Fine for scanning; large downloads won't fit.
- **IP blocking isn't defeated entirely.** Egress IPs are AWS's — a target can
  still block by AWS IP range / ASN or by cloud/datacenter reputation.

## License

Copyright (C) 2026 alacerda (IntruderLabs). Licensed under the GNU General
Public License v3.0 — see [LICENSE](LICENSE).
