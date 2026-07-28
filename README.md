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

## Build

```
make build
```

## Usage

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

## Author / License

Copyright (C) 2026 alacerda (IntruderLabs). Licensed under the GNU General
Public License v3.0 — see [LICENSE](LICENSE).
