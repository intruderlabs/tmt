// TMT (Target My Target) — stands up an AWS API Gateway reverse proxy in
// front of a target URL, for use in authorized security testing engagements.
//
// Copyright (C) 2026 alacerda (IntruderLabs)
// Licensed under the GNU General Public License v3.0. See LICENSE.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"

	"github.com/intruderlabs/tmt/internal/gateway"
	"github.com/intruderlabs/tmt/internal/output"
)

const defaultRegion = "sa-east-1"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "up":
		runUp(os.Args[2:])
	case "down":
		runDown(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		output.Error("unknown command %q", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `
	▄▖▖  ▖▄▖      ▄▖        ▗   ▖  ▖    ▄▖        ▗ 
	▐ ▛▖▞▌▐   ▄▖  ▐ ▀▌▛▘▛▌█▌▜▘  ▛▖▞▌▌▌  ▐ ▀▌▛▘▛▌█▌▜▘
	▐ ▌▝ ▌▐       ▐ █▌▌ ▙▌▙▖▐▖  ▌▝ ▌▙▌  ▐ █▌▌ ▙▌▙▖▐▖
                    	▄▌          ▄▌        ▄▌    
	AWS API Gateway reverse proxy for security testing

Usage:
  tmt up   -ak ACCESS_KEY -sk SECRET_KEY -t TARGET_URL [-st SESSION_TOKEN] [-r REGION]
  tmt down -ak ACCESS_KEY -sk SECRET_KEY -t TARGET_URL [-st SESSION_TOKEN] [-r REGION] [-y]

Commands:
  up      Create the API Gateway proxy for the target
  down    Remove the API Gateway proxy for the target

Options:
  -ak     AWS access key ID (required)
  -sk     AWS secret access key (required)
  -st     AWS session token, for temporary/STS credentials (optional)
  -t      Target URL to proxy to, e.g. https://api.example.com (required)
  -r      AWS region (default: %s)
  -y      Skip the confirmation prompt (down only)

Common regions:
  sa-east-1        Sao Paulo
  us-east-1        N. Virginia
  us-east-2        Ohio
  us-west-1        N. California
  us-west-2        Oregon
  eu-west-1        Ireland
  eu-central-1     Frankfurt
  ap-southeast-1   Singapore

Examples:
  tmt up   -ak AKIA... -sk wJalr... -t https://api.example.com -r us-east-1
  tmt down -ak AKIA... -sk wJalr... -t https://api.example.com -r us-east-1
`, defaultRegion)
}

// credentialFlags holds the flags common to both subcommands.
type credentialFlags struct {
	accessKey    *string
	secretKey    *string
	sessionToken *string
	target       *string
	region       *string
}

func bindCredentialFlags(fs *flag.FlagSet) *credentialFlags {
	return &credentialFlags{
		accessKey:    fs.String("ak", "", "AWS access key ID (required)"),
		secretKey:    fs.String("sk", "", "AWS secret access key (required)"),
		sessionToken: fs.String("st", "", "AWS session token (optional)"),
		target:       fs.String("t", "", "target URL to proxy to (required)"),
		region:       fs.String("r", defaultRegion, "AWS region"),
	}
}

// validate checks required fields and the target URL, and returns the
// target with any trailing slash trimmed.
func (c *credentialFlags) validate() (target string, err error) {
	var missing []string
	if *c.accessKey == "" {
		missing = append(missing, "-ak")
	}
	if *c.secretKey == "" {
		missing = append(missing, "-sk")
	}
	if *c.target == "" {
		missing = append(missing, "-t")
	}
	if len(missing) > 0 {
		return "", fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}

	target = strings.TrimSuffix(*c.target, "/")
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid target URL %q (expected e.g. https://api.example.com)", *c.target)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid target URL scheme %q (expected http or https)", u.Scheme)
	}
	return target, nil
}

func (c *credentialFlags) newManager(ctx context.Context, target string) (*gateway.Manager, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(*c.region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(*c.accessKey, *c.secretKey, *c.sessionToken)),
	)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	client := apigateway.NewFromConfig(cfg)
	return gateway.NewManager(client, *c.region, target), nil
}

func runUp(args []string) {
	fs := flag.NewFlagSet("up", flag.ExitOnError)
	creds := bindCredentialFlags(fs)
	fs.Parse(args)

	target, err := creds.validate()
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}

	ctx := context.Background()
	mgr, err := creds.newManager(ctx, target)
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}

	output.Step("Region: %s", *creds.region)
	output.Step("Checking for an existing proxy for: %s", target)

	res, err := mgr.Up(ctx)
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}

	endpoint := gateway.Endpoint(res.APIID, *creds.region)
	if res.Existing {
		output.Warn("Proxy already exists")
	} else {
		output.Step("Creating API Gateway: %s (region: %s)", res.Name, *creds.region)
		output.Step("Configuring ANY method on root (/)")
		output.Step("Creating catch-all proxy resource (/{proxy+})")
		output.Step("Deploying stage: prod")
		output.Success("Proxy created")
	}
	output.UpSummary(res.Name, res.APIID, *creds.region, target, endpoint)
}

func runDown(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	creds := bindCredentialFlags(fs)
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	fs.Parse(args)

	target, err := creds.validate()
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}

	if !*yes && !output.Confirm(fmt.Sprintf("Are you sure you want to remove the proxy for %s?", target)) {
		output.Warn("Aborted")
		os.Exit(0)
	}

	ctx := context.Background()
	mgr, err := creds.newManager(ctx, target)
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}

	output.Step("Region: %s", *creds.region)
	output.Step("Looking for a proxy for: %s", target)

	res, err := mgr.Down(ctx)
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}

	if !res.Found {
		output.Warn("No proxy found for %s in %s. Nothing to do.", target, *creds.region)
		os.Exit(0)
	}

	output.Success("Proxy removed")
	output.DownSummary(res.Name, res.APIID, *creds.region, target)
}
