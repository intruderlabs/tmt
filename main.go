// TMT (Target My Target) — stands up an AWS API Gateway reverse proxy in
// front of a target URL, for use in authorized security testing engagements.
//
// Copyright (C) 2026 alacerda (IntruderLabs)
// Licensed under the GNU General Public License v3.0. See LICENSE.
package main

import (
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/intruderlabs/tmt/internal/gateway"
	"github.com/intruderlabs/tmt/internal/jump"
	"github.com/intruderlabs/tmt/internal/output"
	"github.com/intruderlabs/tmt/internal/proxy"
	"github.com/intruderlabs/tmt/internal/state"
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
	case "list", "--list", "-list":
		runList()
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
  # API Gateway reverse proxy (per-target)
  tmt up   -ak ACCESS_KEY -sk SECRET_KEY -t TARGET_URL [-st SESSION_TOKEN] [-r REGION]
  tmt down -ak ACCESS_KEY -sk SECRET_KEY -t TARGET_URL [-st SESSION_TOKEN] [-r REGION] [-y]

  # Lambda jump-host + local rotating proxy (target-agnostic egress)
  tmt up   -jump -regions R1,R2,... -ak ACCESS_KEY -sk SECRET_KEY [-st TOKEN] [-port 8008]
  tmt down -jump -regions R1,R2,... -ak ACCESS_KEY -sk SECRET_KEY [-st TOKEN] [-y]

  # Tear down by name / list tracked resources (no need to remember the up command)
  tmt down -n NAME -ak ACCESS_KEY -sk SECRET_KEY [-y]
  tmt --list

Commands:
  up      Create the proxy (API Gateway, or -jump for the Lambda backend)
  down    Remove the proxy (by -t/-regions, or -n NAME from the ledger)
  --list  List locally tracked resources and how they were created

Options:
  -ak       AWS access key ID (required)
  -sk       AWS secret access key (required)
  -st       AWS session token, for temporary/STS credentials (optional)
  -t        Target URL to proxy to, e.g. https://api.example.com (API Gateway mode)
  -r        AWS region (default: %s)
  -y        Skip the confirmation prompt (down only)
  -jump     Use the Lambda jump-host backend (rotating multi-region egress)
  -regions  Comma-separated AWS regions to deploy to (jump mode)
  -port     Local MITM proxy port (jump mode, default: 8008)
  -n        Name a resource on 'up'; tear it down later with 'down -n NAME'

Jump mode: 'up -jump' deploys one Lambda per region, starts a local MITM proxy,
and stays in the foreground. Point your tool at it, e.g.:
  nuclei -u https://target.example.com -proxy http://127.0.0.1:8008
Ctrl-C tears the pool down; 'down -jump' cleans up any orphans.

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
	jumpMode := fs.Bool("jump", false, "use the Lambda jump-host backend (rotating egress)")
	regions := fs.String("regions", "", "comma-separated AWS regions (jump mode)")
	port := fs.Int("port", 8008, "local MITM proxy port (jump mode)")
	name := fs.String("n", "", "name for this resource, for 'down -n NAME' / '--list'")
	fs.Parse(args)

	if *jumpMode {
		runJumpUp(creds, *regions, *port, *name)
		return
	}

	target, err := creds.validate()
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}
	checkNameFree(*name)

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
	if !res.Existing {
		recordEntry(state.Entry{
			Name:      ledgerName(*name, "apigw", target),
			Backend:   "apigateway",
			Target:    target,
			Regions:   []string{*creds.region},
			Command:   state.RedactedCommand(os.Args),
			CreatedAt: time.Now(),
			Resources: []state.Resource{{Region: *creds.region, APIID: res.APIID, APIName: res.Name}},
		})
	}
	output.UpSummary(res.Name, res.APIID, *creds.region, target, endpoint)
}

func runDown(args []string) {
	fs := flag.NewFlagSet("down", flag.ExitOnError)
	creds := bindCredentialFlags(fs)
	yes := fs.Bool("y", false, "skip the confirmation prompt")
	jumpMode := fs.Bool("jump", false, "tear down the Lambda jump-host backend")
	regions := fs.String("regions", "", "comma-separated AWS regions (jump mode)")
	name := fs.String("n", "", "tear down the resource recorded under this name")
	fs.Parse(args)

	if *name != "" {
		runDownByName(creds, *name, *yes)
		return
	}
	if *jumpMode {
		runJumpDown(creds, *regions, *yes)
		return
	}

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
	removeMatching("apigateway", target, nil)
	output.DownSummary(res.Name, res.APIID, *creds.region, target)
}

// runJumpUp deploys one jump-host Lambda per region, starts the local MITM
// proxy, and blocks in the foreground until interrupted, tearing the pool down
// on exit. This is the additive Lambda backend; it does not touch the API
// Gateway path above.
func runJumpUp(creds *credentialFlags, regionsCSV string, port int, name string) {
	regions := parseRegions(regionsCSV)
	if err := creds.validateJump(regions); err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}
	checkNameFree(name)

	ctx := context.Background()
	var backends []proxy.Invoker
	var managers []*jump.Manager
	var resources []state.Resource

	for _, region := range regions {
		cfg, err := creds.regionConfig(ctx, region)
		if err != nil {
			output.Error("[%s] %s", region, err)
			teardown(ctx, managers)
			os.Exit(1)
		}
		lc := lambda.NewFromConfig(cfg)
		mgr := jump.NewManager(lc, iam.NewFromConfig(cfg), region)

		output.Step("[%s] Deploying jump-host Lambda...", region)
		res, err := mgr.Up(ctx)
		if err != nil {
			output.Error("[%s] %s", region, err)
			teardown(ctx, managers)
			os.Exit(1)
		}
		if res.Existing {
			output.Warn("[%s] %s already exists", region, res.Name)
		} else {
			output.Success("[%s] %s deployed", region, res.Name)
		}

		managers = append(managers, mgr)
		backends = append(backends, proxy.NewLambdaInvoker(lc, jump.FuncName(region)))
		resources = append(resources, state.Resource{Region: region, Function: jump.FuncName(region), Role: jump.RoleName(region)})
	}

	prox, err := proxy.New(backends)
	if err != nil {
		output.Error("%s", err)
		teardown(ctx, managers)
		os.Exit(1)
	}

	entryName := ledgerName(name, "jump", strings.Join(regions, ","))
	recordEntry(state.Entry{
		Name:      entryName,
		Backend:   "jump",
		Regions:   regions,
		Command:   state.RedactedCommand(os.Args),
		CreatedAt: time.Now(),
		Resources: resources,
	})

	srv := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: prox}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			output.Error("proxy server: %s", err)
		}
	}()

	output.JumpSummary(port, regions)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	fmt.Println()
	output.Step("Shutting down proxy and tearing down pool...")
	srv.Close()
	teardown(ctx, managers)
	removeEntry(entryName)
	output.Success("Done")
}

// runJumpDown sweeps the given regions, removing any jump-host function/role.
// It is the safety net for orphans left if `up -jump` was killed abruptly.
func runJumpDown(creds *credentialFlags, regionsCSV string, yes bool) {
	regions := parseRegions(regionsCSV)
	if err := creds.validateJump(regions); err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}
	if !yes && !output.Confirm(fmt.Sprintf("Remove the jump-host pool in: %s?", strings.Join(regions, ", "))) {
		output.Warn("Aborted")
		os.Exit(0)
	}

	ctx := context.Background()
	for _, region := range regions {
		cfg, err := creds.regionConfig(ctx, region)
		if err != nil {
			output.Error("[%s] %s", region, err)
			continue
		}
		mgr := jump.NewManager(lambda.NewFromConfig(cfg), iam.NewFromConfig(cfg), region)
		output.Step("[%s] Removing jump-host...", region)
		res, err := mgr.Down(ctx)
		if err != nil {
			output.Error("[%s] %s", region, err)
			continue
		}
		if res.Found {
			output.Success("[%s] Removed %s", region, res.Name)
		} else {
			output.Warn("[%s] Nothing to remove", region)
		}
	}
	removeMatching("jump", "", regions)
}

// teardown removes every jump-host provisioned so far, best-effort.
func teardown(ctx context.Context, managers []*jump.Manager) {
	for _, m := range managers {
		if _, err := m.Down(ctx); err != nil {
			output.Warn("[%s] teardown: %s", m.Region(), err)
		}
	}
}

// parseRegions splits a comma-separated region list, trimming and de-duping.
func parseRegions(csv string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range strings.Split(csv, ",") {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

func (c *credentialFlags) validateJump(regions []string) error {
	var missing []string
	if *c.accessKey == "" {
		missing = append(missing, "-ak")
	}
	if *c.secretKey == "" {
		missing = append(missing, "-sk")
	}
	if len(regions) == 0 {
		missing = append(missing, "-regions")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	return nil
}

func (c *credentialFlags) regionConfig(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(*c.accessKey, *c.secretKey, *c.sessionToken)),
	)
}

// runDownByName tears down whatever was recorded under name, reconstructing the
// backend's Manager(s) from the ledger. Credentials still come from flags — the
// ledger never stores them.
func runDownByName(creds *credentialFlags, name string, yes bool) {
	if *creds.accessKey == "" || *creds.secretKey == "" {
		output.Error("missing required flag(s): -ak, -sk")
		os.Exit(1)
	}
	s, err := state.Load()
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}
	entry, ok := s.Get(name)
	if !ok {
		output.Error("no resource named %q in the ledger (see 'tmt --list')", name)
		os.Exit(1)
	}
	if !yes && !output.Confirm(fmt.Sprintf("Remove %q (%s, regions: %s)?", name, entry.Backend, strings.Join(entry.Regions, ", "))) {
		output.Warn("Aborted")
		os.Exit(0)
	}

	ctx := context.Background()
	failed := false
	for _, region := range entry.Regions {
		cfg, err := creds.regionConfig(ctx, region)
		if err != nil {
			output.Error("[%s] %s", region, err)
			failed = true
			continue
		}
		output.Step("[%s] Removing %s...", region, entry.Backend)
		var derr error
		switch entry.Backend {
		case "apigateway":
			_, derr = gateway.NewManager(apigateway.NewFromConfig(cfg), region, entry.Target).Down(ctx)
		case "jump":
			_, derr = jump.NewManager(lambda.NewFromConfig(cfg), iam.NewFromConfig(cfg), region).Down(ctx)
		default:
			derr = fmt.Errorf("unknown backend %q", entry.Backend)
		}
		if derr != nil {
			output.Error("[%s] %s", region, derr)
			failed = true
			continue
		}
		output.Success("[%s] Removed", region)
	}

	if failed {
		output.Warn("Some resources failed to remove; keeping %q in the ledger", name)
		os.Exit(1)
	}
	removeEntry(name)
	output.Success("Removed %q", name)
}

// runList prints the local ledger. It never calls AWS.
func runList() {
	s, err := state.Load()
	if err != nil {
		output.Error("%s", err)
		os.Exit(1)
	}
	if len(s.Entries) == 0 {
		output.Warn("No tracked resources. Ledger: %s", state.Path())
		return
	}
	for _, e := range s.Entries {
		fmt.Println()
		output.Success("%s  (%s)", e.Name, e.Backend)
		fmt.Printf("  created:   %s\n", e.CreatedAt.Format(time.RFC3339))
		fmt.Printf("  regions:   %s\n", strings.Join(e.Regions, ", "))
		if e.Target != "" {
			fmt.Printf("  target:    %s\n", e.Target)
		}
		fmt.Println("  resources:")
		for _, r := range e.Resources {
			if r.Function != "" {
				fmt.Printf("    - [%s] function=%s role=%s\n", r.Region, r.Function, r.Role)
			} else {
				fmt.Printf("    - [%s] api=%s (%s)\n", r.Region, r.APIID, r.APIName)
			}
		}
		fmt.Printf("  command:   %s\n", e.Command)
		fmt.Printf("  teardown:  tmt down -n %s -ak ... -sk ...\n", e.Name)
	}
	fmt.Println()
	output.Info("Ledger: %s", state.Path())
}

// ledgerName returns explicit if set, else a unique auto-generated slug.
func ledgerName(explicit, backend, seed string) string {
	if explicit != "" {
		return explicit
	}
	sum := sha256.Sum256([]byte(seed + "|" + time.Now().String()))
	return fmt.Sprintf("%s-%x", backend, sum[:3])
}

// checkNameFree aborts early if an explicit name already exists, so we never
// create resources we can't cleanly track.
func checkNameFree(name string) {
	if name == "" {
		return
	}
	s, err := state.Load()
	if err != nil {
		return // non-fatal; recording will surface issues later
	}
	if _, ok := s.Get(name); ok {
		output.Error("a resource named %q already exists (see 'tmt --list')", name)
		os.Exit(1)
	}
}

// recordEntry adds an entry to the ledger, best-effort (a ledger failure must
// not fail the actual provisioning).
func recordEntry(e state.Entry) {
	s, err := state.Load()
	if err != nil {
		output.Warn("ledger: %s", err)
		return
	}
	if err := s.Add(e); err != nil {
		output.Warn("ledger: %s", err)
		return
	}
	if err := s.Save(); err != nil {
		output.Warn("ledger: %s", err)
		return
	}
	output.Info("Tracked as %q (tmt --list)", e.Name)
}

// removeEntry drops an entry by name, best-effort.
func removeEntry(name string) {
	s, err := state.Load()
	if err != nil {
		return
	}
	if s.Remove(name) {
		if err := s.Save(); err != nil {
			output.Warn("ledger: %s", err)
		}
	}
}

// removeMatching drops the ledger entry a legacy (nameless) down just tore down.
func removeMatching(backend, target string, regions []string) {
	s, err := state.Load()
	if err != nil {
		return
	}
	if s.RemoveMatching(backend, target, regions) {
		if err := s.Save(); err != nil {
			output.Warn("ledger: %s", err)
		}
	}
}
