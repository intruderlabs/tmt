// Package jump provisions and tears down the TMT jump-host Lambda in a single
// region. The function is target-agnostic (the destination is a per-invocation
// payload), so one function per region is all that's needed; the local MITM
// proxy rotates Invoke calls across regions. This is a second, additive backend
// alongside the API Gateway proxy in internal/gateway — neither replaces the
// other.
package jump

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// bootstrapZip is the compiled jump-host function, zipped. The Makefile's
// `lambda` target builds it before any `go build`/`go test`; the embed makes
// tmt a single self-contained binary.
//
//go:embed lambdafn.zip
var bootstrapZip []byte

const (
	basicExecPolicyARN = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
	assumeRolePolicy   = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`

	// createRetries/createDelay absorb IAM role-propagation lag: a freshly
	// created role isn't immediately assumable, so CreateFunction can fail
	// with InvalidParameterValueException for a few seconds.
	createRetries = 8
	createDelay   = 3 * time.Second

	// activeAttempts/activeDelay poll until the function leaves the Pending
	// state, so the first Invoke doesn't race function creation.
	activeAttempts = 20
	activeDelay    = 2 * time.Second
)

// LambdaAPI is the subset of *lambda.Client this package calls.
type LambdaAPI interface {
	GetFunction(ctx context.Context, params *lambda.GetFunctionInput, optFns ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error)
	CreateFunction(ctx context.Context, params *lambda.CreateFunctionInput, optFns ...func(*lambda.Options)) (*lambda.CreateFunctionOutput, error)
	DeleteFunction(ctx context.Context, params *lambda.DeleteFunctionInput, optFns ...func(*lambda.Options)) (*lambda.DeleteFunctionOutput, error)
}

// IAMAPI is the subset of *iam.Client this package calls.
type IAMAPI interface {
	GetRole(ctx context.Context, params *iam.GetRoleInput, optFns ...func(*iam.Options)) (*iam.GetRoleOutput, error)
	CreateRole(ctx context.Context, params *iam.CreateRoleInput, optFns ...func(*iam.Options)) (*iam.CreateRoleOutput, error)
	AttachRolePolicy(ctx context.Context, params *iam.AttachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.AttachRolePolicyOutput, error)
	DetachRolePolicy(ctx context.Context, params *iam.DetachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error)
	DeleteRole(ctx context.Context, params *iam.DeleteRoleInput, optFns ...func(*iam.Options)) (*iam.DeleteRoleOutput, error)
}

// Manager provisions/tears down the jump-host function for a single region.
type Manager struct {
	lambda LambdaAPI
	iam    IAMAPI
	region string
}

// NewManager builds a Manager for one region.
func NewManager(l LambdaAPI, i IAMAPI, region string) *Manager {
	return &Manager{lambda: l, iam: i, region: region}
}

// Region returns the region this Manager operates on.
func (m *Manager) Region() string { return m.region }

// FuncName is the deterministic function name for a region, so Down only ever
// matches the function created for that region.
func FuncName(region string) string {
	sum := sha256.Sum256([]byte(region))
	return fmt.Sprintf("tmt-egress-%x", sum[:4])
}

func roleName(region string) string {
	sum := sha256.Sum256([]byte(region))
	return fmt.Sprintf("tmt-egress-role-%x", sum[:4])
}

// UpResult describes the outcome of Up.
type UpResult struct {
	Existing bool
	Name     string
}

// Up creates the jump-host function if it doesn't already exist. It is
// idempotent: calling it again for the same region returns Existing=true and
// makes no mutating calls.
func (m *Manager) Up(ctx context.Context) (*UpResult, error) {
	name := FuncName(m.region)

	if _, err := m.lambda.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String(name)}); err == nil {
		return &UpResult{Existing: true, Name: name}, nil
	} else {
		var nfe *lambdatypes.ResourceNotFoundException
		if !errors.As(err, &nfe) {
			return nil, fmt.Errorf("checking function: %w", err)
		}
	}

	roleARN, err := m.ensureRole(ctx)
	if err != nil {
		return nil, err
	}

	if err := m.createFunction(ctx, name, roleARN); err != nil {
		return nil, err
	}
	if err := m.waitActive(ctx, name); err != nil {
		return nil, err
	}
	return &UpResult{Existing: false, Name: name}, nil
}

// ensureRole returns the ARN of the region's execution role, creating it (and
// attaching the basic-execution policy) if absent.
func (m *Manager) ensureRole(ctx context.Context) (string, error) {
	rn := roleName(m.region)

	if got, err := m.iam.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(rn)}); err == nil {
		return aws.ToString(got.Role.Arn), nil
	} else {
		var nse *iamtypes.NoSuchEntityException
		if !errors.As(err, &nse) {
			return "", fmt.Errorf("checking role: %w", err)
		}
	}

	created, err := m.iam.CreateRole(ctx, &iam.CreateRoleInput{
		RoleName:                 aws.String(rn),
		AssumeRolePolicyDocument: aws.String(assumeRolePolicy),
		Description:              aws.String("TMT jump-host execution role"),
	})
	if err != nil {
		return "", fmt.Errorf("creating role: %w", err)
	}
	if _, err := m.iam.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{
		RoleName:  aws.String(rn),
		PolicyArn: aws.String(basicExecPolicyARN),
	}); err != nil {
		return "", fmt.Errorf("attaching policy: %w", err)
	}
	return aws.ToString(created.Role.Arn), nil
}

func (m *Manager) createFunction(ctx context.Context, name, roleARN string) error {
	in := &lambda.CreateFunctionInput{
		FunctionName:  aws.String(name),
		Role:          aws.String(roleARN),
		Runtime:       lambdatypes.RuntimeProvidedal2023,
		Handler:       aws.String("bootstrap"),
		Architectures: []lambdatypes.Architecture{lambdatypes.ArchitectureArm64},
		Code:          &lambdatypes.FunctionCode{ZipFile: bootstrapZip},
		Timeout:       aws.Int32(35),
		Description:   aws.String("TMT jump-host egress function"),
	}

	var lastErr error
	for i := 0; i < createRetries; i++ {
		if _, err := m.lambda.CreateFunction(ctx, in); err == nil {
			return nil
		} else {
			var ipe *lambdatypes.InvalidParameterValueException
			if !errors.As(err, &ipe) {
				return fmt.Errorf("creating function: %w", err)
			}
			lastErr = err
		}
		if err := sleep(ctx, createDelay); err != nil {
			return err
		}
	}
	return fmt.Errorf("creating function (role not assumable after retries): %w", lastErr)
}

func (m *Manager) waitActive(ctx context.Context, name string) error {
	for i := 0; i < activeAttempts; i++ {
		out, err := m.lambda.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String(name)})
		if err != nil {
			return fmt.Errorf("polling function state: %w", err)
		}
		if out.Configuration != nil && out.Configuration.State == lambdatypes.StateActive {
			return nil
		}
		if err := sleep(ctx, activeDelay); err != nil {
			return err
		}
	}
	return fmt.Errorf("function %s did not become active in time", name)
}

// DownResult describes the outcome of Down.
type DownResult struct {
	Found bool
	Name  string
}

// Down deletes the jump-host function and its role if they exist. It is
// idempotent: absent resources are treated as nothing-to-do.
func (m *Manager) Down(ctx context.Context) (*DownResult, error) {
	name := FuncName(m.region)
	rn := roleName(m.region)
	found := true

	if _, err := m.lambda.DeleteFunction(ctx, &lambda.DeleteFunctionInput{FunctionName: aws.String(name)}); err != nil {
		var nfe *lambdatypes.ResourceNotFoundException
		if !errors.As(err, &nfe) {
			return nil, fmt.Errorf("deleting function: %w", err)
		}
		found = false
	}

	if _, err := m.iam.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
		RoleName:  aws.String(rn),
		PolicyArn: aws.String(basicExecPolicyARN),
	}); err != nil {
		var nse *iamtypes.NoSuchEntityException
		if !errors.As(err, &nse) {
			return nil, fmt.Errorf("detaching policy: %w", err)
		}
	}
	if _, err := m.iam.DeleteRole(ctx, &iam.DeleteRoleInput{RoleName: aws.String(rn)}); err != nil {
		var nse *iamtypes.NoSuchEntityException
		if !errors.As(err, &nse) {
			return nil, fmt.Errorf("deleting role: %w", err)
		}
	}

	return &DownResult{Found: found, Name: name}, nil
}

// sleep waits d, returning early if ctx is cancelled.
func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
