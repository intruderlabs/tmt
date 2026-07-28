// Package gateway provisions and tears down an AWS API Gateway REST API that
// acts as a catch-all HTTP proxy in front of a target URL.
package gateway

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
)

// stage is the API Gateway deployment stage name. It never varies for this
// tool, so it is a constant rather than a flag nobody asked for.
const stage = "prod"

// APIClient is the subset of *apigateway.Client this package calls. It
// exists so tests can supply a fake; *apigateway.Client satisfies it as-is.
type APIClient interface {
	GetRestApis(ctx context.Context, params *apigateway.GetRestApisInput, optFns ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error)
	CreateRestApi(ctx context.Context, params *apigateway.CreateRestApiInput, optFns ...func(*apigateway.Options)) (*apigateway.CreateRestApiOutput, error)
	GetResources(ctx context.Context, params *apigateway.GetResourcesInput, optFns ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error)
	PutMethod(ctx context.Context, params *apigateway.PutMethodInput, optFns ...func(*apigateway.Options)) (*apigateway.PutMethodOutput, error)
	PutIntegration(ctx context.Context, params *apigateway.PutIntegrationInput, optFns ...func(*apigateway.Options)) (*apigateway.PutIntegrationOutput, error)
	CreateResource(ctx context.Context, params *apigateway.CreateResourceInput, optFns ...func(*apigateway.Options)) (*apigateway.CreateResourceOutput, error)
	CreateDeployment(ctx context.Context, params *apigateway.CreateDeploymentInput, optFns ...func(*apigateway.Options)) (*apigateway.CreateDeploymentOutput, error)
	DeleteStage(ctx context.Context, params *apigateway.DeleteStageInput, optFns ...func(*apigateway.Options)) (*apigateway.DeleteStageOutput, error)
	DeleteRestApi(ctx context.Context, params *apigateway.DeleteRestApiInput, optFns ...func(*apigateway.Options)) (*apigateway.DeleteRestApiOutput, error)
}

// Manager provisions/tears down the proxy API for a single target+region pair.
type Manager struct {
	client APIClient
	region string
	target string // trailing slash already trimmed by the caller
}

// NewManager builds a Manager. target must already have any trailing slash trimmed.
func NewManager(client APIClient, region, target string) *Manager {
	return &Manager{client: client, region: region, target: target}
}

// apiName derives a deterministic API Gateway name from the target and
// region, so "down" only ever matches the proxy created for that pair.
func apiName(target, region string) string {
	sum := sha256.Sum256([]byte(target + "|" + region))
	return fmt.Sprintf("pentest-proxy-%x", sum[:4])
}

// findAPIID pages through all REST APIs looking for one named after this
// Manager's target+region, returning "" if none exists yet.
func (m *Manager) findAPIID(ctx context.Context) (string, error) {
	name := apiName(m.target, m.region)
	p := apigateway.NewGetRestApisPaginator(m.client, &apigateway.GetRestApisInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("listing rest apis: %w", err)
		}
		for _, api := range page.Items {
			if aws.ToString(api.Name) == name {
				return aws.ToString(api.Id), nil
			}
		}
	}
	return "", nil
}

// UpResult describes the outcome of Up.
type UpResult struct {
	Existing bool
	APIID    string
	Name     string
}

// Up creates the proxy API if it doesn't already exist. It is idempotent:
// calling it again for the same target+region returns Existing=true and
// makes no mutating AWS calls.
func (m *Manager) Up(ctx context.Context) (*UpResult, error) {
	name := apiName(m.target, m.region)

	if id, err := m.findAPIID(ctx); err != nil {
		return nil, err
	} else if id != "" {
		return &UpResult{Existing: true, APIID: id, Name: name}, nil
	}

	created, err := m.client.CreateRestApi(ctx, &apigateway.CreateRestApiInput{
		Name:        aws.String(name),
		Description: aws.String(fmt.Sprintf("Pentest proxy -> %s (%s)", m.target, m.region)),
		EndpointConfiguration: &types.EndpointConfiguration{
			Types: []types.EndpointType{types.EndpointTypeRegional},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("creating rest api: %w", err)
	}
	apiID := aws.ToString(created.Id)

	resources, err := m.client.GetResources(ctx, &apigateway.GetResourcesInput{RestApiId: created.Id})
	if err != nil {
		return nil, fmt.Errorf("listing resources: %w", err)
	}
	var rootID *string
	for _, r := range resources.Items {
		if aws.ToString(r.Path) == "/" {
			rootID = r.Id
			break
		}
	}
	if rootID == nil {
		return nil, fmt.Errorf("root resource not found for api %s", apiID)
	}

	if _, err := m.client.PutMethod(ctx, &apigateway.PutMethodInput{
		RestApiId:         created.Id,
		ResourceId:        rootID,
		HttpMethod:        aws.String("ANY"),
		AuthorizationType: aws.String("NONE"),
		RequestParameters: map[string]bool{},
	}); err != nil {
		return nil, fmt.Errorf("put method (root): %w", err)
	}

	if _, err := m.client.PutIntegration(ctx, &apigateway.PutIntegrationInput{
		RestApiId:             created.Id,
		ResourceId:            rootID,
		HttpMethod:            aws.String("ANY"),
		Type:                  types.IntegrationTypeHttpProxy,
		IntegrationHttpMethod: aws.String("ANY"),
		Uri:                   aws.String(m.target + "/"),
	}); err != nil {
		return nil, fmt.Errorf("put integration (root): %w", err)
	}

	proxyResource, err := m.client.CreateResource(ctx, &apigateway.CreateResourceInput{
		RestApiId: created.Id,
		ParentId:  rootID,
		PathPart:  aws.String("{proxy+}"),
	})
	if err != nil {
		return nil, fmt.Errorf("creating proxy resource: %w", err)
	}

	if _, err := m.client.PutMethod(ctx, &apigateway.PutMethodInput{
		RestApiId:         created.Id,
		ResourceId:        proxyResource.Id,
		HttpMethod:        aws.String("ANY"),
		AuthorizationType: aws.String("NONE"),
		RequestParameters: map[string]bool{"method.request.path.proxy": true},
	}); err != nil {
		return nil, fmt.Errorf("put method (proxy): %w", err)
	}

	if _, err := m.client.PutIntegration(ctx, &apigateway.PutIntegrationInput{
		RestApiId:             created.Id,
		ResourceId:            proxyResource.Id,
		HttpMethod:            aws.String("ANY"),
		Type:                  types.IntegrationTypeHttpProxy,
		IntegrationHttpMethod: aws.String("ANY"),
		Uri:                   aws.String(m.target + "/{proxy}"),
		RequestParameters:     map[string]string{"integration.request.path.proxy": "method.request.path.proxy"},
		CacheKeyParameters:    []string{"method.request.path.proxy"},
	}); err != nil {
		return nil, fmt.Errorf("put integration (proxy): %w", err)
	}

	if _, err := m.client.CreateDeployment(ctx, &apigateway.CreateDeploymentInput{
		RestApiId: created.Id,
		StageName: aws.String(stage),
	}); err != nil {
		return nil, fmt.Errorf("creating deployment: %w", err)
	}

	return &UpResult{Existing: false, APIID: apiID, Name: name}, nil
}

// DownResult describes the outcome of Down.
type DownResult struct {
	Found bool
	APIID string
	Name  string
}

// Down deletes the proxy API if it exists. It is idempotent: calling it
// again for a target+region with nothing deployed returns Found=false and
// makes no AWS calls.
func (m *Manager) Down(ctx context.Context) (*DownResult, error) {
	name := apiName(m.target, m.region)

	id, err := m.findAPIID(ctx)
	if err != nil {
		return nil, err
	}
	if id == "" {
		return &DownResult{Found: false, Name: name}, nil
	}

	if _, err := m.client.DeleteStage(ctx, &apigateway.DeleteStageInput{
		RestApiId: aws.String(id),
		StageName: aws.String(stage),
	}); err != nil {
		var nfe *types.NotFoundException
		if !errors.As(err, &nfe) {
			return nil, fmt.Errorf("deleting stage: %w", err)
		}
	}

	if _, err := m.client.DeleteRestApi(ctx, &apigateway.DeleteRestApiInput{RestApiId: aws.String(id)}); err != nil {
		return nil, fmt.Errorf("deleting rest api: %w", err)
	}

	return &DownResult{Found: true, APIID: id, Name: name}, nil
}

// Endpoint returns the public invoke URL for a deployed proxy API.
func Endpoint(apiID, region string) string {
	return fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s", apiID, region, stage)
}
