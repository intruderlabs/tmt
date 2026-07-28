package gateway

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
)

// fakeClient is a hand-rolled APIClient that records call order and lets a
// test inject the existing REST APIs / errors it should return.
type fakeClient struct {
	calls []string

	existing []types.RestApi
	errors   map[string]error

	putIntegrationURIs   []string
	putIntegrationParams []map[string]string
	putMethodParams      []map[string]bool
}

func (f *fakeClient) record(name string) error {
	f.calls = append(f.calls, name)
	return f.errors[name]
}

func (f *fakeClient) GetRestApis(_ context.Context, _ *apigateway.GetRestApisInput, _ ...func(*apigateway.Options)) (*apigateway.GetRestApisOutput, error) {
	if err := f.record("GetRestApis"); err != nil {
		return nil, err
	}
	return &apigateway.GetRestApisOutput{Items: f.existing}, nil
}

func (f *fakeClient) CreateRestApi(_ context.Context, _ *apigateway.CreateRestApiInput, _ ...func(*apigateway.Options)) (*apigateway.CreateRestApiOutput, error) {
	if err := f.record("CreateRestApi"); err != nil {
		return nil, err
	}
	return &apigateway.CreateRestApiOutput{Id: aws.String("new-api-id")}, nil
}

func (f *fakeClient) GetResources(_ context.Context, _ *apigateway.GetResourcesInput, _ ...func(*apigateway.Options)) (*apigateway.GetResourcesOutput, error) {
	if err := f.record("GetResources"); err != nil {
		return nil, err
	}
	return &apigateway.GetResourcesOutput{Items: []types.Resource{
		{Id: aws.String("root-id"), Path: aws.String("/")},
	}}, nil
}

func (f *fakeClient) PutMethod(_ context.Context, params *apigateway.PutMethodInput, _ ...func(*apigateway.Options)) (*apigateway.PutMethodOutput, error) {
	f.putMethodParams = append(f.putMethodParams, params.RequestParameters)
	if err := f.record("PutMethod"); err != nil {
		return nil, err
	}
	return &apigateway.PutMethodOutput{}, nil
}

func (f *fakeClient) PutIntegration(_ context.Context, params *apigateway.PutIntegrationInput, _ ...func(*apigateway.Options)) (*apigateway.PutIntegrationOutput, error) {
	f.putIntegrationURIs = append(f.putIntegrationURIs, aws.ToString(params.Uri))
	f.putIntegrationParams = append(f.putIntegrationParams, params.RequestParameters)
	if err := f.record("PutIntegration"); err != nil {
		return nil, err
	}
	return &apigateway.PutIntegrationOutput{}, nil
}

func (f *fakeClient) CreateResource(_ context.Context, _ *apigateway.CreateResourceInput, _ ...func(*apigateway.Options)) (*apigateway.CreateResourceOutput, error) {
	if err := f.record("CreateResource"); err != nil {
		return nil, err
	}
	return &apigateway.CreateResourceOutput{Id: aws.String("proxy-resource-id")}, nil
}

func (f *fakeClient) CreateDeployment(_ context.Context, _ *apigateway.CreateDeploymentInput, _ ...func(*apigateway.Options)) (*apigateway.CreateDeploymentOutput, error) {
	if err := f.record("CreateDeployment"); err != nil {
		return nil, err
	}
	return &apigateway.CreateDeploymentOutput{}, nil
}

func (f *fakeClient) DeleteStage(_ context.Context, _ *apigateway.DeleteStageInput, _ ...func(*apigateway.Options)) (*apigateway.DeleteStageOutput, error) {
	if err := f.record("DeleteStage"); err != nil {
		return nil, err
	}
	return &apigateway.DeleteStageOutput{}, nil
}

func (f *fakeClient) DeleteRestApi(_ context.Context, _ *apigateway.DeleteRestApiInput, _ ...func(*apigateway.Options)) (*apigateway.DeleteRestApiOutput, error) {
	if err := f.record("DeleteRestApi"); err != nil {
		return nil, err
	}
	return &apigateway.DeleteRestApiOutput{}, nil
}

func TestAPIName_DeterministicAndRegionScoped(t *testing.T) {
	a := apiName("https://api.example.com", "us-east-1")
	b := apiName("https://api.example.com", "us-east-1")
	if a != b {
		t.Fatalf("apiName not deterministic: %q != %q", a, b)
	}
	c := apiName("https://api.example.com", "sa-east-1")
	if a == c {
		t.Fatalf("apiName did not change with region: %q == %q", a, c)
	}
}

func TestUp_ExistingAPI_NoMutatingCalls(t *testing.T) {
	target, region := "https://api.example.com", "us-east-1"
	name := apiName(target, region)
	f := &fakeClient{existing: []types.RestApi{{Id: aws.String("existing-id"), Name: aws.String(name)}}}

	m := NewManager(f, region, target)
	res, err := m.Up(context.Background())
	if err != nil {
		t.Fatalf("Up returned error: %v", err)
	}
	if !res.Existing || res.APIID != "existing-id" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !reflect.DeepEqual(f.calls, []string{"GetRestApis"}) {
		t.Fatalf("expected only GetRestApis to be called, got %v", f.calls)
	}
}

func TestUp_CreatesFullChain(t *testing.T) {
	target, region := "https://api.example.com", "us-east-1"
	f := &fakeClient{}

	m := NewManager(f, region, target)
	res, err := m.Up(context.Background())
	if err != nil {
		t.Fatalf("Up returned error: %v", err)
	}
	if res.Existing || res.APIID != "new-api-id" {
		t.Fatalf("unexpected result: %+v", res)
	}

	wantCalls := []string{
		"GetRestApis", "CreateRestApi", "GetResources",
		"PutMethod", "PutIntegration", "CreateResource",
		"PutMethod", "PutIntegration", "CreateDeployment",
	}
	if !reflect.DeepEqual(f.calls, wantCalls) {
		t.Fatalf("call order mismatch:\ngot:  %v\nwant: %v", f.calls, wantCalls)
	}

	wantURIs := []string{target + "/", target + "/{proxy}"}
	if !reflect.DeepEqual(f.putIntegrationURIs, wantURIs) {
		t.Fatalf("integration URIs mismatch:\ngot:  %v\nwant: %v", f.putIntegrationURIs, wantURIs)
	}

	if len(f.putMethodParams) != 2 || len(f.putMethodParams[0]) != 0 {
		t.Fatalf("root PutMethod should have empty RequestParameters, got %v", f.putMethodParams)
	}
	if got := f.putMethodParams[1]; !reflect.DeepEqual(got, map[string]bool{"method.request.path.proxy": true}) {
		t.Fatalf("proxy PutMethod RequestParameters mismatch: %v", got)
	}

	if got := f.putIntegrationParams[1]; !reflect.DeepEqual(got, map[string]string{"integration.request.path.proxy": "method.request.path.proxy"}) {
		t.Fatalf("proxy PutIntegration RequestParameters mismatch: %v", got)
	}
}

func TestDown_NothingFound_NoDeletes(t *testing.T) {
	target, region := "https://api.example.com", "us-east-1"
	f := &fakeClient{}

	m := NewManager(f, region, target)
	res, err := m.Down(context.Background())
	if err != nil {
		t.Fatalf("Down returned error: %v", err)
	}
	if res.Found {
		t.Fatalf("expected Found=false, got %+v", res)
	}
	if !reflect.DeepEqual(f.calls, []string{"GetRestApis"}) {
		t.Fatalf("expected only GetRestApis to be called, got %v", f.calls)
	}
}

func TestDown_DeletesStageThenAPI(t *testing.T) {
	target, region := "https://api.example.com", "us-east-1"
	name := apiName(target, region)
	f := &fakeClient{existing: []types.RestApi{{Id: aws.String("existing-id"), Name: aws.String(name)}}}

	m := NewManager(f, region, target)
	res, err := m.Down(context.Background())
	if err != nil {
		t.Fatalf("Down returned error: %v", err)
	}
	if !res.Found || res.APIID != "existing-id" {
		t.Fatalf("unexpected result: %+v", res)
	}

	wantCalls := []string{"GetRestApis", "DeleteStage", "DeleteRestApi"}
	if !reflect.DeepEqual(f.calls, wantCalls) {
		t.Fatalf("call order mismatch:\ngot:  %v\nwant: %v", f.calls, wantCalls)
	}
}
