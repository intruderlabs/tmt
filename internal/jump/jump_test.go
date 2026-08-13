package jump

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

// fakeLambda records call order. GetFunction returns NotFound on the first
// call (existence check) unless existsInitially, and an Active function
// afterwards (the waitActive poll).
type fakeLambda struct {
	calls           []string
	getCount        int
	existsInitially bool
	deleteNotFound  bool
}

func (f *fakeLambda) GetFunction(context.Context, *lambda.GetFunctionInput, ...func(*lambda.Options)) (*lambda.GetFunctionOutput, error) {
	f.calls = append(f.calls, "GetFunction")
	f.getCount++
	if f.getCount == 1 && !f.existsInitially {
		return nil, &lambdatypes.ResourceNotFoundException{}
	}
	return &lambda.GetFunctionOutput{
		Configuration: &lambdatypes.FunctionConfiguration{State: lambdatypes.StateActive},
	}, nil
}

func (f *fakeLambda) CreateFunction(context.Context, *lambda.CreateFunctionInput, ...func(*lambda.Options)) (*lambda.CreateFunctionOutput, error) {
	f.calls = append(f.calls, "CreateFunction")
	return &lambda.CreateFunctionOutput{}, nil
}

func (f *fakeLambda) DeleteFunction(context.Context, *lambda.DeleteFunctionInput, ...func(*lambda.Options)) (*lambda.DeleteFunctionOutput, error) {
	f.calls = append(f.calls, "DeleteFunction")
	if f.deleteNotFound {
		return nil, &lambdatypes.ResourceNotFoundException{}
	}
	return &lambda.DeleteFunctionOutput{}, nil
}

// fakeIAM records call order. roleExists controls GetRole; roleMissing makes
// Detach/Delete report NoSuchEntity.
type fakeIAM struct {
	calls       []string
	roleExists  bool
	roleMissing bool
}

func (f *fakeIAM) GetRole(context.Context, *iam.GetRoleInput, ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	f.calls = append(f.calls, "GetRole")
	if f.roleExists {
		return &iam.GetRoleOutput{Role: &iamtypes.Role{Arn: aws.String("arn:aws:iam::0:role/x")}}, nil
	}
	return nil, &iamtypes.NoSuchEntityException{}
}

func (f *fakeIAM) CreateRole(context.Context, *iam.CreateRoleInput, ...func(*iam.Options)) (*iam.CreateRoleOutput, error) {
	f.calls = append(f.calls, "CreateRole")
	return &iam.CreateRoleOutput{Role: &iamtypes.Role{Arn: aws.String("arn:aws:iam::0:role/x")}}, nil
}

func (f *fakeIAM) AttachRolePolicy(context.Context, *iam.AttachRolePolicyInput, ...func(*iam.Options)) (*iam.AttachRolePolicyOutput, error) {
	f.calls = append(f.calls, "AttachRolePolicy")
	return &iam.AttachRolePolicyOutput{}, nil
}

func (f *fakeIAM) DetachRolePolicy(context.Context, *iam.DetachRolePolicyInput, ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error) {
	f.calls = append(f.calls, "DetachRolePolicy")
	if f.roleMissing {
		return nil, &iamtypes.NoSuchEntityException{}
	}
	return &iam.DetachRolePolicyOutput{}, nil
}

func (f *fakeIAM) DeleteRole(context.Context, *iam.DeleteRoleInput, ...func(*iam.Options)) (*iam.DeleteRoleOutput, error) {
	f.calls = append(f.calls, "DeleteRole")
	if f.roleMissing {
		return nil, &iamtypes.NoSuchEntityException{}
	}
	return &iam.DeleteRoleOutput{}, nil
}

func TestFuncName_DeterministicAndRegionScoped(t *testing.T) {
	a := FuncName("us-east-1")
	if a != FuncName("us-east-1") {
		t.Fatal("FuncName not deterministic")
	}
	if a == FuncName("sa-east-1") {
		t.Fatal("FuncName did not change with region")
	}
}

func TestUp_ExistingFunction_NoMutatingCalls(t *testing.T) {
	fl := &fakeLambda{existsInitially: true}
	fi := &fakeIAM{}

	res, err := NewManager(fl, fi, "us-east-1").Up(context.Background())
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if !res.Existing {
		t.Fatalf("expected Existing=true, got %+v", res)
	}
	if !reflect.DeepEqual(fl.calls, []string{"GetFunction"}) {
		t.Fatalf("lambda calls = %v", fl.calls)
	}
	if len(fi.calls) != 0 {
		t.Fatalf("iam should be untouched, got %v", fi.calls)
	}
}

func TestUp_CreatesRoleThenFunction(t *testing.T) {
	fl := &fakeLambda{}
	fi := &fakeIAM{}

	res, err := NewManager(fl, fi, "us-east-1").Up(context.Background())
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if res.Existing {
		t.Fatalf("expected Existing=false, got %+v", res)
	}
	// existence check (NotFound) -> create -> waitActive poll (Active)
	if want := []string{"GetFunction", "CreateFunction", "GetFunction"}; !reflect.DeepEqual(fl.calls, want) {
		t.Fatalf("lambda calls = %v, want %v", fl.calls, want)
	}
	if want := []string{"GetRole", "CreateRole", "AttachRolePolicy"}; !reflect.DeepEqual(fi.calls, want) {
		t.Fatalf("iam calls = %v, want %v", fi.calls, want)
	}
}

func TestDown_DeletesFunctionAndRole(t *testing.T) {
	fl := &fakeLambda{}
	fi := &fakeIAM{}

	res, err := NewManager(fl, fi, "us-east-1").Down(context.Background())
	if err != nil {
		t.Fatalf("Down: %v", err)
	}
	if !res.Found {
		t.Fatalf("expected Found=true, got %+v", res)
	}
	if want := []string{"DeleteFunction"}; !reflect.DeepEqual(fl.calls, want) {
		t.Fatalf("lambda calls = %v, want %v", fl.calls, want)
	}
	if want := []string{"DetachRolePolicy", "DeleteRole"}; !reflect.DeepEqual(fi.calls, want) {
		t.Fatalf("iam calls = %v, want %v", fi.calls, want)
	}
}

func TestDown_NothingPresent_NoError(t *testing.T) {
	fl := &fakeLambda{deleteNotFound: true}
	fi := &fakeIAM{roleMissing: true}

	res, err := NewManager(fl, fi, "us-east-1").Down(context.Background())
	if err != nil {
		t.Fatalf("Down: %v", err)
	}
	if res.Found {
		t.Fatalf("expected Found=false, got %+v", res)
	}
}
