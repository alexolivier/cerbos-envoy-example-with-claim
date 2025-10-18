package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"github.com/gin-gonic/gin"
	"google.golang.org/protobuf/types/known/structpb"
)

type fakeCerbosChecker struct {
	resp          *cerbos.CheckResourcesResponse
	err           error
	lastPrincipal *cerbos.Principal
	lastBatch     *cerbos.ResourceBatch
}

func (f *fakeCerbosChecker) CheckResources(_ context.Context, principal *cerbos.Principal, batch *cerbos.ResourceBatch) (*cerbos.CheckResourcesResponse, error) {
	f.lastPrincipal = principal
	f.lastBatch = batch
	return f.resp, f.err
}

func TestFilterAllowedDocuments(t *testing.T) {
	t.Helper()

	docs := []Document{
		{ID: "doc-1", AccountID: "acct-1", Title: "allowed", Body: "allowed"},
		{ID: "doc-2", AccountID: "acct-1", Title: "denied", Body: "denied"},
	}

	resp := &cerbos.CheckResourcesResponse{
		CheckResourcesResponse: &responsev1.CheckResourcesResponse{
			Results: []*responsev1.CheckResourcesResponse_ResultEntry{
				{
					Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{
						Id:   "doc-1",
						Kind: "document",
					},
					Actions: map[string]effectv1.Effect{
						"read": effectv1.Effect_EFFECT_ALLOW,
					},
				},
				{
					Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{
						Id:   "doc-2",
						Kind: "document",
					},
					Actions: map[string]effectv1.Effect{
						"read": effectv1.Effect_EFFECT_DENY,
					},
				},
			},
		},
	}

	client := &cerbosClient{checker: &fakeCerbosChecker{resp: resp}}
	principal := cerbos.NewPrincipal("user-1", "admin")
	if err := principal.Validate(); err != nil {
		t.Fatalf("validate principal: %v", err)
	}

	allowed, err := client.filterAllowedDocuments(context.Background(), principal, docs, "acct-1", "read")
	if err != nil {
		t.Fatalf("filterAllowedDocuments returned error: %v", err)
	}

	if len(allowed) != 1 || allowed[0].ID != "doc-1" {
		t.Fatalf("unexpected allowed documents: %#v", allowed)
	}

	fc := client.checker.(*fakeCerbosChecker)
	if fc.lastPrincipal == nil || fc.lastPrincipal.ID() != "user-1" {
		t.Fatalf("expected principal to be recorded")
	}
	if fc.lastBatch == nil || len(fc.lastBatch.Batch) != len(docs) {
		t.Fatalf("expected resource batch to contain %d entries", len(docs))
	}
}

func TestFilterAllowedDocumentsError(t *testing.T) {
	client := &cerbosClient{checker: &fakeCerbosChecker{err: errors.New("pdp unavailable")}}
	principal := cerbos.NewPrincipal("user-1", "admin")

	_, err := client.filterAllowedDocuments(context.Background(), principal, []Document{{ID: "doc-1", AccountID: "acct"}}, "acct", "read")
	if err == nil || err.Error() != "authorization check failed: pdp unavailable" {
		t.Fatalf("expected wrapped error, got %v", err)
	}
}

func TestPrincipalFromHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("x-authz-id", "user-123")
	req.Header.Set("x-authz-roles", `["admin","member"]`)
	req.Header.Set("z-authz-accountId", "acct-123")
	ctx.Request = req

	principal, err := principalFromHeaders(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if principal.ID() != "user-123" {
		t.Fatalf("unexpected principal id: %s", principal.ID())
	}

	gotRoles := principal.Roles()
	if len(gotRoles) != 2 || gotRoles[0] != "admin" || gotRoles[1] != "member" {
		t.Fatalf("unexpected roles: %#v", gotRoles)
	}

	attr := principal.Obj.GetAttr()
	if attr["accountId"].GetStringValue() != "acct-123" {
		t.Fatalf("unexpected account attribute: %#v", attr["accountId"])
	}
}

func TestFilterAllowedDocumentsWithOutputs(t *testing.T) {
	t.Helper()

	val := &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"accountId": structpb.NewStringValue("acct-123"),
				},
			},
		},
	}

	resp := &cerbos.CheckResourcesResponse{
		CheckResourcesResponse: &responsev1.CheckResourcesResponse{
			Results: []*responsev1.CheckResourcesResponse_ResultEntry{
				{
					Resource: &responsev1.CheckResourcesResponse_ResultEntry_Resource{
						Id:   "doc-1",
						Kind: "document",
					},
					Actions: map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW},
					Outputs: []*enginev1.OutputEntry{
						{Src: "headers", Val: val},
					},
				},
			},
		},
	}

	fc := &fakeCerbosChecker{resp: resp}
	client := &cerbosClient{checker: fc}
	principal := cerbos.NewPrincipal("user", "admin")
	allowed, err := client.filterAllowedDocuments(context.Background(), principal, []Document{{ID: "doc-1", AccountID: "acct-123"}}, "acct-123", "read")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(allowed) != 1 {
		t.Fatalf("expected document to be allowed, got %#v", allowed)
	}
}
