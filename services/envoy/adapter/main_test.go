package main

import (
	"testing"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	effectv1 "github.com/cerbos/cerbos/api/genpb/cerbos/effect/v1"
	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	responsev1 "github.com/cerbos/cerbos/api/genpb/cerbos/response/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestExtractBearerToken(t *testing.T) {
	t.Run("valid header", func(t *testing.T) {
		token, err := extractBearerToken("Bearer abc.def")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "abc.def" {
			t.Fatalf("unexpected token: %s", token)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		if _, err := extractBearerToken(""); err == nil {
			t.Fatal("expected error for missing header")
		}
	})

	t.Run("invalid scheme", func(t *testing.T) {
		if _, err := extractBearerToken("Basic foo"); err == nil {
			t.Fatal("expected error for invalid scheme")
		}
	})
}

func TestRolesFromClaims(t *testing.T) {
	t.Run("array roles", func(t *testing.T) {
		claims := &adapterClaims{Roles: []any{"admin", "member", "admin"}}
		roles := rolesFromClaims(claims)
		if len(roles) != 2 || roles[0] != "admin" || roles[1] != "member" {
			t.Fatalf("unexpected roles: %#v", roles)
		}
	})

	t.Run("string role and legacy role", func(t *testing.T) {
		claims := &adapterClaims{Roles: "viewer", Role: "editor"}
		roles := rolesFromClaims(claims)
		if len(roles) != 2 || roles[0] != "viewer" || roles[1] != "editor" {
			t.Fatalf("unexpected roles: %#v", roles)
		}
	})
}

func TestUniqueStringsAdapter(t *testing.T) {
	values := uniqueStrings([]string{"", "a", "b", "a"})
	if len(values) != 2 || values[0] != "a" || values[1] != "b" {
		t.Fatalf("unexpected unique strings: %#v", values)
	}
}

func TestBuildResponseHeaders(t *testing.T) {
	outputs := []*enginev1.OutputEntry{
		{
			Src: "headers",
			Val: &structpb.Value{
				Kind: &structpb.Value_StructValue{
					StructValue: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"X-Trace": structpb.NewStringValue("trace-123"),
							"Empty":   structpb.NewStringValue(""),
						},
					},
				},
			},
		},
		{
			Src: "audit",
			Val: structpb.NewStringValue("captured"),
		},
	}

	rr := &cerbos.ResourceResult{
		CheckResourcesResponse_ResultEntry: &responsev1.CheckResourcesResponse_ResultEntry{
			Actions: map[string]effectv1.Effect{"read": effectv1.Effect_EFFECT_ALLOW},
			Outputs: outputs,
		},
	}

	headers := buildResponseHeaders(rr)
	if len(headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(headers))
	}

	headerMap := make(map[string]string, len(headers))
	for _, h := range headers {
		headerMap[h.Header.GetKey()] = h.Header.GetValue()
	}

	if headerMap["x-trace"] != "trace-123" {
		t.Fatalf("missing x-trace header: %#v", headerMap)
	}

	if headerMap[fallbackHeaderKey] != "captured" {
		t.Fatalf("missing fallback header: %#v", headerMap)
	}
}

func TestFlattenValue(t *testing.T) {
	structVal := &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"Foo": structpb.NewStringValue("bar"),
				},
			},
		},
	}
	fields := flattenValue(structVal)
	if len(fields) != 1 || fields["Foo"] != "bar" {
		t.Fatalf("unexpected flattened struct: %#v", fields)
	}

	scalarVal := structpb.NewNumberValue(42)
	scalar := flattenValue(scalarVal)
	if len(scalar) != 1 || scalar[fallbackHeaderKey] != "42" {
		t.Fatalf("unexpected fallback flatten: %#v", scalar)
	}
}

func TestStringifyValue(t *testing.T) {
	if got := stringifyValue(structpb.NewStringValue("value")); got != "value" {
		t.Fatalf("expected string value, got %s", got)
	}
	if got := stringifyValue(structpb.NewNumberValue(3.14)); got != "3.14" {
		t.Fatalf("expected float string, got %s", got)
	}
	if got := stringifyValue(structpb.NewBoolValue(true)); got != "true" {
		t.Fatalf("expected bool string, got %s", got)
	}
	if got := stringifyValue(structpb.NewNullValue()); got != "" {
		t.Fatalf("expected empty string for nil, got %s", got)
	}
	mapVal := &structpb.Value{
		Kind: &structpb.Value_StructValue{
			StructValue: &structpb.Struct{
				Fields: map[string]*structpb.Value{
					"foo": structpb.NewStringValue("bar"),
				},
			},
		},
	}
	if got := stringifyValue(mapVal); got == "" {
		t.Fatal("expected json representation for complex type")
	}
}
