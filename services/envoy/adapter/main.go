package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	jwt "github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	gstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultListenAddr = ":9090"
	defaultCerbosAddr = "cerbos:3593"
	cerbosActionRoute = "route"
	jwtAlgRS256       = "RS256"
	jwtKeySetID       = "local-dev-cert"
	fallbackHeaderKey = "output"
)

type adapterClaims struct {
	Roles     any    `json:"roles"`
	Role      string `json:"role"`
	AccountID string `json:"accountId"`
	jwt.RegisteredClaims
}

type adapterServer struct {
	authv3.UnimplementedAuthorizationServer

	cerbosClient *cerbos.GRPCClient
}

func newAdapterServer(client *cerbos.GRPCClient) *adapterServer {
	return &adapterServer{cerbosClient: client}
}

func (s *adapterServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	httpAttrs := req.GetAttributes().GetRequest().GetHttp()
	if httpAttrs == nil {
		return denyResponse(codes.InvalidArgument, "missing HTTP attributes", typev3.StatusCode_BadRequest), nil
	}

	path := httpAttrs.GetPath()
	method := httpAttrs.GetMethod()
	headers := httpAttrs.GetHeaders()

	token, err := extractBearerToken(headers["authorization"])
	if err != nil {
		return denyResponse(codes.Unauthenticated, err.Error(), typev3.StatusCode_Unauthorized), nil
	}

	claims, err := parseJWT(token)
	if err != nil {
		return denyResponse(codes.Unauthenticated, err.Error(), typev3.StatusCode_Unauthorized), nil
	}

	principalID := claims.Subject
	if principalID == "" {
		return denyResponse(codes.Unauthenticated, "token missing subject", typev3.StatusCode_Unauthorized), nil
	}

	roles := rolesFromClaims(claims)
	if len(roles) == 0 {
		return denyResponse(codes.PermissionDenied, "token missing roles claim", typev3.StatusCode_Forbidden), nil
	}

	principal := cerbos.NewPrincipal(principalID, roles...)
	if claims.AccountID != "" {
		principal = principal.WithAttr("accountId", claims.AccountID)
	}
	if err := principal.Validate(); err != nil {
		return denyResponse(codes.InvalidArgument, fmt.Sprintf("invalid principal: %v", err), typev3.StatusCode_BadRequest), nil
	}

	resourceAttrs := map[string]any{
		"path":   path,
		"method": method,
	}
	if accountIDs := accountIDsFromPath(path); len(accountIDs) > 0 {
		resourceAttrs["accountId"] = accountIDs
	}
	if len(headers) > 0 {
		resourceAttrs["headers"] = headers
	}

	resource := cerbos.NewResource("api_gateway", path).WithAttributes(resourceAttrs)
	if err := resource.Validate(); err != nil {
		return denyResponse(codes.InvalidArgument, fmt.Sprintf("invalid resource: %v", err), typev3.StatusCode_BadRequest), nil
	}

	resourceBatch := cerbos.NewResourceBatch().Add(resource, cerbosActionRoute)
	if err := resourceBatch.Validate(); err != nil {
		return denyResponse(codes.InvalidArgument, fmt.Sprintf("invalid resource batch: %v", err), typev3.StatusCode_BadRequest), nil
	}

	cerbosCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	checkResp, err := s.cerbosClient.
		With(cerbos.AuxDataJWT(token, jwtKeySetID)).
		CheckResources(cerbosCtx, principal, resourceBatch)
	if err != nil {
		log.Printf("cerbos check failed: %v", err)
		return denyResponse(codes.Unavailable, "authorization service unavailable", typev3.StatusCode_ServiceUnavailable), nil
	}

	resourceResult := checkResp.GetResource(path)
	if err := resourceResult.Err(); err != nil {
		log.Printf("cerbos response error: %v", err)
		return denyResponse(codes.Internal, "authorization decision unavailable", typev3.StatusCode_ServiceUnavailable), nil
	}

	if resourceResult.IsAllowed(cerbosActionRoute) {
		return allowResponse(buildResponseHeaders(resourceResult)), nil
	}

	return denyResponse(codes.PermissionDenied, "access denied", typev3.StatusCode_Forbidden), nil
}

func parseJWT(token string) (*adapterClaims, error) {
	claims := &adapterClaims{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwtAlgRS256}))

	parsedToken, _, err := parser.ParseUnverified(token, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if alg, _ := parsedToken.Header["alg"].(string); alg != "" && !strings.EqualFold(alg, jwtAlgRS256) {
		return nil, fmt.Errorf("unsupported token algorithm %q", alg)
	}

	if kid, _ := parsedToken.Header["kid"].(string); kid != "" && kid != jwtKeySetID {
		return nil, fmt.Errorf("unexpected token key ID %q", kid)
	}

	return claims, nil
}

func rolesFromClaims(claims *adapterClaims) []string {
	if claims == nil {
		return nil
	}

	var roles []string
	switch v := claims.Roles.(type) {
	case []string:
		roles = append(roles, v...)
	case []any:
		for _, item := range v {
			if str, ok := item.(string); ok && str != "" {
				roles = append(roles, str)
			}
		}
	case string:
		if v != "" {
			roles = append(roles, v)
		}
	}

	if claims.Role != "" {
		roles = append(roles, claims.Role)
	}

	return uniqueStrings(roles)
}

func allowResponse(headers []*corev3.HeaderValueOption) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: gstatus.New(codes.OK, "allowed").Proto(),
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: headers,
			},
		},
	}
}

func denyResponse(code codes.Code, message string, httpStatus typev3.StatusCode) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: gstatus.New(code, message).Proto(),
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: httpStatus},
				Body:   message,
			},
		},
	}
}

func extractBearerToken(header string) (string, error) {
	if header == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", errors.New("invalid authorization header")
	}

	return parts[1], nil
}

func accountIDsFromPath(path string) []string {
	path = strings.SplitN(path, "?", 2)[0]
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if len(segments) >= 3 && segments[0] == "api" {
		return []string{segments[1]}
	}

	return nil
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))

	for _, v := range values {
		if v == "" {
			continue
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	return out
}

func main() {
	listenAddr := defaultListenAddr
	if port := strings.TrimSpace(os.Getenv("PORT")); port != "" {
		if strings.HasPrefix(port, ":") {
			listenAddr = port
		} else {
			listenAddr = ":" + port
		}
	}

	cerbosAddr := strings.TrimSpace(os.Getenv("CERBOS_GRPC_ADDR"))
	if cerbosAddr == "" {
		cerbosAddr = strings.TrimSpace(os.Getenv("CERBOS_ENDPOINT"))
	}
	if cerbosAddr == "" {
		cerbosAddr = defaultCerbosAddr
	}

	cerbosClient, err := cerbos.New(cerbosAddr, cerbos.WithPlaintext(), cerbos.WithConnectTimeout(2*time.Second))
	if err != nil {
		log.Fatalf("failed to create Cerbos client: %v", err)
	}

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, newAdapterServer(cerbosClient))

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("failed to listen on %s: %v", listenAddr, err)
	}

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-shutdownCh
		log.Printf("received signal %s, shutting down", sig)
		grpcServer.GracefulStop()
	}()

	log.Printf("Envoy adapter listening on %s (cerbos=%s)", listenAddr, cerbosAddr)

	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("gRPC server stopped: %v", err)
	}
}

func buildResponseHeaders(rr *cerbos.ResourceResult) []*corev3.HeaderValueOption {
	if rr == nil {
		return nil
	}

	var headers []*corev3.HeaderValueOption
	for _, output := range rr.GetOutputs() {
		fields := flattenValue(output.GetVal())
		for key, value := range fields {
			if value == "" {
				continue
			}

			headers = append(headers, &corev3.HeaderValueOption{
				Header: &corev3.HeaderValue{
					Key:   strings.TrimSpace(strings.ToLower(key)),
					Value: value,
				},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			})
		}
	}

	return headers
}

func flattenValue(val *structpb.Value) map[string]string {
	if val == nil {
		return nil
	}

	switch v := val.Kind.(type) {
	case *structpb.Value_StructValue:
		result := make(map[string]string, len(v.StructValue.GetFields()))
		for key, field := range v.StructValue.GetFields() {
			result[key] = stringifyValue(field)
		}
		return result
	default:
		return map[string]string{fallbackHeaderKey: stringifyValue(val)}
	}
}

func stringifyValue(val *structpb.Value) string {
	if val == nil {
		return ""
	}

	switch val.Kind.(type) {
	case *structpb.Value_StringValue:
		return val.GetStringValue()
	case *structpb.Value_NumberValue:
		return fmt.Sprintf("%v", val.GetNumberValue())
	case *structpb.Value_BoolValue:
		return fmt.Sprintf("%t", val.GetBoolValue())
	default:
		bytes, err := json.Marshal(val.AsInterface())
		if err != nil {
			return ""
		}
		return string(bytes)
	}
}
