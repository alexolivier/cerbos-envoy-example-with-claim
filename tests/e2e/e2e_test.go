package e2e

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/compose"
)

const (
	fixtureKeyID      = "local-dev-cert"
	jwtAlgorithm      = "RS256"
	envoyAdminMessage = `{"message":"admin access granted"}`
)

type document struct {
	ID        string `json:"id"`
	AccountID string `json:"accountId"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Status    string `json:"status"`
}

type documentListResponse struct {
	AccountID string     `json:"accountID"`
	Documents []document `json:"documents"`
}

type scenario struct {
	name          string
	tokenFixture  string
	path          string
	expectedCode  int
	responseCheck func(t *testing.T, resp *http.Response, body []byte)
}

func TestEnvoyIntegrationScenarios(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	repoRoot := findRepoRoot(t)
	composeFile := filepath.Join(repoRoot, "docker-compose.yaml")

	stack, err := compose.NewDockerComposeWith(
		compose.WithStackFiles(composeFile),
		compose.StackIdentifier("cerbos-envoy-e2e"),
	)
	require.NoError(t, err)

	if err := stack.Down(ctx, compose.RemoveOrphans(true), compose.RemoveVolumes(true)); err != nil {
		t.Logf("warning: initial compose down failed: %v", err)
	}

	t.Cleanup(func() {
		downErr := stack.Down(ctx, compose.RemoveOrphans(true), compose.RemoveVolumes(true))
		if downErr != nil {
			t.Logf("failed to tear down compose stack: %v", downErr)
		}
	})

	require.NoError(t, stack.Up(ctx, compose.Wait(true)))

	waitForEnvoy(t, "http://localhost:18000/healthz", 2*time.Minute)

	tokenCache := map[string]string{}
	for _, fixture := range []string{"alice", "bob", "carol"} {
		tokenCache[fixture] = mintFixtureToken(t, repoRoot, fixture)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	scenarios := []scenario{
		{
			name:         "alice allowed own documents",
			tokenFixture: "alice",
			path:         "/api/acct-123/documents",
			expectedCode: http.StatusOK,
			responseCheck: func(t *testing.T, _ *http.Response, body []byte) {
				assertDocumentsResponse(t, body, "acct-123", []document{
					{
						ID:        "doc-2",
						AccountID: "acct-123",
						Title:     "Team roster",
						Body:      "Contacts for the team assigned to acct-123.",
						Status:    "published",
					},
				})
			},
		},
		{
			name:         "alice denied cross-account documents",
			tokenFixture: "alice",
			path:         "/api/acct-456/documents",
			expectedCode: http.StatusForbidden,
			responseCheck: func(t *testing.T, _ *http.Response, body []byte) {
				require.Equal(t, "access denied", strings.TrimSpace(string(body)))
			},
		},
		{
			name:         "alice denied admin route",
			tokenFixture: "alice",
			path:         "/api/admin",
			expectedCode: http.StatusForbidden,
			responseCheck: func(t *testing.T, _ *http.Response, body []byte) {
				require.Equal(t, "access denied", strings.TrimSpace(string(body)))
			},
		},
		{
			name:         "bob denied other account",
			tokenFixture: "bob",
			path:         "/api/acct-123/documents",
			expectedCode: http.StatusForbidden,
			responseCheck: func(t *testing.T, _ *http.Response, body []byte) {
				require.Equal(t, "access denied", strings.TrimSpace(string(body)))
			},
		},
		{
			name:         "bob allowed own documents but filtered",
			tokenFixture: "bob",
			path:         "/api/acct-456/documents",
			expectedCode: http.StatusOK,
			responseCheck: func(t *testing.T, _ *http.Response, body []byte) {
				assertDocumentsResponse(t, body, "acct-456", []document{})
			},
		},
		{
			name:         "bob denied admin route",
			tokenFixture: "bob",
			path:         "/api/admin",
			expectedCode: http.StatusForbidden,
			responseCheck: func(t *testing.T, _ *http.Response, body []byte) {
				require.Equal(t, "access denied", strings.TrimSpace(string(body)))
			},
		},
		{
			name:         "carol allowed acct-123 documents",
			tokenFixture: "carol",
			path:         "/api/acct-123/documents",
			expectedCode: http.StatusOK,
			responseCheck: func(t *testing.T, _ *http.Response, body []byte) {
				assertDocumentsResponse(t, body, "acct-123", []document{
					{
						ID:        "doc-1",
						AccountID: "acct-123",
						Title:     "Quarterly plan",
						Body:      "Internal roadmap for acct-123.",
						Status:    "draft",
					},
					{
						ID:        "doc-2",
						AccountID: "acct-123",
						Title:     "Team roster",
						Body:      "Contacts for the team assigned to acct-123.",
						Status:    "published",
					},
				})
			},
		},
		{
			name:         "carol allowed acct-456 documents",
			tokenFixture: "carol",
			path:         "/api/acct-456/documents",
			expectedCode: http.StatusOK,
			responseCheck: func(t *testing.T, _ *http.Response, body []byte) {
				assertDocumentsResponse(t, body, "acct-456", []document{
					{
						ID:        "doc-3",
						AccountID: "acct-456",
						Title:     "Budget",
						Body:      "Budget for acct-456.",
						Status:    "archived",
					},
				})
			},
		},
		{
			name:         "carol allowed admin route",
			tokenFixture: "carol",
			path:         "/api/admin",
			expectedCode: http.StatusOK,
			responseCheck: func(t *testing.T, resp *http.Response, body []byte) {
				require.Equal(t, "application/json; charset=utf-8", resp.Header.Get("Content-Type"))
				require.JSONEq(t, envoyAdminMessage, string(body))
			},
		},
	}

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			token := tokenCache[sc.tokenFixture]
			require.NotEmpty(t, token, "token for fixture %s", sc.tokenFixture)

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:18000"+sc.path, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			require.Equal(t, sc.expectedCode, resp.StatusCode, "body: %s", string(body))
			sc.responseCheck(t, resp, body)
		})
	}
}

func assertDocumentsResponse(t *testing.T, body []byte, expectedAccount string, expectedDocs []document) {
	t.Helper()

	var response documentListResponse
	require.NoError(t, json.Unmarshal(body, &response))

	require.Equal(t, expectedAccount, response.AccountID)
	require.Equal(t, expectedDocs, response.Documents)
}

func waitForEnvoy(t *testing.T, url string, timeout time.Duration) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	require.Eventuallyf(
		t,
		func() bool {
			resp, err := client.Get(url)
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			return resp.StatusCode == http.StatusOK
		},
		timeout,
		time.Second,
		"envoy did not become ready at %s within %s",
		url,
		timeout,
	)
}

func mintFixtureToken(t *testing.T, repoRoot, fixture string) string {
	t.Helper()

	header := map[string]string{
		"alg": jwtAlgorithm,
		"kid": fixtureKeyID,
		"typ": "JWT",
	}

	payloadPath := filepath.Join(repoRoot, "tokens", fmt.Sprintf("%s.json", fixture))
	payloadData, err := os.ReadFile(payloadPath)
	require.NoError(t, err, "failed to read payload for %s", fixture)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(payloadData, &payload))

	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)

	payloadJSON, err := json.Marshal(payload)
	require.NoError(t, err)

	headerSegment := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadSegment := base64.RawURLEncoding.EncodeToString(payloadJSON)

	message := []byte(headerSegment + "." + payloadSegment)
	signatureSegment := signJWT(t, repoRoot, message)

	return fmt.Sprintf("%s.%s.%s", headerSegment, payloadSegment, signatureSegment)
}

func signJWT(t *testing.T, repoRoot string, message []byte) string {
	t.Helper()

	keyPath := filepath.Join(repoRoot, "tokens", "jwt-signing.key")
	keyBytes, err := os.ReadFile(keyPath)
	require.NoError(t, err, "failed to read signing key")

	block, _ := pem.Decode(keyBytes)
	require.NotNil(t, block, "failed to decode PEM block from signing key")

	var key *rsa.PrivateKey
	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsed, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		require.NoError(t, parseErr, "failed to parse private key")

		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		require.True(t, ok, "signing key is not an RSA private key")
	}

	hash := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	require.NoError(t, err, "failed to sign JWT")

	return base64.RawURLEncoding.EncodeToString(signature)
}

func findRepoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)

	for {
		configPath := filepath.Join(dir, "docker-compose.yaml")
		info, statErr := os.Stat(configPath)
		if statErr == nil && !info.IsDir() {
			return dir
		}

		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "failed to locate repository root containing docker-compose.yaml")
		dir = parent
	}
}
