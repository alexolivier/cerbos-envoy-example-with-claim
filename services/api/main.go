package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
	"github.com/gin-gonic/gin"
)

type Document struct {
	ID        string `json:"id"`
	AccountID string `json:"accountId"`
	Title     string `json:"title"`
	Body      string `json:"body"`
}

var documents = []Document{
	{ID: "doc-1", AccountID: "acct-123", Title: "Quarterly plan", Body: "Internal roadmap for acct-123."},
	{ID: "doc-2", AccountID: "acct-123", Title: "Team roster", Body: "Contacts for the team assigned to acct-123."},
	{ID: "doc-3", AccountID: "acct-456", Title: "Budget", Body: "Budget for acct-456."},
}

type cerbosClient struct {
	client *cerbos.GRPCClient
}

var authzClient = newCerbosClient()

func newCerbosClient() *cerbosClient {
	addr := os.Getenv("CERBOS_GRPC_ADDR")
	if addr == "" {
		addr = os.Getenv("CERBOS_ENDPOINT")
	}
	if addr == "" {
		addr = "cerbos:3593"
	}

	client, err := cerbos.New(addr, cerbos.WithPlaintext(), cerbos.WithConnectTimeout(2*time.Second))
	if err != nil {
		log.Fatalf("failed to create Cerbos client: %v", err)
	}

	return &cerbosClient{client: client}
}

func (c *cerbosClient) filterAllowedDocuments(ctx context.Context, principal *cerbos.Principal, docs []Document, action string) ([]Document, error) {
	if len(docs) == 0 {
		return []Document{}, nil
	}

	resourceBatch := cerbos.NewResourceBatch()
	for _, doc := range docs {
		resource := cerbos.NewResource("document", doc.ID).WithAttributes(map[string]any{
			"accountId": []string{doc.AccountID},
		})

		if err := resource.Validate(); err != nil {
			return nil, fmt.Errorf("invalid resource for document %s: %w", doc.ID, err)
		}

		resourceBatch.Add(resource, action)
	}

	if err := resourceBatch.Validate(); err != nil {
		return nil, fmt.Errorf("invalid resource batch: %w", err)
	}

	checkResp, err := c.client.CheckResources(ctx, principal, resourceBatch)
	if err != nil {
		return nil, fmt.Errorf("authorization check failed: %w", err)
	}

	allowed := make([]Document, 0, len(docs))
	for _, doc := range docs {
		result := checkResp.GetResource(doc.ID)
		if result == nil {
			continue
		}

		if err := result.Err(); err != nil {
			return nil, fmt.Errorf("authorization result error for document %s: %w", doc.ID, err)
		}

		if result.IsAllowed(action) {
			allowed = append(allowed, doc)
		}
	}

	return allowed, nil
}

func main() {
	addr := ":8080"
	if value := os.Getenv("PORT"); value != "" {
		addr = ":" + value
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	router.GET("/api/documents", func(c *gin.Context) {
		principal, err := principalFromHeaders(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		authCtx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		allowedDocs, err := authzClient.filterAllowedDocuments(authCtx, principal, documents, "read")
		if err != nil {
			log.Printf("authorization error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "authorization failure"})
			return
		}

		if accountID := c.GetHeader("x-accountId"); accountID != "" {
			c.Header("x-accountId", accountID)
		}
		mirrorHeadersWithPrefix(c, "x-authz-")
		c.JSON(http.StatusOK, allowedDocs)
	})
	router.GET("/api/:accountID/documents", func(c *gin.Context) {
		accountID := strings.TrimSpace(c.Param("accountID"))
		principal, err := principalFromHeaders(c)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		if headerAccountID := c.GetHeader("x-auth-accountId"); headerAccountID != "" {
			c.Header("x-auth-accountId", headerAccountID)
		}
		mirrorHeadersWithPrefix(c, "x-authz-")

		authCtx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()

		filteredDocs := filterDocumentsByAccountID(accountID)
		allowedDocs, err := authzClient.filterAllowedDocuments(authCtx, principal, filteredDocs, "read")
		if err != nil {
			log.Printf("authorization error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "authorization failure"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"accountID": accountID,
			"documents": allowedDocs,
		})
	})

	router.GET("/openapi.json", func(c *gin.Context) {
		c.File("openapi.json")
	})

	log.Printf("downstream API listening on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func filterDocumentsByAccountID(accountID string) []Document {
	var filtered []Document
	for _, doc := range documents {
		if doc.AccountID == accountID {
			filtered = append(filtered, doc)
		}
	}
	return filtered
}

func mirrorHeadersWithPrefix(c *gin.Context, prefix string) {
	prefix = strings.ToLower(prefix)

	writerHeaders := c.Writer.Header()
	for name, values := range c.Request.Header {
		if !strings.HasPrefix(strings.ToLower(name), prefix) {
			continue
		}

		writerHeaders.Del(name)
		for _, value := range values {
			writerHeaders.Add(name, value)
		}
	}
}

func principalFromHeaders(c *gin.Context) (*cerbos.Principal, error) {
	principalID := strings.TrimSpace(c.GetHeader("x-authz-id"))
	if principalID == "" {
		return nil, errors.New("missing principal id header")
	}

	roles, err := parseRolesHeader(c.GetHeader("x-authz-roles"))
	if err != nil {
		return nil, err
	}

	principal := cerbos.NewPrincipal(principalID, roles...)

	accountID := strings.TrimSpace(c.GetHeader("z-authz-accountId"))
	if accountID == "" {
		accountID = strings.TrimSpace(c.GetHeader("x-authz-accountId"))
	}

	if accountID != "" {
		principal = principal.WithAttributes(map[string]any{
			"accountId": accountID,
		})
	}

	if err := principal.Validate(); err != nil {
		return nil, fmt.Errorf("invalid principal: %w", err)
	}

	return principal, nil
}

func parseRolesHeader(headerValue string) ([]string, error) {
	raw := strings.TrimSpace(headerValue)
	if raw == "" {
		return nil, errors.New("missing roles header")
	}

	var roles []string
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &roles); err != nil {
			return nil, fmt.Errorf("invalid roles header: %w", err)
		}
	} else {
		for _, part := range strings.Split(raw, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				roles = append(roles, part)
			}
		}
	}

	roles = uniqueStrings(roles)
	if len(roles) == 0 {
		return nil, errors.New("no roles provided")
	}

	return roles, nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))

	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		if _, ok := seen[value]; ok {
			continue
		}

		seen[value] = struct{}{}
		result = append(result, value)
	}

	return result
}
