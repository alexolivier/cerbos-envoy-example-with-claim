package main

import (
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

// func (c *cerbosClient) isAllowed(ctx context.Context, principal *cerbos.Principal, resource *cerbos.Resource, action string) (bool, error) {
// 	return c.client.IsAllowed(ctx, principal, resource, action)
// }

func main() {
	addr := ":8080"
	if value := os.Getenv("PORT"); value != "" {
		addr = ":" + value
	}

	newCerbosClient()

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	router.GET("/api/documents", func(c *gin.Context) {
		if accountID := c.GetHeader("x-accountId"); accountID != "" {
			c.Header("x-accountId", accountID)
		}
		mirrorHeadersWithPrefix(c, "x-authz-")
		c.JSON(http.StatusOK, documents)
	})
	router.GET("/api/:accountID/documents", func(c *gin.Context) {
		accountID := strings.TrimSpace(c.Param("accountID"))

		if headerAccountID := c.GetHeader("x-accountId"); headerAccountID != "" {
			c.Header("x-accountId", headerAccountID)
		}
		mirrorHeadersWithPrefix(c, "x-authz-")
		c.JSON(http.StatusOK, gin.H{
			"accountID": accountID,
			"documents": filterDocumentsByAccountID(accountID),
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
