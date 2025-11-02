//go:build integration
// +build integration

package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
)

// GraphQLTestClient provides a simple interface for testing GraphQL operations
type GraphQLTestClient struct {
	handler    *handler.Server
	middleware func(http.Handler) http.Handler
}

// NewGraphQLTestClient creates a new test client for the given GraphQL schema
func NewGraphQLTestClient(schema graphql.ExecutableSchema) *GraphQLTestClient {
	srv := handler.NewDefaultServer(schema)
	return &GraphQLTestClient{
		handler: srv,
	}
}

// NewGraphQLTestClientWithMiddleware creates a new test client with middleware
func NewGraphQLTestClientWithMiddleware(schema graphql.ExecutableSchema, middleware func(http.Handler) http.Handler) *GraphQLTestClient {
	srv := handler.NewDefaultServer(schema)
	return &GraphQLTestClient{
		handler:    srv,
		middleware: middleware,
	}
}

// Query executes a GraphQL query and unmarshals the result into the response
func (c *GraphQLTestClient) Query(ctx context.Context, query string, response interface{}) error {
	vars := make(map[string]interface{})
	return c.execute(ctx, query, vars, response)
}

// MutateWithVariables executes a GraphQL mutation with variables
func (c *GraphQLTestClient) MutateWithVariables(ctx context.Context, mutation string, variables map[string]interface{}, response interface{}) error {
	return c.execute(ctx, mutation, variables, response)
}

// QueryWithAuth executes a GraphQL query with an Authorization header
func (c *GraphQLTestClient) QueryWithAuth(ctx context.Context, query string, token string, response interface{}) error {
	vars := make(map[string]interface{})
	return c.executeWithAuth(ctx, query, vars, token, response)
}

// MutateWithAuth executes a GraphQL mutation with an Authorization header
func (c *GraphQLTestClient) MutateWithAuth(ctx context.Context, mutation string, variables map[string]interface{}, token string, response interface{}) error {
	return c.executeWithAuth(ctx, mutation, variables, token, response)
}

// execute performs the actual GraphQL operation
func (c *GraphQLTestClient) execute(ctx context.Context, query string, variables map[string]interface{}, response interface{}) error {
	return c.executeWithAuth(ctx, query, variables, "", response)
}

// executeWithAuth performs the actual GraphQL operation with optional auth token
func (c *GraphQLTestClient) executeWithAuth(ctx context.Context, query string, variables map[string]interface{}, token string, response interface{}) error {
	// Create the GraphQL request payload
	requestPayload := map[string]interface{}{
		"query": query,
	}
	if len(variables) > 0 {
		requestPayload["variables"] = variables
	}

	jsonBytes, err := json.Marshal(requestPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req := httptest.NewRequest("POST", "/query", bytes.NewReader(jsonBytes))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	req = req.WithContext(ctx)

	// Execute request
	w := httptest.NewRecorder()

	// Apply middleware if available
	var h http.Handler = c.handler
	if c.middleware != nil {
		h = c.middleware(h)
	}
	h.ServeHTTP(w, req)

	// Parse response
	var graphqlResponse struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string        `json:"message"`
			Path    []interface{} `json:"path"`
		} `json:"errors"`
	}

	if err := json.NewDecoder(w.Body).Decode(&graphqlResponse); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for GraphQL errors
	if len(graphqlResponse.Errors) > 0 {
		return fmt.Errorf("graphql errors: %v", graphqlResponse.Errors)
	}

	// Unmarshal data into response
	if err := json.Unmarshal(graphqlResponse.Data, response); err != nil {
		return fmt.Errorf("failed to unmarshal response data: %w", err)
	}

	return nil
}
