package authentication

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
)

func setupTestConfig(mockUserRepo *MockUserRepository) *config.Config {
	cfg := &config.Config{
		UserRepository: mockUserRepo,
	}
	cfg.Constants.JWT.Secret = testSecret
	cfg.Constants.JWT.AccessTokenTTL = 15 * time.Minute
	cfg.Constants.JWT.RefreshTokenTTL = 7 * 24 * time.Hour
	return cfg
}

func TestMiddleware(t *testing.T) {
	t.Run("valid JWT adds user to context", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		permission := dbmodel.Permission{Name: "read:user:self"}
		role := dbmodel.Role{
			Name:        "user",
			Permissions: []dbmodel.Permission{permission},
		}

		dbUser := createTestUser(123, "test@test.com", nil, []dbmodel.Role{role})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		// Generate a valid token
		token, _, err := GenerateToken(testSecret, 123, 15*time.Minute)
		require.NoError(t, err)

		// Create a test handler that checks for user in context
		var capturedUser *dbmodel.User
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedUser = ForContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		// Create middleware
		middlewareHandler := Middleware(cfg)(testHandler)

		// Create request with Authorization header
		req := httptest.NewRequest("GET", "/graphql", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		// Execute
		middlewareHandler.ServeHTTP(w, req)

		// Verify
		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotNil(t, capturedUser)
		assert.Equal(t, uint(123), capturedUser.ID)
		assert.Equal(t, "test@test.com", capturedUser.Email)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("missing Authorization header allows request without user", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		var capturedUser *dbmodel.User
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedUser = ForContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		middlewareHandler := Middleware(cfg)(testHandler)

		req := httptest.NewRequest("GET", "/graphql", nil)
		// No Authorization header
		w := httptest.NewRecorder()

		middlewareHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Nil(t, capturedUser)
	})

	t.Run("invalid JWT returns 403 Forbidden", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middlewareHandler := Middleware(cfg)(testHandler)

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.Header.Set("Authorization", "Bearer invalid.jwt.token")
		w := httptest.NewRecorder()

		middlewareHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("expired JWT returns 403 Forbidden", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		// Generate an expired token
		expiredToken, _, err := GenerateToken(testSecret, 123, -1*time.Hour)
		require.NoError(t, err)

		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		middlewareHandler := Middleware(cfg)(testHandler)

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)
		w := httptest.NewRecorder()

		middlewareHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("user from token is loaded with roles and permissions", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		permission1 := dbmodel.Permission{Name: "read:user:self"}
		permission2 := dbmodel.Permission{Name: "update:user:self"}
		role := dbmodel.Role{
			Name:        "user",
			Permissions: []dbmodel.Permission{permission1, permission2},
		}

		dbUser := createTestUser(456, "user@test.com", nil, []dbmodel.Role{role})

		mockUserRepo.On("FindByID", uint(456), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		token, _, err := GenerateToken(testSecret, 456, 15*time.Minute)
		require.NoError(t, err)

		var capturedUser *dbmodel.User
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedUser = ForContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		middlewareHandler := Middleware(cfg)(testHandler)

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()

		middlewareHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotNil(t, capturedUser)
		assert.Len(t, capturedUser.Roles, 1)
		assert.Equal(t, "user", capturedUser.Roles[0].Name)
		assert.Len(t, capturedUser.Roles[0].Permissions, 2)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("handles token without Bearer prefix", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		dbUser := createTestUser(789, "test@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(789), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		token, _, err := GenerateToken(testSecret, 789, 15*time.Minute)
		require.NoError(t, err)

		var capturedUser *dbmodel.User
		testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedUser = ForContext(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		middlewareHandler := Middleware(cfg)(testHandler)

		req := httptest.NewRequest("GET", "/graphql", nil)
		req.Header.Set("Authorization", token) // No Bearer prefix
		w := httptest.NewRecorder()

		middlewareHandler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.NotNil(t, capturedUser)
		assert.Equal(t, uint(789), capturedUser.ID)

		mockUserRepo.AssertExpectations(t)
	})
}

func TestWebsocketInitFunc(t *testing.T) {
	t.Run("extracts token from Authorization parameter", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		dbUser := createTestUser(123, "ws@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		token, _, err := GenerateToken(testSecret, 123, 15*time.Minute)
		require.NoError(t, err)

		initPayload := transport.InitPayload{
			"Authorization": "Bearer " + token,
		}

		ctx := context.Background()
		resultCtx, resultPayload, err := WebsocketInitFunc(ctx, initPayload, cfg)

		require.NoError(t, err)
		assert.NotNil(t, resultPayload)

		user := ForContext(resultCtx)
		assert.NotNil(t, user)
		assert.Equal(t, uint(123), user.ID)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("extracts token from lowercase authorization parameter", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		dbUser := createTestUser(456, "ws@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(456), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		token, _, err := GenerateToken(testSecret, 456, 15*time.Minute)
		require.NoError(t, err)

		initPayload := transport.InitPayload{
			"authorization": "Bearer " + token, // lowercase
		}

		ctx := context.Background()
		resultCtx, resultPayload, err := WebsocketInitFunc(ctx, initPayload, cfg)

		require.NoError(t, err)
		assert.NotNil(t, resultPayload)

		user := ForContext(resultCtx)
		assert.NotNil(t, user)
		assert.Equal(t, uint(456), user.ID)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("extracts token from token parameter", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		dbUser := createTestUser(789, "ws@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(789), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		token, _, err := GenerateToken(testSecret, 789, 15*time.Minute)
		require.NoError(t, err)

		initPayload := transport.InitPayload{
			"token": token,
		}

		ctx := context.Background()
		resultCtx, resultPayload, err := WebsocketInitFunc(ctx, initPayload, cfg)

		require.NoError(t, err)
		assert.NotNil(t, resultPayload)

		user := ForContext(resultCtx)
		assert.NotNil(t, user)
		assert.Equal(t, uint(789), user.ID)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("allows connection without token", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		initPayload := transport.InitPayload{}

		ctx := context.Background()
		resultCtx, resultPayload, err := WebsocketInitFunc(ctx, initPayload, cfg)

		require.NoError(t, err)
		assert.NotNil(t, resultPayload)

		user := ForContext(resultCtx)
		assert.Nil(t, user)
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		initPayload := transport.InitPayload{
			"Authorization": "Bearer invalid.token.here",
		}

		ctx := context.Background()
		_, _, err := WebsocketInitFunc(ctx, initPayload, cfg)

		assert.Error(t, err)
	})

	t.Run("loads user with permissions", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		cfg := setupTestConfig(mockUserRepo)

		permission := dbmodel.Permission{Name: "message:read"}
		role := dbmodel.Role{
			Name:        "user",
			Permissions: []dbmodel.Permission{permission},
		}

		dbUser := createTestUser(999, "ws@test.com", nil, []dbmodel.Role{role})

		mockUserRepo.On("FindByID", uint(999), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		token, _, err := GenerateToken(testSecret, 999, 15*time.Minute)
		require.NoError(t, err)

		initPayload := transport.InitPayload{
			"Authorization": token,
		}

		ctx := context.Background()
		resultCtx, _, err := WebsocketInitFunc(ctx, initPayload, cfg)

		require.NoError(t, err)

		user := ForContext(resultCtx)
		assert.NotNil(t, user)
		assert.Len(t, user.Roles, 1)
		assert.Len(t, user.Roles[0].Permissions, 1)
		assert.Equal(t, "message:read", user.Roles[0].Permissions[0].Name)

		mockUserRepo.AssertExpectations(t)
	})
}

func TestForContext(t *testing.T) {
	t.Run("retrieves user from context", func(t *testing.T) {
		expectedUser := createTestUser(123, "test@test.com", nil, []dbmodel.Role{})

		ctx := context.WithValue(context.Background(), UserCtxKey, expectedUser)

		user := ForContext(ctx)

		assert.NotNil(t, user)
		assert.Equal(t, expectedUser.ID, user.ID)
		assert.Equal(t, expectedUser.Email, user.Email)
	})

	t.Run("returns nil when no user in context", func(t *testing.T) {
		ctx := context.Background()

		user := ForContext(ctx)

		assert.Nil(t, user)
	})

	t.Run("returns nil when context value is not a user", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), UserCtxKey, "not-a-user")

		user := ForContext(ctx)

		assert.Nil(t, user)
	})
}
