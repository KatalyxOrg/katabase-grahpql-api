//go:build integration
// +build integration

package resolver_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/graph"
	"katalyx.fr/katabasegql/graph/resolver"
	"katalyx.fr/katabasegql/internal/authentication"
	"katalyx.fr/katabasegql/internal/user"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
	"katalyx.fr/katabasegql/pkg/errormsg"
	"katalyx.fr/katabasegql/tests/fixtures"
	"katalyx.fr/katabasegql/tests/helpers"
)

// createTestResolver creates a configured resolver for testing
func createTestResolver(db *gorm.DB) (*resolver.Resolver, *config.Config) {
	cfg := &config.Config{
		AddressRepository:                dbmodel.NewAddressRepository(db),
		PermissionRepository:             dbmodel.NewPermissionRepository(db),
		RefreshTokenRepository:           dbmodel.NewRefreshTokenRepository(db),
		RoleRepository:                   dbmodel.NewRoleRepository(db),
		UserPermissionOverrideRepository: dbmodel.NewUserPermissionOverrideRepository(db),
		UserRepository:                   dbmodel.NewUserRepository(db),
	}
	cfg.Constants.JWT.Secret = fixtures.TestJWTSecret
	cfg.Constants.JWT.AccessTokenTTL = 15 * time.Minute
	cfg.Constants.JWT.RefreshTokenTTL = 7 * 24 * time.Hour

	authService := &authentication.AuthenticationService{Config: cfg}
	userService := &user.UsersService{Config: cfg}

	return &resolver.Resolver{
		AuthenticationService: authService,
		UsersService:          userService,
	}, cfg
}

// withAuthenticatedContext loads the full user from DB and adds it to context
func withAuthenticatedContext(ctx context.Context, db *gorm.DB, userID uint) context.Context {
	userRepo := dbmodel.NewUserRepository(db)
	user, err := userRepo.FindByID(userID, &dbmodel.UserFieldsToInclude{
		UserProfile:       true,
		Roles:             true,
		Roles_Permissions: true,
	})
	if err != nil || user == nil {
		// Return context without user if load fails
		return ctx
	}
	return context.WithValue(ctx, authentication.UserCtxKey, user)
}

// createTestSchemaConfig creates a GraphQL config with directives
func createTestSchemaConfig(res *resolver.Resolver) graph.Config {
	c := graph.Config{Resolvers: res}

	// Add hasPermission directive implementation (from server.go)
	c.Directives.HasPermission = func(ctx context.Context, obj interface{}, next graphql.Resolver, permissions []string) (res interface{}, err error) {
		user := authentication.ForContext(ctx)

		if user == nil {
			return nil, &errormsg.UserAccessDeniedError{}
		}

		permissionSet := make(map[string]struct{}, len(permissions))
		for _, permission := range permissions {
			permissionSet[permission] = struct{}{}
		}

		// Check user-level permission overrides first
		for _, override := range user.PermissionOverrides {
			if _, exists := permissionSet[override.Permission.Name]; exists {
				if override.IsGranted {
					return next(ctx) // Override grants permission
				}
				// Override denies permission - continue checking (explicit deny)
			}
		}

		// Check role-based permissions
		for _, role := range user.Roles {
			for _, rolePermission := range role.Permissions {
				if _, exists := permissionSet[rolePermission.Name]; exists {
					return next(ctx)
				}
			}
		}

		return nil, &errormsg.UserAccessDeniedError{}
	}

	return c
}

// createTestClient creates a GraphQL test client with authentication middleware
func createTestClient(schema graphql.ExecutableSchema, cfg *config.Config) *helpers.GraphQLTestClient {
	return helpers.NewGraphQLTestClientWithMiddleware(schema, authentication.Middleware(cfg))
}

// TestLoginMutation tests the GraphQL login mutation with real database
func TestLoginMutation(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("successful login returns user and tokens", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)
		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation Login($input: LoginInput!) {
				login(input: $input) {
					user {
						id
						email
						roles
					}
					token
					refreshToken
					permissions
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    user.Email,
				"password": "User123!",
			},
		}

		ctx := context.Background()
		var response struct {
			Login struct {
				User struct {
					ID    string
					Email string
					Roles []string
				}
				Token        string
				RefreshToken string
				Permissions  []string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)

		require.NoError(t, err)
		assert.NotEmpty(t, response.Login.User.ID)
		assert.Equal(t, user.Email, response.Login.User.Email)
		assert.NotEmpty(t, response.Login.Token)
		assert.NotEmpty(t, response.Login.RefreshToken)
		assert.NotEmpty(t, response.Login.Permissions)
	})

	t.Run("invalid credentials return error", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)
		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation Login($input: LoginInput!) {
				login(input: $input) {
					user { id }
					token
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    user.Email,
				"password": "WrongPassword123!",
			},
		}

		ctx := context.Background()
		var response struct {
			Login struct {
				User struct {
					ID string
				}
				Token string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err, "Invalid credentials should return error")
	})

	t.Run("missing email returns validation error", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		res, _ := createTestResolver(db)
		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation Login($input: LoginInput!) {
				login(input: $input) {
					user { id }
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    "",
				"password": "Password123!",
			},
		}

		ctx := context.Background()
		var response struct {
			Login struct {
				User struct {
					ID string
				}
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err)
	})

	t.Run("login with deleted user fails", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)
		email := user.Email

		// Soft delete user
		db.Delete(&user)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation Login($input: LoginInput!) {
				login(input: $input) {
					user { id }
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    email,
				"password": "User123!",
			},
		}

		ctx := context.Background()
		var response struct {
			Login struct {
				User struct {
					ID string
				}
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err)
	})
}

// TestRefreshTokenMutation tests the GraphQL refreshToken mutation
func TestRefreshTokenMutation(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("valid refresh token returns new tokens", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)

		// Generate valid refresh token
		oldRefreshToken, err := fixtures.GenerateValidRefreshToken(db, user.ID)
		require.NoError(t, err)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation RefreshToken($refreshToken: String!) {
				refreshToken(refreshToken: $refreshToken) {
					token
					refreshToken
				}
			}
		`

		variables := map[string]interface{}{
			"refreshToken": oldRefreshToken,
		}

		ctx := context.Background()
		var response struct {
			RefreshToken struct {
				Token        string
				RefreshToken string
			}
		}

		err = client.MutateWithVariables(ctx, query, variables, &response)

		require.NoError(t, err)
		assert.NotEmpty(t, response.RefreshToken.Token)
		assert.NotEmpty(t, response.RefreshToken.RefreshToken)
		assert.NotEqual(t, oldRefreshToken, response.RefreshToken.RefreshToken)
	})

	t.Run("expired refresh token returns error", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)

		// Generate expired refresh token
		expiredToken, err := fixtures.GenerateExpiredRefreshToken(db, user.ID)
		require.NoError(t, err)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation RefreshToken($refreshToken: String!) {
				refreshToken(refreshToken: $refreshToken) {
					token
				}
			}
		`

		variables := map[string]interface{}{
			"refreshToken": expiredToken,
		}

		ctx := context.Background()
		var response struct {
			RefreshToken struct {
				Token string
			}
		}

		err = client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err)
	})

	t.Run("revoked refresh token returns error", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)

		// Generate revoked refresh token
		revokedToken, err := fixtures.GenerateRevokedRefreshToken(db, user.ID)
		require.NoError(t, err)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation RefreshToken($refreshToken: String!) {
				refreshToken(refreshToken: $refreshToken) {
					token
				}
			}
		`

		variables := map[string]interface{}{
			"refreshToken": revokedToken,
		}

		ctx := context.Background()
		var response struct {
			RefreshToken struct {
				Token string
			}
		}

		err = client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err)
	})

	t.Run("invalid token format returns error", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation RefreshToken($refreshToken: String!) {
				refreshToken(refreshToken: $refreshToken) {
					token
				}
			}
		`

		variables := map[string]interface{}{
			"refreshToken": "invalid-token-format",
		}

		ctx := context.Background()
		var response struct {
			RefreshToken struct {
				Token string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err)
	})

	t.Run("token reuse detection revokes family", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)

		authService := res.AuthenticationService

		// Generate and rotate tokens
		token1, _, err := authService.GenerateRefreshToken(user.ID, "test-agent", "127.0.0.1")
		require.NoError(t, err)

		token2, err := authService.RotateRefreshToken(token1, "test-agent", "127.0.0.1")
		require.NoError(t, err)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation RefreshToken($refreshToken: String!) {
				refreshToken(refreshToken: $refreshToken) {
					token
				}
			}
		`

		// Try to reuse token1 (already rotated)
		variables := map[string]interface{}{
			"refreshToken": token1,
		}

		ctx := context.Background()
		var response struct {
			RefreshToken struct {
				Token string
			}
		}

		err = client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err, "Reused token should be rejected")

		// Verify token2 is also now invalid (family revoked)
		variables2 := map[string]interface{}{
			"refreshToken": token2,
		}

		err = client.MutateWithVariables(ctx, query, variables2, &response)
		assert.Error(t, err, "Token in same family should be revoked")
	})
}

// TestCreateUserMutation tests the GraphQL createUser mutation with RBAC
func TestCreateUserMutation(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("authenticated user can also create user (for admin bulk operations)", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		admin := fixtures.CreateAdminUser(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation CreateUser($input: NewUserInput!) {
				createUser(input: $input) {
					id
					email
					roles
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    "newuser@test.com",
				"password": "NewUser123!",
				"userProfile": map[string]interface{}{
					"firstName": "New",
					"lastName":  "User",
				},
			},
		}

		ctx := withAuthenticatedContext(context.Background(), db, admin.ID)
		var response struct {
			CreateUser struct {
				ID    string
				Email string
				Roles []string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)

		require.NoError(t, err)
		assert.NotEmpty(t, response.CreateUser.ID)
		assert.Equal(t, "newuser@test.com", response.CreateUser.Email)
	})

	t.Run("anyone can create user (registration)", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation CreateUser($input: NewUserInput!) {
				createUser(input: $input) {
					id
					email
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    "newuser@test.com",
				"password": "NewUser123!",
				"userProfile": map[string]interface{}{
					"firstName": "New",
				},
			},
		}

		// No authentication context - public registration
		ctx := context.Background()
		var response struct {
			CreateUser struct {
				ID    string
				Email string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		require.NoError(t, err, "Anyone should be able to register (create user)")
		assert.NotEmpty(t, response.CreateUser.ID)
		assert.Equal(t, "newuser@test.com", response.CreateUser.Email)
	})

	t.Run("unauthenticated user can also create account", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation CreateUser($input: NewUserInput!) {
				createUser(input: $input) {
					id
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    "another@test.com",
				"password": "Another123!",
				"userProfile": map[string]interface{}{
					"firstName": "Another",
				},
			},
		}

		ctx := context.Background() // No auth context - this is intentional for registration
		var response struct {
			CreateUser struct {
				ID string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		require.NoError(t, err, "Registration should work without authentication")
		assert.NotEmpty(t, response.CreateUser.ID)
	})

	t.Run("duplicate email validation works", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		existingUser := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation CreateUser($input: NewUserInput!) {
				createUser(input: $input) {
					id
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    existingUser.Email,
				"password": "NewUser123!",
				"userProfile": map[string]interface{}{
					"firstName": "Duplicate",
				},
			},
		}

		ctx := context.Background()
		var response struct {
			CreateUser struct {
				ID string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err, "Should fail with duplicate email")
	})

	t.Run("password validation enforced", func(t *testing.T) {
		t.Skip("Password validation not yet implemented in AuthenticationService.CreateUser")

		helpers.CleanupTestDB(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation CreateUser($input: NewUserInput!) {
				createUser(input: $input) {
					id
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    "weakpass@test.com",
				"password": "weak",
				"userProfile": map[string]interface{}{
					"firstName": "Weak",
				},
			},
		}

		ctx := context.Background()
		var response struct {
			CreateUser struct {
				ID string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err, "Weak password should be rejected")
	})

	t.Run("created user has default role assigned", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation CreateUser($input: NewUserInput!) {
				createUser(input: $input) {
					id
					roles
				}
			}
		`

		variables := map[string]interface{}{
			"input": map[string]interface{}{
				"email":    "roletest@test.com",
				"password": "RoleTest123!",
				"userProfile": map[string]interface{}{
					"firstName": "Role",
					"lastName":  "Test",
				},
			},
		}

		ctx := context.Background()
		var response struct {
			CreateUser struct {
				ID    string
				Roles []string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)

		require.NoError(t, err)
		assert.NotEmpty(t, response.CreateUser.Roles)
		assert.Equal(t, "user", response.CreateUser.Roles[0])
	})
}

// TestUpdateUserMutation tests the GraphQL updateUser mutation with RBAC
func TestUpdateUserMutation(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("admin can update any user", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		admin := fixtures.CreateAdminUser(db)
		targetUser := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation UpdateUser($id: ID!, $input: UpdateUserInput!) {
				updateUser(id: $id, input: $input) {
					id
					email
				}
			}
		`

		newEmail := "updated@test.com"
		variables := map[string]interface{}{
			"id": fmt.Sprintf("%d", targetUser.ID),
			"input": map[string]interface{}{
				"email": newEmail,
			},
		}

		ctx := withAuthenticatedContext(context.Background(), db, admin.ID)
		var response struct {
			UpdateUser struct {
				ID    string
				Email string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)

		require.NoError(t, err)
		assert.Equal(t, newEmail, response.UpdateUser.Email)
	})

	t.Run("user can update own profile", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateUserWithProfile(db, "Original", "Name", "original@test.com")

		res, cfg := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := createTestClient(schema, cfg)

		// Generate JWT token for the user
		token, _, err := authentication.GenerateToken(cfg.Constants.JWT.Secret, user.ID, 15*time.Minute)
		require.NoError(t, err)

		query := `
			mutation UpdateUser($id: ID!, $input: UpdateUserInput!) {
				updateUser(id: $id, input: $input) {
					id
					userProfile {
						firstName
						lastName
					}
				}
			}
		`

		variables := map[string]interface{}{
			"id": fmt.Sprintf("%d", user.ID),
			"input": map[string]interface{}{
				"userProfile": map[string]interface{}{
					"firstName": "Updated",
					"lastName":  "Name",
				},
			},
		}

		var response struct {
			UpdateUser struct {
				ID          string
				UserProfile struct {
					FirstName string
					LastName  string
				}
			}
		}

		err = client.MutateWithAuth(context.Background(), query, variables, token, &response)

		require.NoError(t, err)
		assert.Equal(t, "Updated", response.UpdateUser.UserProfile.FirstName)
	})

	t.Run("user cannot update other users", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user1 := fixtures.CreateRegularUser(db)
		user2 := fixtures.CreateRegularUser(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			mutation UpdateUser($id: ID!, $input: UpdateUserInput!) {
				updateUser(id: $id, input: $input) {
					id
				}
			}
		`

		variables := map[string]interface{}{
			"id": fmt.Sprintf("%d", user2.ID),
			"input": map[string]interface{}{
				"email": "hacked@test.com",
			},
		}

		ctx := withAuthenticatedContext(context.Background(), db, user1.ID)
		var response struct {
			UpdateUser struct {
				ID string
			}
		}

		err := client.MutateWithVariables(ctx, query, variables, &response)
		assert.Error(t, err, "User should not be able to update other users")
	})

	// Additional test cases...
}

// TestMeQuery tests the GraphQL me query
func TestMeQuery(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("authenticated user can query own profile", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateUserWithProfile(db, "Test", "User", "test@test.com")

		res, cfg := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := createTestClient(schema, cfg)

		// Generate JWT token for the user
		token, _, err := authentication.GenerateToken(cfg.Constants.JWT.Secret, user.ID, 15*time.Minute)
		require.NoError(t, err)

		query := `
			query {
				me {
					id
					email
					userProfile {
						firstName
						lastName
					}
					roles
				}
			}
		`

		var response struct {
			Me struct {
				ID          string
				Email       string
				UserProfile struct {
					FirstName string
					LastName  string
				}
				Roles []string
			}
		}

		err = client.QueryWithAuth(context.Background(), query, token, &response)

		require.NoError(t, err)
		assert.Equal(t, user.Email, response.Me.Email)
		assert.Equal(t, "Test", response.Me.UserProfile.FirstName)
		assert.Equal(t, "User", response.Me.UserProfile.LastName)
	})

	t.Run("unauthenticated request fails", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			query {
				me {
					id
				}
			}
		`

		ctx := context.Background()
		var response struct {
			Me struct {
				ID string
			}
		}

		err := client.Query(ctx, query, &response)
		assert.Error(t, err)
	})

	t.Run("deleted user cannot query me", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)
		userID := user.ID

		// Soft delete user
		db.Delete(&user)

		res, _ := createTestResolver(db)

		schema := graph.NewExecutableSchema(createTestSchemaConfig(res))
		client := helpers.NewGraphQLTestClient(schema)

		query := `
			query {
				me {
					id
				}
			}
		`

		// Try to use context with deleted user
		ctx := withAuthenticatedContext(context.Background(), db, userID)
		var response struct {
			Me *struct {
				ID string
			}
		}

		err := client.Query(ctx, query, &response)
		// Should return error because withAuthenticatedContext will fail to load deleted user,
		// leaving context without user, causing directive to deny access
		assert.Error(t, err, "Deleted user should not be able to query me")
	})
}

// More test sections to follow...
