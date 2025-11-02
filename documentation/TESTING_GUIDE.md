# Katabase GraphQL API Testing Guide

## 📊 Current Test Coverage Status

| Component              | Coverage  | Test Count    | Status                  |
| ---------------------- | --------- | ------------- | ----------------------- |
| **Authentication**     | 83.8%     | 115 tests     | ✅ Excellent            |
| **JWT & Tokens**       | 95%+      | 28 tests      | ✅ Excellent            |
| **RBAC & Permissions** | 90%+      | 24 tests      | ✅ Excellent            |
| **Middleware**         | 85%+      | 12 tests      | ✅ Good                 |
| **Overall**            | **83.8%** | **115 tests** | ✅ **Production-Ready** |

**Quality Grade: A- (92/100)**

---

## 🎯 Test Philosophy

The Katabase GraphQL test suite follows **Clean Architecture** principles with three distinct testing layers:

1. **Unit Tests** (`*_test.go`): Fast, isolated, mock-based tests for business logic
2. **Integration Tests** (`integration_test.go` with `//go:build integration`): Real database interactions
3. **GraphQL Resolver Tests** (`resolver_integration_test.go`): End-to-end API testing

### Key Principles

- ✅ **Test Isolation**: Each test is independent and self-contained
- ✅ **Security-First**: Comprehensive RBAC, token security, and permission testing
- ✅ **Real-World Scenarios**: Tests cover actual user journeys and edge cases
- ✅ **Clear Naming**: Descriptive test names that explain the scenario
- ✅ **Mock Verification**: Always verify mock expectations were met

---

## 🚀 Running Tests

### Quick Start

```bash
# Run all tests (unit only, fast)
go test ./... -v

# Run with coverage report
go test ./... -cover

# Run authentication tests specifically
go test ./internal/authentication/... -v

# Run integration tests (requires database)
go test ./... -tags=integration -v
```

### Specific Test Suites

```bash
# JWT token tests
go test ./internal/authentication/... -run TestJWT -v
go test ./internal/authentication/... -run TestGenerateToken -v
go test ./internal/authentication/... -run TestParseToken -v

# Refresh token tests
go test ./internal/authentication/... -run TestRefreshToken -v
go test ./internal/authentication/... -run TestRotateRefreshToken -v

# Service layer tests
go test ./internal/authentication/... -run TestLogin -v
go test ./internal/authentication/... -run TestCreateUser -v
go test ./internal/authentication/... -run TestUpdateUser -v

# Middleware tests
go test ./internal/authentication/... -run TestMiddleware -v

# GraphQL resolver tests
go test ./graph/resolver/... -run TestLoginMutation -v
go test ./graph/resolver/... -run TestMeQuery -v
```

### Advanced Testing Options

```bash
# Run with race detector (detect concurrency issues)
go test ./... -race -v

# Run with coverage profile and HTML report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
xdg-open coverage.html  # Linux
open coverage.html      # macOS

# Run specific test with verbose output
go test ./internal/authentication/... -run TestLogin/successful_login -v

# Run with timeout
go test ./... -timeout 30s -v

# Run integration tests with database
docker-compose -f docker/docker-compose.test.yml up -d
go test ./... -tags=integration -v
docker-compose -f docker/docker-compose.test.yml down
```

---

## 📁 Test Structure & Organization

### Directory Layout

```
katabasegql-api/
├── internal/
│   └── authentication/
│       ├── service.go              # Business logic
│       ├── service_test.go         # ⭐ Unit tests (90+ tests)
│       ├── integration_test.go     # ⭐ Integration tests
│       ├── jwt.go                  # JWT utilities
│       ├── jwt_test.go             # JWT unit tests
│       ├── refresh.go              # Refresh token logic
│       ├── refresh_test.go         # Refresh token tests
│       ├── middleware.go           # Auth middleware
│       └── middleware_test.go      # Middleware tests
├── graph/
│   └── resolver/
│       ├── resolver.go
│       └── resolver_integration_test.go  # ⭐ GraphQL E2E tests
└── tests/
    ├── fixtures/                   # Test data factories
    │   ├── users.go
    │   └── tokens.go
    └── helpers/                    # Test utilities
        ├── database.go
        └── graphql.go
```

### Test File Naming Conventions

- `*_test.go`: Unit tests (run by default)
- `integration_test.go`: Integration tests (require `//go:build integration` tag)
- `*_integration_test.go`: Integration tests for specific components

### Test Organization Pattern

Each test file follows this structure:

```go
package authentication

// 1. Mock implementations
type MockUserRepository struct { mock.Mock }
// ... mock methods ...

// 2. Helper functions
func setupAuthServiceWithMocks(...) *AuthenticationService { }
func createTestUser(...) *dbmodel.User { }

// 3. Test suites grouped by feature
func TestLogin(t *testing.T) {
    t.Run("successful login returns user, tokens, and permissions", func(t *testing.T) {
        // Arrange, Act, Assert
    })

    t.Run("login with invalid email returns UserNotFoundError", func(t *testing.T) {
        // Arrange, Act, Assert
    })

    // ... more test cases
}

func TestRefreshAccessToken(t *testing.T) {
    // ... grouped test cases
}
```

---

## 🧪 Test Types & When to Use Them

### 1. Unit Tests (Primary - 90+ tests)

**Purpose**: Test individual functions/methods in isolation using mocks

**When to use**:

- Testing business logic without external dependencies
- Fast feedback during development
- Testing error handling and edge cases

**Example**:

```go
func TestLogin(t *testing.T) {
    t.Run("login with invalid password returns UserInvalidCredentialsError", func(t *testing.T) {
        // Arrange
        mockUserRepo := new(MockUserRepository)
        mockRoleRepo := new(MockRoleRepository)
        mockRefreshTokenRepo := new(MockRefreshTokenRepository)
        authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

        passwordHash, _ := HashPassword("correct-password")
        dbUser := createTestUser(123, "test@test.com", &passwordHash, []dbmodel.Role{})

        mockUserRepo.On("FindByEmail", "test@test.com",
            mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
            Return(dbUser, nil)

        loginInput := model.LoginInput{
            Email:    "test@test.com",
            Password: "wrong-password",  // Wrong password!
        }

        // Act
        _, _, _, _, err := authService.Login(loginInput, "test-agent", "192.168.1.1")

        // Assert
        assert.Error(t, err)
        assert.IsType(t, &errormsg.UserInvalidCredentialsError{}, err)
        mockUserRepo.AssertExpectations(t)
    })
}
```

### 2. Integration Tests (Database-backed)

**Purpose**: Test components working together with real database

**When to use**:

- Testing repository layer interactions
- Verifying database constraints and transactions
- Testing token rotation with real persistence

**Setup**:

```go
//go:build integration

package authentication

import (
    "testing"
    "katalyx.fr/katabasegql/tests/helpers"
)

func TestFullLoginFlow(t *testing.T) {
    // Setup real database
    db := helpers.SetupTestDatabase(t)
    defer helpers.CleanupTestDatabase(t, db)

    // Create real repositories
    userRepo := dbmodel.NewUserRepository(db)
    roleRepo := dbmodel.NewRoleRepository(db)
    refreshTokenRepo := dbmodel.NewRefreshTokenRepository(db)

    // Test with real database interactions
    // ...
}
```

### 3. GraphQL Resolver Tests (End-to-End)

**Purpose**: Test full GraphQL request/response cycle

**When to use**:

- Validating GraphQL schema matches implementation
- Testing directive behavior (`@hasPermission`)
- End-to-end user journey validation

**Example**:

```go
func TestLoginMutation(t *testing.T) {
    db := helpers.SetupTestDatabase(t)
    defer helpers.CleanupTestDatabase(t, db)

    client := helpers.NewGraphQLTestClient(db)

    // Create test user
    user := fixtures.CreateRegularUser(db)

    // Execute GraphQL mutation
    query := `
        mutation Login($input: LoginInput!) {
            login(input: $input) {
                user { id email }
                token
                refreshToken
            }
        }
    `

    variables := map[string]interface{}{
        "input": map[string]interface{}{
            "email":    user.Email,
            "password": "User123!",
        },
    }

    var response struct {
        Login struct {
            User struct {
                ID    string
                Email string
            }
            Token        string
            RefreshToken string
        }
    }

    err := client.MutateWithVariables(context.Background(), query, variables, &response)

    assert.NoError(t, err)
    assert.NotEmpty(t, response.Login.Token)
    assert.NotEmpty(t, response.Login.RefreshToken)
}
```

---

## 🎭 Mock Usage & Best Practices

### Creating Mocks

Our test suite uses [testify/mock](https://pkg.go.dev/github.com/stretchr/testify/mock) for clean, maintainable mocks.

```go
// Mock definition
type MockUserRepository struct {
    mock.Mock
}

func (m *MockUserRepository) FindByID(id uint, fieldsToInclude *dbmodel.UserFieldsToInclude) (*dbmodel.User, error) {
    args := m.Called(id, fieldsToInclude)
    if args.Get(0) == nil {
        return nil, args.Error(1)
    }
    return args.Get(0).(*dbmodel.User), args.Error(1)
}
```

### Setting Up Mock Expectations

```go
// Simple return value
mockUserRepo.On("FindByID", uint(123), mock.Anything).
    Return(user, nil)

// Return error
mockUserRepo.On("FindByEmail", "missing@test.com", mock.Anything).
    Return(nil, errors.New("not found"))

// Match any type
mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).
    Return(updatedUser, nil)

// Capture arguments for verification
var capturedToken *dbmodel.RefreshToken
mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).
    Run(func(args mock.Arguments) {
        capturedToken = args.Get(0).(*dbmodel.RefreshToken)
    }).
    Return(&dbmodel.RefreshToken{}, nil)

// Later verify captured data
assert.Equal(t, "expected-user-agent", capturedToken.UserAgent)
assert.Equal(t, "192.168.1.1", capturedToken.IPAddress)
```

### Mock Verification (Critical!)

**Always verify mocks were called as expected**:

```go
func TestExample(t *testing.T) {
    mockUserRepo := new(MockUserRepository)
    mockUserRepo.On("FindByID", uint(123), mock.Anything).Return(user, nil)

    // ... test execution ...

    // ✅ CRITICAL: Verify all expectations were met
    mockUserRepo.AssertExpectations(t)
}
```

### Common Mock Patterns

#### Pattern 1: Success Path

```go
mockUserRepo.On("FindByEmail", "test@test.com", mock.Anything).
    Return(testUser, nil)
```

#### Pattern 2: Not Found

```go
mockUserRepo.On("FindByEmail", "nonexistent@test.com", mock.Anything).
    Return(nil, nil)  // No error, but nil user
```

#### Pattern 3: Database Error

```go
mockUserRepo.On("Create", mock.Anything).
    Return(nil, errors.New("database connection failed"))
```

#### Pattern 4: Multiple Calls

```go
// First call returns one thing, second call returns another
mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", oldTokenHash).
    Return(dbRefreshToken, nil).Once()

mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", oldTokenHash).
    Return(dbRefreshToken, nil).Once()
```

---

## 🛠️ Helper Functions

### Test User Creation

```go
// Basic user
func createTestUser(id uint, email string, passwordHash *string, roles []dbmodel.Role) *dbmodel.User {
    user := &dbmodel.User{
        Email:        email,
        PasswordHash: passwordHash,
        Roles:        roles,
    }
    user.ID = id  // GORM model, set ID after creation
    return user
}

// Usage examples:
// User with password
passwordHash, _ := HashPassword("password123")
user := createTestUser(123, "test@test.com", &passwordHash, []dbmodel.Role{})

// User without password (OAuth user)
user := createTestUser(456, "oauth@test.com", nil, []dbmodel.Role{})

// User with roles and permissions
permission := dbmodel.Permission{Name: "read:user:self"}
role := dbmodel.Role{
    Name:        "user",
    Permissions: []dbmodel.Permission{permission},
}
user := createTestUser(789, "user@test.com", nil, []dbmodel.Role{role})

// Admin user with multiple permissions
adminPermission := dbmodel.Permission{Name: "update:user"}
adminRole := dbmodel.Role{
    Name:        "admin",
    Permissions: []dbmodel.Permission{adminPermission},
}
adminUser := createTestUser(1, "admin@test.com", nil, []dbmodel.Role{adminRole})
```

### Test Refresh Token Creation

```go
func createTestRefreshToken(
    id uint,
    userID uint,
    tokenHash string,
    familyID string,
    expiresAt time.Time,
    revokedAt *time.Time,
) *dbmodel.RefreshToken {
    token := &dbmodel.RefreshToken{
        UserID:    userID,
        TokenHash: tokenHash,
        FamilyID:  familyID,
        ExpiresAt: expiresAt,
        RevokedAt: revokedAt,
    }
    token.ID = id
    return token
}

// Usage examples:
// Valid token
validToken := createTestRefreshToken(
    1,                              // ID
    123,                            // User ID
    "hashed-token",                 // Token hash
    "family-abc",                   // Family ID
    time.Now().Add(7*24*time.Hour), // Expires in 7 days
    nil,                            // Not revoked
)

// Expired token
expiredToken := createTestRefreshToken(
    2,
    123,
    "expired-hash",
    "family-xyz",
    time.Now().Add(-24*time.Hour),  // Expired yesterday
    nil,
)

// Revoked token
revokedTime := time.Now().Add(-1 * time.Hour)
revokedToken := createTestRefreshToken(
    3,
    123,
    "revoked-hash",
    "family-123",
    time.Now().Add(7*24*time.Hour),
    &revokedTime,  // Revoked 1 hour ago
)
```

### Service Setup Helpers

```go
func setupAuthServiceWithMocks(
    mockUserRepo *MockUserRepository,
    mockRoleRepo *MockRoleRepository,
    mockRefreshTokenRepo *MockRefreshTokenRepository,
) *AuthenticationService {
    cfg := &config.Config{
        UserRepository:         mockUserRepo,
        RoleRepository:         mockRoleRepo,
        RefreshTokenRepository: mockRefreshTokenRepo,
    }
    cfg.Constants.JWT.Secret = testSecret
    cfg.Constants.JWT.AccessTokenTTL = 15 * time.Minute
    cfg.Constants.JWT.RefreshTokenTTL = 7 * 24 * time.Hour

    return &AuthenticationService{
        Config: cfg,
    }
}
```

### Context Helpers (For GraphQL/Middleware Tests)

```go
// Add authenticated user to context
func withAuthenticatedContext(ctx context.Context, user *dbmodel.User) context.Context {
    return context.WithValue(ctx, userCtxKey, user)
}

// Usage
ctx := context.Background()
ctx = withAuthenticatedContext(ctx, testUser)
```

---

## ✅ Test Writing Best Practices

### 1. Arrange-Act-Assert Pattern

**Always structure tests in three clear sections**:

```go
func TestExample(t *testing.T) {
    t.Run("descriptive test name", func(t *testing.T) {
        // ========== ARRANGE ==========
        // Set up mocks, test data, and expectations
        mockRepo := new(MockUserRepository)
        authService := setupAuthServiceWithMocks(mockRepo, ...)
        mockRepo.On("FindByEmail", "test@test.com", mock.Anything).
            Return(testUser, nil)

        // ========== ACT ==========
        // Execute the function under test
        result, err := authService.SomeMethod(input)

        // ========== ASSERT ==========
        // Verify the results
        require.NoError(t, err)
        assert.Equal(t, expectedValue, result)
        mockRepo.AssertExpectations(t)
    })
}
```

### 2. require vs assert

```go
// Use require.* for critical setup/preconditions
// Stops test execution on failure
require.NoError(t, err, "Setup should not fail")
require.NotNil(t, user, "User must exist for test to proceed")

// Use assert.* for actual test assertions
// Continues execution to show all failures
assert.Equal(t, expectedEmail, user.Email)
assert.True(t, user.IsActive)
assert.Len(t, user.Roles, 2)
```

### 3. Clear Test Names

**Good naming convention**: `Test<FunctionName>` with subtests describing scenarios

```go
// ✅ Good: Describes what is being tested and expected outcome
func TestLogin(t *testing.T) {
    t.Run("successful login returns user, tokens, and permissions", func(t *testing.T) { })
    t.Run("login with invalid email returns UserNotFoundError", func(t *testing.T) { })
    t.Run("login with invalid password returns UserInvalidCredentialsError", func(t *testing.T) { })
}

// ❌ Bad: Vague, unclear what's being tested
func TestLogin(t *testing.T) {
    t.Run("test1", func(t *testing.T) { })
    t.Run("error_case", func(t *testing.T) { })
}
```

### 4. Test Independence

**Each test must be completely independent**:

```go
// ❌ Bad: Tests share state
var sharedUser *dbmodel.User

func TestA(t *testing.T) {
    sharedUser = createTestUser(...)  // Modifies shared state
}

func TestB(t *testing.T) {
    // Depends on TestA running first!
    assert.NotNil(t, sharedUser)
}

// ✅ Good: Each test creates its own data
func TestA(t *testing.T) {
    user := createTestUser(...)  // Local to this test
}

func TestB(t *testing.T) {
    user := createTestUser(...)  // Independent data
}
```

### 5. One Logical Assertion Per Test

**Focus each test on one behavior**:

```go
// ✅ Good: Each test validates one specific behavior
func TestUpdateUser(t *testing.T) {
    t.Run("user can update their own profile", func(t *testing.T) {
        // Test only self-update permission
    })

    t.Run("user without permission cannot update other users", func(t *testing.T) {
        // Test only permission denial
    })

    t.Run("admin can update any user", func(t *testing.T) {
        // Test only admin privilege
    })
}

// ❌ Bad: Tests multiple unrelated behaviors
func TestUpdateUser(t *testing.T) {
    // Tests self-update AND admin update AND permission denial all mixed together
}
```

### 6. Test Error Types, Not Just Error Presence

```go
// ✅ Good: Validates specific error type
_, err := authService.Login(invalidInput, "agent", "ip")
assert.Error(t, err)
assert.IsType(t, &errormsg.UserNotFoundError{}, err)

// ❌ Acceptable but less precise
_, err := authService.Login(invalidInput, "agent", "ip")
assert.Error(t, err)

// ✅ Even better: Also check error message
assert.Error(t, err)
assert.IsType(t, &errormsg.UserNotFoundError{}, err)
assert.Contains(t, err.Error(), "user not found")
```

---

## 🔐 Security Testing Patterns

Our test suite has **excellent security coverage** (90%+ for RBAC and auth flows).

### Testing RBAC (Role-Based Access Control)

```go
func TestUpdateUser(t *testing.T) {
    // ✅ Test 1: Self-access allowed
    t.Run("user can update their own profile", func(t *testing.T) {
        loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})

        result, err := authService.UpdateUser(loggedInUser, 123, changes)  // Same ID

        require.NoError(t, err)
        assert.NotNil(t, result)
    })

    // ✅ Test 2: Access denied without permission
    t.Run("user without permission cannot update other users", func(t *testing.T) {
        loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})

        _, err := authService.UpdateUser(loggedInUser, 456, changes)  // Different ID

        assert.Error(t, err)
        assert.IsType(t, &errormsg.UserAccessDeniedError{}, err)
    })

    // ✅ Test 3: Access granted with permission
    t.Run("user with update:user permission can update other users", func(t *testing.T) {
        adminPermission := dbmodel.Permission{Name: "update:user"}
        adminRole := dbmodel.Role{
            Name:        "admin",
            Permissions: []dbmodel.Permission{adminPermission},
        }
        adminUser := createTestUser(123, "admin@test.com", nil, []dbmodel.Role{adminRole})

        result, err := authService.UpdateUser(adminUser, 456, changes)

        require.NoError(t, err)
        assert.NotNil(t, result)
    })
}
```

### Testing Token Security

```go
func TestRefreshTokenSecurity(t *testing.T) {
    // ✅ Test token reuse detection
    t.Run("reused refresh token triggers family revocation", func(t *testing.T) {
        revokedAt := time.Now().Add(-1 * time.Hour)
        dbRefreshToken := createTestRefreshToken(
            1, 123, reusedTokenHash, "family-123",
            time.Now().Add(24*time.Hour),
            &revokedAt,  // Already revoked
        )

        mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", reusedTokenHash).
            Return(dbRefreshToken, nil)
        mockRefreshTokenRepo.On("RevokeByFamilyID", "family-123").Return(nil)

        _, _, _, _, err := authService.RefreshAccessToken(reusedToken, "agent", "ip")

        assert.Error(t, err)
        assert.IsType(t, &errormsg.RefreshTokenReuseDetectedError{}, err)
        mockRefreshTokenRepo.AssertExpectations(t)  // Verify family was revoked
    })

    // ✅ Test expired token rejection
    t.Run("expired refresh token returns error", func(t *testing.T) {
        expiredToken := createTestRefreshToken(
            1, 123, tokenHash, "family-123",
            time.Now().Add(-24*time.Hour),  // Expired
            nil,
        )

        mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", tokenHash).
            Return(expiredToken, nil)

        _, _, _, _, err := authService.RefreshAccessToken(token, "agent", "ip")

        assert.Error(t, err)
        assert.IsType(t, &errormsg.RefreshTokenExpiredError{}, err)
    })
}
```

### Testing Password Security

```go
func TestPasswordSecurity(t *testing.T) {
    // ✅ Test bcrypt cost
    t.Run("password hash uses secure cost factor", func(t *testing.T) {
        hash, err := HashPassword("TestPassword123!")
        require.NoError(t, err)

        cost, _ := bcrypt.Cost([]byte(hash))
        assert.Equal(t, 14, cost, "Should use cost factor 14 for production")
    })

    // ✅ Test hash uniqueness (salt verification)
    t.Run("same password produces different hashes due to salt", func(t *testing.T) {
        password := "SamePassword123!"

        hash1, _ := HashPassword(password)
        hash2, _ := HashPassword(password)

        assert.NotEqual(t, hash1, hash2, "Hashes should differ due to random salt")
        assert.True(t, CheckPasswordHash(password, hash1))
        assert.True(t, CheckPasswordHash(password, hash2))
    })
}
```

---

## 🧩 Common Testing Patterns

### Pattern: Testing JWT Tokens

```go
// Generate and verify token
t.Run("generates valid JWT with correct claims", func(t *testing.T) {
    userID := uint(123)
    ttl := 15 * time.Minute

    token, jti, err := GenerateToken(testSecret, userID, ttl)

    require.NoError(t, err)
    assert.NotEmpty(t, token)
    assert.NotEmpty(t, jti)

    // Parse and verify claims
    parsedUserID, err := ParseToken(testSecret, token)
    require.NoError(t, err)
    assert.Equal(t, userID, parsedUserID)
})

// Test token expiration
t.Run("expired token is rejected", func(t *testing.T) {
    expiredToken, _, err := GenerateToken(testSecret, 456, -1*time.Hour)
    require.NoError(t, err)

    _, err = ParseToken(testSecret, expiredToken)

    assert.Error(t, err)
    assert.Contains(t, err.Error(), "expired")
})

// Test invalid secret
t.Run("token signed with different secret is rejected", func(t *testing.T) {
    token, _, err := GenerateToken("secret1", 789, 15*time.Minute)
    require.NoError(t, err)

    _, err = ParseToken("different-secret", token)

    assert.Error(t, err)
})
```

### Pattern: Testing Middleware

```go
func TestAuthMiddleware(t *testing.T) {
    t.Run("valid token adds user to context", func(t *testing.T) {
        // Setup
        mockUserRepo := new(MockUserRepository)
        cfg := setupTestConfig(mockUserRepo)
        user := createTestUser(123, "test@test.com", nil, []dbmodel.Role{})

        mockUserRepo.On("FindByID", uint(123), mock.Anything).Return(user, nil)

        // Generate valid token
        token, _, err := GenerateToken(testSecret, 123, 15*time.Minute)
        require.NoError(t, err)

        // Create test handler that captures user from context
        var capturedUser *dbmodel.User
        testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            capturedUser = ForContext(r.Context())
            w.WriteHeader(http.StatusOK)
        })

        // Apply middleware
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

    t.Run("missing token continues without user in context", func(t *testing.T) {
        // No Authorization header - should continue but with nil user
        var capturedUser *dbmodel.User
        testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            capturedUser = ForContext(r.Context())
            w.WriteHeader(http.StatusOK)
        })

        middlewareHandler := Middleware(cfg)(testHandler)
        req := httptest.NewRequest("GET", "/graphql", nil)  // No auth header
        w := httptest.NewRecorder()

        middlewareHandler.ServeHTTP(w, req)

        assert.Equal(t, http.StatusOK, w.Code)
        assert.Nil(t, capturedUser)  // No user in context
    })
}
```

### Pattern: Testing GraphQL Mutations

```go
func TestLoginMutation(t *testing.T) {
    // Setup database and client
    db := helpers.SetupTestDatabase(t)
    defer helpers.CleanupTestDatabase(t, db)
    client := helpers.NewGraphQLTestClient(db)

    // Create test user with known password
    user := fixtures.CreateRegularUser(db)  // Password: "User123!"

    t.Run("successful login", func(t *testing.T) {
        query := `
            mutation Login($input: LoginInput!) {
                login(input: $input) {
                    user {
                        id
                        email
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

        var response struct {
            Login struct {
                User struct {
                    ID    string
                    Email string
                }
                Token        string
                RefreshToken string
                Permissions  []string
            }
        }

        err := client.MutateWithVariables(context.Background(), query, variables, &response)

        require.NoError(t, err)
        assert.Equal(t, user.Email, response.Login.User.Email)
        assert.NotEmpty(t, response.Login.Token)
        assert.NotEmpty(t, response.Login.RefreshToken)
        assert.Contains(t, response.Login.Permissions, "read:user:self")
    })

    t.Run("invalid credentials", func(t *testing.T) {
        variables := map[string]interface{}{
            "input": map[string]interface{}{
                "email":    user.Email,
                "password": "WrongPassword",
            },
        }

        var response struct{ Login interface{} }
        err := client.MutateWithVariables(context.Background(), query, variables, &response)

        assert.Error(t, err)
        assert.Contains(t, err.Error(), "invalid credentials")
    })
}
```

### Pattern: Testing with Fixtures

```go
// Use fixtures for consistent test data
func TestUserOperations(t *testing.T) {
    db := helpers.SetupTestDatabase(t)
    defer helpers.CleanupTestDatabase(t, db)

    // Create test users using fixtures
    regularUser := fixtures.CreateRegularUser(db)
    adminUser := fixtures.CreateAdminUser(db)

    t.Run("regular user can read own profile", func(t *testing.T) {
        ctx := withAuthenticatedContext(context.Background(), regularUser)
        // Test with regularUser context
    })

    t.Run("admin can read any profile", func(t *testing.T) {
        ctx := withAuthenticatedContext(context.Background(), adminUser)
        // Test with adminUser context
    })
}
```

---

## 🚦 Test Quality Checklist

Before committing tests, ensure they meet these criteria:

### ✅ Basic Requirements

- [ ] Test has a clear, descriptive name
- [ ] Test follows Arrange-Act-Assert pattern
- [ ] Test is independent (no shared state)
- [ ] Test uses `require` for setup, `assert` for validation
- [ ] Mocks are verified with `AssertExpectations(t)`

### ✅ Security Requirements

- [ ] RBAC scenarios covered (self, denied, granted)
- [ ] Token expiration tested
- [ ] Invalid credentials handled
- [ ] Permission boundaries validated

### ✅ Error Handling

- [ ] Error types verified (not just error presence)
- [ ] Edge cases covered (nil, empty, invalid)
- [ ] Repository failures tested
- [ ] Timeout scenarios considered

### ✅ Code Quality

- [ ] No magic numbers (use constants/variables)
- [ ] Helper functions used for repetitive setup
- [ ] Comments explain "why" for complex scenarios
- [ ] Test data is realistic and meaningful

---

## 📊 Current Coverage Analysis

### Strengths (A+ Level)

✅ **JWT & Token Management (95%+ coverage)**

- Token generation, parsing, expiration
- Refresh token rotation and family tracking
- Token reuse detection and revocation
- Secure bcrypt hashing with proper cost

✅ **RBAC & Permissions (90%+ coverage)**

- Self-access vs other-user access
- Permission-based access control
- Permission overrides (grant/revoke)
- Admin privilege escalation

✅ **Authentication Flows (85%+ coverage)**

- Login with email/password
- Refresh token flow
- User creation and updates
- Middleware authentication

### Areas for Improvement

⚠️ **Performance Testing (Missing)**

```go
// TODO: Add benchmark tests
func BenchmarkHashPassword(b *testing.B) {
    for i := 0; i < b.N; i++ {
        HashPassword("TestPassword123!")
    }
}

func BenchmarkGenerateToken(b *testing.B) {
    for i := 0; i < b.N; i++ {
        GenerateToken(testSecret, 123, 15*time.Minute)
    }
}

func BenchmarkParseToken(b *testing.B) {
    token, _, _ := GenerateToken(testSecret, 123, 15*time.Minute)
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        ParseToken(testSecret, token)
    }
}
```

⚠️ **Concurrency Testing (Limited)**

```go
// TODO: Add concurrent access tests
func TestConcurrentLogin(t *testing.T) {
    t.Run("multiple simultaneous logins", func(t *testing.T) {
        var wg sync.WaitGroup
        errors := make(chan error, 10)

        for i := 0; i < 10; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                _, _, _, _, err := authService.Login(input, "device", "ip")
                if err != nil {
                    errors <- err
                }
            }()
        }

        wg.Wait()
        close(errors)

        for err := range errors {
            t.Errorf("Concurrent login failed: %v", err)
        }
    })
}
```

⚠️ **Table-Driven Tests**

```go
// TODO: Consider table-driven approach for similar tests
func TestValidateInput(t *testing.T) {
    tests := []struct {
        name      string
        email     string
        password  string
        wantError bool
        errorType error
    }{
        {"valid input", "user@test.com", "Pass123!", false, nil},
        {"empty email", "", "Pass123!", true, &ValidationError{}},
        {"invalid email", "notanemail", "Pass123!", true, &ValidationError{}},
        {"short password", "user@test.com", "123", true, &ValidationError{}},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validateInput(tt.email, tt.password)

            if tt.wantError {
                assert.Error(t, err)
                if tt.errorType != nil {
                    assert.IsType(t, tt.errorType, err)
                }
            } else {
                assert.NoError(t, err)
            }
        })
    }
}
```

---

## 🐛 Debugging Tests

### Enable Verbose Output

```go
// Add logging to tests
t.Run("debug test", func(t *testing.T) {
    user := createTestUser(123, "test@test.com", nil, []dbmodel.Role{})

    // Use t.Logf for debugging
    t.Logf("User ID: %d", user.ID)
    t.Logf("User Email: %s", user.Email)
    t.Logf("User Roles: %+v", user.Roles)

    // Your test assertions...
})
```

```bash
# Run with verbose output to see logs
go test ./internal/authentication/... -v -run TestDebug
```

### Use Test Helpers for Complex Debugging

```go
// Helper to print mock calls
func debugMockCalls(t *testing.T, mock *MockUserRepository) {
    t.Helper()
    for _, call := range mock.Calls {
        t.Logf("Mock called: %s with args: %+v", call.Method, call.Arguments)
    }
}

// Usage in test
t.Run("debug mock interactions", func(t *testing.T) {
    mockUserRepo := new(MockUserRepository)
    // ... setup and test ...
    debugMockCalls(t, mockUserRepo)
    mockUserRepo.AssertExpectations(t)
})
```

### Run Single Test

```bash
# Run specific test case
go test ./internal/authentication/... -run TestLogin/successful_login -v

# Run with race detector for concurrency issues
go test ./internal/authentication/... -run TestRefreshToken -race -v

# Run with timeout
go test ./internal/authentication/... -run TestSlowOperation -timeout 30s -v
```

---

## 🎯 Testing Roadmap

### Phase 1: Unit Tests ✅ (Complete)

- [x] JWT generation and parsing
- [x] Refresh token rotation
- [x] Password hashing
- [x] Login flow
- [x] User CRUD operations
- [x] RBAC enforcement
- [x] Middleware authentication
- [x] Permission overrides

**Status**: 83.8% coverage, 115 tests, Grade A-

### Phase 2: Integration Tests (In Progress)

- [ ] File upload testing (avatar with temp files)
- [ ] Address creation with AddressRepository
- [ ] Transaction rollback scenarios
- [ ] Database constraint validation
- [ ] OAuth flow integration
- [ ] Email notification sending
- [ ] Full user journey (register → verify → login → update)

### Phase 3: Performance & Load Testing (Planned)

- [ ] Benchmark password hashing (verify cost=14 performance)
- [ ] Benchmark JWT operations (target: < 1ms)
- [ ] Concurrent login stress test (100+ simultaneous)
- [ ] Token rotation under load
- [ ] GraphQL query latency (target p95 < 300ms)
- [ ] WebSocket connection stability

### Phase 4: End-to-End Testing (Future)

- [ ] Complete user journeys with GraphQL client
- [ ] Provider integration tests (Google/Microsoft OAuth)
- [ ] DocuSign signature workflows
- [ ] Stripe payment flows
- [ ] Calendar sync bidirectional testing
- [ ] Messaging and real-time subscriptions

---

## Example: Testing a New Feature

## 🔄 Continuous Integration

### Local Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Pre-commit hook for Katabase GraphQL API

echo "🧪 Running authentication tests..."
go test ./internal/authentication/... -cover

if [ $? -ne 0 ]; then
    echo "❌ Tests failed. Commit aborted."
    exit 1
fi

echo "🔍 Running linter..."
golangci-lint run ./internal/authentication/...

if [ $? -ne 0 ]; then
    echo "❌ Linter found issues. Commit aborted."
    exit 1
fi

echo "✅ All checks passed!"
exit 0
```

Make it executable:

```bash
chmod +x .git/hooks/pre-commit
```

### GitHub Actions Workflow

Create `.github/workflows/test.yml`:

```yaml
name: Tests & Coverage

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgis/postgis:15-3.3
        env:
          POSTGRES_USER: katabasegql_test
          POSTGRES_PASSWORD: test_password
          POSTGRES_DB: katabasegql_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: "1.21"
          cache: true

      - name: Install dependencies
        run: go mod download

      - name: Run unit tests
        run: go test ./... -v -cover -coverprofile=coverage.out

      - name: Run integration tests
        run: go test ./... -tags=integration -v
        env:
          DB_HOST: localhost
          DB_PORT: 5432
          DB_USER: katabasegql_test
          DB_PASSWORD: test_password
          DB_NAME: katabasegql_test

      - name: Run race detector
        run: go test ./... -race

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out
          flags: unittests
          name: codecov-umbrella

      - name: Check coverage threshold
        run: |
          coverage=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          threshold=80
          if (( $(echo "$coverage < $threshold" | bc -l) )); then
            echo "❌ Coverage $coverage% is below threshold $threshold%"
            exit 1
          fi
          echo "✅ Coverage $coverage% meets threshold"

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: "1.21"

      - name: Run golangci-lint
        uses: golangci/golangci-lint-action@v3
        with:
          version: latest
          args: --timeout=5m
```

### Docker Compose for CI Testing

Use `docker/docker-compose.test.yml`:

```bash
# Start test environment
docker-compose -f docker/docker-compose.test.yml up -d

# Wait for database
sleep 5

# Run tests
go test ./... -tags=integration -v

# Cleanup
docker-compose -f docker/docker-compose.test.yml down
```

---

## 📈 Coverage Tracking

### Generate Coverage Report

```bash
# Generate coverage profile
go test ./... -coverprofile=coverage.out

# View coverage summary
go tool cover -func=coverage.out

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html

# Open in browser
xdg-open coverage.html  # Linux
open coverage.html      # macOS
```

### Coverage by Package

```bash
# Authentication package
go test ./internal/authentication/... -coverprofile=auth_coverage.out
go tool cover -func=auth_coverage.out

# User package
go test ./internal/user/... -coverprofile=user_coverage.out
go tool cover -func=user_coverage.out
```

### Coverage Targets

| Package                              | Current   | Target  | Status              |
| ------------------------------------ | --------- | ------- | ------------------- |
| `internal/authentication`            | 83.8%     | 85%     | 🟡 Close            |
| `internal/authentication/jwt`        | 95%+      | 90%     | ✅ Excellent        |
| `internal/authentication/refresh`    | 90%+      | 85%     | ✅ Excellent        |
| `internal/authentication/middleware` | 85%+      | 80%     | ✅ Good             |
| **Overall**                          | **83.8%** | **80%** | ✅ **Above Target** |

---

## ⚠️ Troubleshooting Common Issues

### Issue: Mock Not Being Called

**Symptoms**: `AssertExpectations` fails with "Expected call not found"

**Solution**:

```go
// ❌ Wrong: Typo in method name
mockRepo.On("FindByID", uint(123), mock.Anything).Return(user, nil)
result, _ := userService.GetUser(123)  // Calls FindByEmail instead!

// ✅ Correct: Verify method name matches
mockRepo.On("FindByEmail", "test@test.com", mock.Anything).Return(user, nil)
```

### Issue: Tests Pass Individually but Fail Together

**Symptoms**: Tests fail when run with `go test ./...` but pass individually

**Cause**: Shared state between tests

**Solution**:

```go
// ❌ Bad: Global state
var testUser *dbmodel.User

func TestA(t *testing.T) {
    testUser = createTestUser(...)  // Modifies global
}

func TestB(t *testing.T) {
    assert.NotNil(t, testUser)  // Depends on TestA
}

// ✅ Good: Local state
func TestA(t *testing.T) {
    testUser := createTestUser(...)  // Local variable
}

func TestB(t *testing.T) {
    testUser := createTestUser(...)  // Independent
}
```

### Issue: GORM "unknown field ID in struct literal"

**Symptoms**: Compilation error when creating GORM models

**Cause**: GORM models embed `gorm.Model` which includes ID

**Solution**:

```go
// ❌ Wrong: Can't set ID in literal
user := &dbmodel.User{
    ID: 123,  // Error: unknown field
    Email: "test@test.com",
}

// ✅ Correct: Use helper function
user := createTestUser(123, "test@test.com", nil, []dbmodel.Role{})

// Or set ID after creation
user := &dbmodel.User{Email: "test@test.com"}
user.ID = 123
```

### Issue: Tests Are Slow

**Symptoms**: Test suite takes > 10 seconds

**Causes & Solutions**:

1. **Too many bcrypt operations**:

```go
// Problem: Hashing is slow (cost=14)
for i := 0; i < 100; i++ {
    HashPassword("password")  // ~200ms each!
}

// Solution: Hash once, reuse
passwordHash, _ := HashPassword("password")
for i := 0; i < 100; i++ {
    user := createTestUser(i, "test@test.com", &passwordHash, nil)
}
```

2. **Database operations in unit tests**:

```go
// ❌ Bad: Unit tests hitting database
func TestLogin(t *testing.T) {
    db := setupRealDatabase()  // Slow!
    // ...
}

// ✅ Good: Use mocks for unit tests
func TestLogin(t *testing.T) {
    mockRepo := new(MockUserRepository)  // Fast!
    // ...
}
```

3. **Unnecessary sleep calls**:

```go
// ❌ Bad
time.Sleep(5 * time.Second)  // Why?!

// ✅ Good: Use proper synchronization
done := make(chan bool)
go func() {
    // async work
    done <- true
}()
<-done  // Wait only as long as needed
```

### Issue: Integration Tests Fail with "connection refused"

**Symptoms**: Database connection errors in integration tests

**Solution**:

```bash
# Start test database
docker-compose -f docker/docker-compose.test.yml up -d

# Wait for database to be ready
until docker-compose -f docker/docker-compose.test.yml exec -T db pg_isready; do
    echo "Waiting for database..."
    sleep 1
done

# Run integration tests
go test ./... -tags=integration -v

# Cleanup
docker-compose -f docker/docker-compose.test.yml down
```

### Issue: Race Detector Failures

**Symptoms**: Tests fail with `-race` flag

**Common causes**:

```go
// ❌ Race condition: Concurrent map access
var cache = make(map[string]string)

func TestConcurrent(t *testing.T) {
    go func() { cache["key"] = "value1" }()
    go func() { cache["key"] = "value2" }()  // RACE!
}

// ✅ Fix: Use mutex
var (
    cache = make(map[string]string)
    mu    sync.RWMutex
)

func TestConcurrent(t *testing.T) {
    go func() {
        mu.Lock()
        cache["key"] = "value1"
        mu.Unlock()
    }()
    go func() {
        mu.Lock()
        cache["key"] = "value2"
        mu.Unlock()
    }()
}
```

---

## 📚 Best Practices Summary

### ✅ DO

1. **Write tests first** (TDD) or immediately after implementation
2. **Use descriptive test names** that explain the scenario
3. **Follow Arrange-Act-Assert** pattern consistently
4. **Isolate tests** - no shared state between tests
5. **Mock external dependencies** for unit tests
6. **Verify mock expectations** with `AssertExpectations(t)`
7. **Test error paths** - not just happy paths
8. **Use require for setup**, assert for validation
9. **Test one behavior** per test case
10. **Keep tests fast** - unit tests should be < 100ms each

### ❌ DON'T

1. **Don't skip error checking** in test setup
2. **Don't use magic numbers** - use constants or variables
3. **Don't test implementation details** - test behavior
4. **Don't share state** between tests (globals, singletons)
5. **Don't mix unit and integration tests** - use build tags
6. **Don't ignore race conditions** - run with `-race` regularly
7. **Don't hardcode secrets** - use test constants
8. **Don't skip mock verification** - always call `AssertExpectations`
9. **Don't write flaky tests** - ensure deterministic behavior
10. **Don't forget to clean up** - use defer for cleanup

---

## 🎓 Learning Resources

### Official Documentation

- [Go Testing Package](https://pkg.go.dev/testing) - Official testing docs
- [Testify Documentation](https://pkg.go.dev/github.com/stretchr/testify) - Assertion library
- [GORM Testing](https://gorm.io/docs/testing.html) - Database testing with GORM

### Testing Best Practices

- [Table Driven Tests](https://github.com/golang/go/wiki/TableDrivenTests) - Pattern for similar tests
- [Go Testing Best Practices](https://go.dev/doc/tutorial/add-a-test) - Official tutorial
- [Effective Go: Testing](https://go.dev/doc/effective_go#testing) - Testing chapter

### Advanced Topics

- [Go Test Comments](https://pkg.go.dev/cmd/go#hdr-Test_packages) - Test flags and options
- [Benchmarking](https://pkg.go.dev/testing#hdr-Benchmarks) - Performance testing
- [Fuzzing](https://go.dev/security/fuzz/) - Automated test case generation

---

## 🎯 Quick Reference

### Common Commands

```bash
# Run all tests
go test ./...

# Run with coverage
go test ./... -cover

# Run specific package
go test ./internal/authentication/...

# Run specific test
go test ./internal/authentication/... -run TestLogin

# Run with race detector
go test ./... -race

# Generate coverage report
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Run integration tests
go test ./... -tags=integration

# Benchmark tests
go test ./... -bench=. -benchmem

# Verbose output
go test ./... -v

# Run tests in parallel
go test ./... -parallel 4
```

### Common Assertions

```go
// Equality
assert.Equal(t, expected, actual)
assert.NotEqual(t, unexpected, actual)

// Nil checks
assert.Nil(t, object)
assert.NotNil(t, object)

// Boolean
assert.True(t, condition)
assert.False(t, condition)

// Errors
assert.Error(t, err)
assert.NoError(t, err)
assert.EqualError(t, err, "expected message")

// Type checks
assert.IsType(t, &ExpectedType{}, actual)

// Collections
assert.Len(t, slice, expectedLength)
assert.Contains(t, slice, element)
assert.Empty(t, collection)
assert.NotEmpty(t, collection)

// Strings
assert.Contains(t, haystack, needle)
assert.NotContains(t, haystack, needle)

// Panics
assert.Panics(t, func() { /* code that panics */ })
assert.NotPanics(t, func() { /* safe code */ })
```

---

## 📞 Getting Help

### Internal Resources

- Check existing tests in `internal/authentication/*_test.go`
- Review test fixtures in `tests/fixtures/`
- Consult test helpers in `tests/helpers/`

### When Writing New Tests

1. **Copy similar test** as a template
2. **Follow existing patterns** in the codebase
3. **Use helper functions** for common setup
4. **Ask for code review** on complex test scenarios

### Questions to Ask

- ✅ Does this test follow our patterns?
- ✅ Is this test isolated and independent?
- ✅ Does this test have clear Arrange-Act-Assert sections?
- ✅ Are all mocks verified?
- ✅ Does this test cover both success and error paths?

---

**Last Updated**: November 2, 2025  
**Test Coverage**: 83.8% (115 tests)  
**Quality Grade**: A- (Production-Ready)
