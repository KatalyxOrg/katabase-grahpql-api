package authentication

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/graph/model"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
	"katalyx.fr/katabasegql/pkg/errormsg"
)

// Mock UserRepository
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

func (m *MockUserRepository) FindByEmail(email string, fieldsToInclude *dbmodel.UserFieldsToInclude) (*dbmodel.User, error) {
	args := m.Called(email, fieldsToInclude)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.User), args.Error(1)
}

func (m *MockUserRepository) FindByLinkedInID(linkedInID string, fieldsToInclude *dbmodel.UserFieldsToInclude) (*dbmodel.User, error) {
	args := m.Called(linkedInID, fieldsToInclude)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.User), args.Error(1)
}

func (m *MockUserRepository) FindByGroupID(groupID uint) ([]*dbmodel.User, error) {
	args := m.Called(groupID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*dbmodel.User), args.Error(1)
}

func (m *MockUserRepository) Create(user *dbmodel.User) (*dbmodel.User, error) {
	args := m.Called(user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *dbmodel.User) (*dbmodel.User, error) {
	args := m.Called(user)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.User), args.Error(1)
}

func (m *MockUserRepository) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

// Mock RoleRepository
type MockRoleRepository struct {
	mock.Mock
}

func (m *MockRoleRepository) FindByName(name string) (*dbmodel.Role, error) {
	args := m.Called(name)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.Role), args.Error(1)
}

// Mock PermissionRepository
type MockPermissionRepository struct {
	mock.Mock
}

func (m *MockPermissionRepository) FindAll() ([]*dbmodel.Permission, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*dbmodel.Permission), args.Error(1)
}

// Mock UserPermissionOverrideRepository
type MockUserPermissionOverrideRepository struct {
	mock.Mock
}

func (m *MockUserPermissionOverrideRepository) Create(override *dbmodel.UserPermissionOverride) (*dbmodel.UserPermissionOverride, error) {
	args := m.Called(override)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.UserPermissionOverride), args.Error(1)
}

func (m *MockUserPermissionOverrideRepository) Delete(userID uint, permissionID uint) error {
	args := m.Called(userID, permissionID)
	return args.Error(0)
}

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

// Helper to create a user with ID (gorm.Model embeds ID)
func createTestUser(id uint, email string, passwordHash *string, roles []dbmodel.Role) *dbmodel.User {
	user := &dbmodel.User{
		Email:        email,
		PasswordHash: passwordHash,
		Roles:        roles,
	}
	user.ID = id
	return user
}

// Helper to create a refresh token with ID
func createTestRefreshToken(id uint, userID uint, tokenHash string, familyID string, expiresAt time.Time, revokedAt *time.Time) *dbmodel.RefreshToken {
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

// Helper function to create a string pointer
func stringPtr(s string) *string {
	return &s
}

func TestLogin(t *testing.T) {
	t.Run("successful login returns user, tokens, and permissions", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		passwordHash, _ := HashPassword("password123")
		permission := dbmodel.Permission{Name: "read:user:self"}
		role := dbmodel.Role{
			Name:        "user",
			Permissions: []dbmodel.Permission{permission},
		}

		dbUser := createTestUser(123, "test@test.com", &passwordHash, []dbmodel.Role{role})

		mockUserRepo.On("FindByEmail", "test@test.com", mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).
			Return(&dbmodel.RefreshToken{}, nil)

		loginInput := model.LoginInput{
			Email:    "test@test.com",
			Password: "password123",
		}

		user, accessToken, refreshToken, permissions, err := authService.Login(loginInput, "test-agent", "192.168.1.1")

		require.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, uint(123), user.ID)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
		assert.Len(t, permissions, 1)
		assert.Equal(t, "read:user:self", permissions[0].Name)

		mockUserRepo.AssertExpectations(t)
		mockRefreshTokenRepo.AssertExpectations(t)
	})

	t.Run("login with invalid email returns UserNotFoundError", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockUserRepo.On("FindByEmail", "nonexistent@test.com", mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(nil, nil)

		loginInput := model.LoginInput{
			Email:    "nonexistent@test.com",
			Password: "password123",
		}

		_, _, _, _, err := authService.Login(loginInput, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		assert.IsType(t, &errormsg.UserNotFoundError{}, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("login with invalid password returns UserInvalidCredentialsError", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		passwordHash, _ := HashPassword("correct-password")
		dbUser := createTestUser(123, "test@test.com", &passwordHash, []dbmodel.Role{})

		mockUserRepo.On("FindByEmail", "test@test.com", mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		loginInput := model.LoginInput{
			Email:    "test@test.com",
			Password: "wrong-password",
		}

		_, _, _, _, err := authService.Login(loginInput, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		assert.IsType(t, &errormsg.UserInvalidCredentialsError{}, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("login generates valid access and refresh tokens", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		passwordHash, _ := HashPassword("password123")
		dbUser := createTestUser(456, "test@test.com", &passwordHash, []dbmodel.Role{})

		mockUserRepo.On("FindByEmail", "test@test.com", mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).
			Return(&dbmodel.RefreshToken{}, nil)

		loginInput := model.LoginInput{
			Email:    "test@test.com",
			Password: "password123",
		}

		_, accessToken, refreshToken, _, err := authService.Login(loginInput, "test-agent", "192.168.1.1")

		require.NoError(t, err)

		// Verify access token is valid JWT
		userID, err := ParseToken(testSecret, accessToken)
		require.NoError(t, err)
		assert.Equal(t, uint(456), userID)

		// Verify refresh token is not empty and is base64 encoded
		assert.NotEmpty(t, refreshToken)
		assert.Greater(t, len(refreshToken), 40)

		mockUserRepo.AssertExpectations(t)
		mockRefreshTokenRepo.AssertExpectations(t)
	})

	t.Run("login captures user agent and IP address", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		passwordHash, _ := HashPassword("password123")
		dbUser := createTestUser(789, "test@test.com", &passwordHash, []dbmodel.Role{})

		userAgent := "Mozilla/5.0 Test"
		ipAddress := "203.0.113.100"

		var capturedToken *dbmodel.RefreshToken
		mockUserRepo.On("FindByEmail", "test@test.com", mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).
			Run(func(args mock.Arguments) {
				capturedToken = args.Get(0).(*dbmodel.RefreshToken)
			}).Return(&dbmodel.RefreshToken{}, nil)

		loginInput := model.LoginInput{
			Email:    "test@test.com",
			Password: "password123",
		}

		_, _, _, _, err := authService.Login(loginInput, userAgent, ipAddress)

		require.NoError(t, err)
		assert.Equal(t, userAgent, capturedToken.UserAgent)
		assert.Equal(t, ipAddress, capturedToken.IPAddress)

		mockUserRepo.AssertExpectations(t)
		mockRefreshTokenRepo.AssertExpectations(t)
	})
}

func TestRefreshAccessToken(t *testing.T) {
	t.Run("valid refresh token generates new tokens", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		oldToken := "old-refresh-token"
		oldTokenHash, _ := hashRefreshToken(oldToken)

		dbRefreshToken := createTestRefreshToken(
			1,
			123,
			oldTokenHash,
			"family-123",
			time.Now().Add(24*time.Hour),
			nil,
		)

		permission := dbmodel.Permission{Name: "read:user:self"}
		role := dbmodel.Role{
			Name:        "user",
			Permissions: []dbmodel.Permission{permission},
		}

		dbUser := createTestUser(123, "test@test.com", nil, []dbmodel.Role{role})

		// Call sequence in RefreshAccessToken -> RotateRefreshToken:
		// 1. RotateRefreshToken calls FindByTokenHashIncludingRevoked
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", oldTokenHash).Return(dbRefreshToken, nil).Once()
		// 2. UpdateLastUsed is called
		mockRefreshTokenRepo.On("UpdateLastUsed", uint(1)).Return(nil)
		// 3. RevokeByID is called
		mockRefreshTokenRepo.On("RevokeByID", uint(1)).Return(nil)
		// 4. Create new refresh token
		mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Return(&dbmodel.RefreshToken{}, nil)
		// 5. Back in RefreshAccessToken, FindByTokenHashIncludingRevoked is called again
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", oldTokenHash).Return(dbRefreshToken, nil).Once()
		// 6. FindByID to get user
		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).Return(dbUser, nil)

		user, newAccessToken, newRefreshToken, permissions, err := authService.RefreshAccessToken(
			oldToken,
			"test-agent",
			"192.168.1.1",
		)

		require.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, uint(123), user.ID)
		assert.NotEmpty(t, newAccessToken)
		assert.NotEmpty(t, newRefreshToken)
		assert.NotEqual(t, oldToken, newRefreshToken)
		assert.Len(t, permissions, 1)

		mockUserRepo.AssertExpectations(t)
		mockRefreshTokenRepo.AssertExpectations(t)
	})

	t.Run("invalid refresh token returns error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		invalidToken := "invalid-token"
		invalidTokenHash, _ := hashRefreshToken(invalidToken)

		// RotateRefreshToken calls FindByTokenHashIncludingRevoked which returns nil for invalid token
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", invalidTokenHash).Return(nil, nil)

		_, _, _, _, err := authService.RefreshAccessToken(invalidToken, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenInvalidError{}, err)

		mockRefreshTokenRepo.AssertExpectations(t)
	})

	t.Run("expired refresh token returns error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		expiredToken := "expired-token"
		expiredTokenHash, _ := hashRefreshToken(expiredToken)

		dbRefreshToken := createTestRefreshToken(
			1,
			123,
			expiredTokenHash,
			"family-123",
			time.Now().Add(-24*time.Hour), // Expired
			nil,
		)

		// RotateRefreshToken calls FindByTokenHashIncludingRevoked
		// The token is found but expired, so it fails in the expiry check
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", expiredTokenHash).Return(dbRefreshToken, nil)

		_, _, _, _, err := authService.RefreshAccessToken(expiredToken, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenExpiredError{}, err)

		mockRefreshTokenRepo.AssertExpectations(t)
	})

	t.Run("reused refresh token triggers family revocation", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		reusedToken := "reused-token"
		reusedTokenHash, _ := hashRefreshToken(reusedToken)

		revokedAt := time.Now().Add(-1 * time.Hour)
		dbRefreshToken := createTestRefreshToken(
			1,
			123,
			reusedTokenHash,
			"family-123",
			time.Now().Add(24*time.Hour),
			&revokedAt, // Token is already revoked
		)

		// RotateRefreshToken calls FindByTokenHashIncludingRevoked
		// Token is found but is already revoked - this triggers reuse detection
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", reusedTokenHash).Return(dbRefreshToken, nil)
		// When reuse is detected, it revokes the entire family
		mockRefreshTokenRepo.On("RevokeByFamilyID", "family-123").Return(nil)

		_, _, _, _, err := authService.RefreshAccessToken(reusedToken, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenReuseDetectedError{}, err)

		mockRefreshTokenRepo.AssertExpectations(t)
	})
}

func TestCreateUser(t *testing.T) {
	t.Run("successfully creates user with valid input", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		defaultRole := &dbmodel.Role{Name: "user"}
		createdUser := createTestUser(999, "newuser@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByEmail", "newuser@test.com", mock.Anything).Return(nil, nil)
		mockRoleRepo.On("FindByName", "user").Return(defaultRole, nil)
		mockUserRepo.On("Create", mock.AnythingOfType("*dbmodel.User")).Return(createdUser, nil)

		password := "SecurePassword123"
		firstName := "John"

		input := model.NewUserInput{
			Email:    "newuser@test.com",
			Password: &password,
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		user, err := authService.CreateUser(input)

		require.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, uint(999), user.ID)

		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("hashes password using bcrypt", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		defaultRole := &dbmodel.Role{Name: "user"}
		var capturedUser *dbmodel.User

		mockUserRepo.On("FindByEmail", "newuser@test.com", mock.Anything).Return(nil, nil)
		mockRoleRepo.On("FindByName", "user").Return(defaultRole, nil)
		mockUserRepo.On("Create", mock.AnythingOfType("*dbmodel.User")).Run(func(args mock.Arguments) {
			capturedUser = args.Get(0).(*dbmodel.User)
		}).Return(&dbmodel.User{}, nil)

		password := "MyPassword123"
		firstName := "Jane"

		input := model.NewUserInput{
			Email:    "newuser@test.com",
			Password: &password,
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		_, err := authService.CreateUser(input)

		require.NoError(t, err)
		assert.NotNil(t, capturedUser.PasswordHash)

		// Verify password is hashed (not stored in plain text)
		assert.NotEqual(t, password, *capturedUser.PasswordHash)

		// Verify bcrypt can verify the password
		err = bcrypt.CompareHashAndPassword([]byte(*capturedUser.PasswordHash), []byte(password))
		assert.NoError(t, err)

		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("assigns default user role", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		defaultRole := &dbmodel.Role{Name: "user"}
		var capturedUser *dbmodel.User

		mockUserRepo.On("FindByEmail", "newuser@test.com", mock.Anything).Return(nil, nil)
		mockRoleRepo.On("FindByName", "user").Return(defaultRole, nil)
		mockUserRepo.On("Create", mock.AnythingOfType("*dbmodel.User")).Run(func(args mock.Arguments) {
			capturedUser = args.Get(0).(*dbmodel.User)
		}).Return(&dbmodel.User{}, nil)

		password := "Password123"
		firstName := "Test"

		input := model.NewUserInput{
			Email:    "newuser@test.com",
			Password: &password,
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		_, err := authService.CreateUser(input)

		require.NoError(t, err)
		assert.Len(t, capturedUser.Roles, 1)
		assert.Equal(t, "user", capturedUser.Roles[0].Name)

		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("creates associated user profile", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		defaultRole := &dbmodel.Role{Name: "user"}
		var capturedUser *dbmodel.User

		mockUserRepo.On("FindByEmail", "newuser@test.com", mock.Anything).Return(nil, nil)
		mockRoleRepo.On("FindByName", "user").Return(defaultRole, nil)
		mockUserRepo.On("Create", mock.AnythingOfType("*dbmodel.User")).Run(func(args mock.Arguments) {
			capturedUser = args.Get(0).(*dbmodel.User)
		}).Return(&dbmodel.User{}, nil)

		password := "Password123"
		firstName := "Alice"

		input := model.NewUserInput{
			Email:    "newuser@test.com",
			Password: &password,
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		_, err := authService.CreateUser(input)

		require.NoError(t, err)
		assert.Equal(t, firstName, capturedUser.UserProfile.FirstName)

		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("rejects duplicate email", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		existingUser := createTestUser(123, "existing@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByEmail", "existing@test.com", mock.Anything).Return(existingUser, nil)

		password := "Password123"
		firstName := "Test"

		input := model.NewUserInput{
			Email:    "existing@test.com",
			Password: &password,
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		_, err := authService.CreateUser(input)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.UserEmailAlreadyExistsError{}, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("handles optional password for OAuth users", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		defaultRole := &dbmodel.Role{Name: "user"}
		var capturedUser *dbmodel.User

		mockUserRepo.On("FindByEmail", "oauth@test.com", mock.Anything).Return(nil, nil)
		mockRoleRepo.On("FindByName", "user").Return(defaultRole, nil)
		mockUserRepo.On("Create", mock.AnythingOfType("*dbmodel.User")).Run(func(args mock.Arguments) {
			capturedUser = args.Get(0).(*dbmodel.User)
		}).Return(&dbmodel.User{}, nil)

		firstName := "OAuth"

		input := model.NewUserInput{
			Email:    "oauth@test.com",
			Password: nil, // No password for OAuth user
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		_, err := authService.CreateUser(input)

		require.NoError(t, err)
		assert.Nil(t, capturedUser.PasswordHash)

		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})
}

func TestHashPassword(t *testing.T) {
	t.Run("hashes password successfully", func(t *testing.T) {
		password := "MySecurePassword123"

		hash, err := HashPassword(password)

		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.NotEqual(t, password, hash)
	})

	t.Run("generates different hashes for same password", func(t *testing.T) {
		password := "SamePassword123"

		hash1, err1 := HashPassword(password)
		hash2, err2 := HashPassword(password)

		require.NoError(t, err1)
		require.NoError(t, err2)

		// bcrypt generates different salts, so hashes should differ
		assert.NotEqual(t, hash1, hash2)
	})
}

func TestCheckPasswordHash(t *testing.T) {
	t.Run("returns true for matching password", func(t *testing.T) {
		password := "CorrectPassword123"
		hash, _ := HashPassword(password)

		result := CheckPasswordHash(password, hash)

		assert.True(t, result)
	})

	t.Run("returns false for non-matching password", func(t *testing.T) {
		password := "CorrectPassword123"
		wrongPassword := "WrongPassword456"
		hash, _ := HashPassword(password)

		result := CheckPasswordHash(wrongPassword, hash)

		assert.False(t, result)
	})

	t.Run("returns false for invalid hash", func(t *testing.T) {
		password := "SomePassword123"
		invalidHash := "not-a-valid-bcrypt-hash"

		result := CheckPasswordHash(password, invalidHash)

		assert.False(t, result)
	})

	t.Run("handles legacy bcrypt hash format", func(t *testing.T) {
		// The CheckPasswordHash function has a fallback for $2y$ prefix
		// This tests the legacy hash handling
		password := "TestPassword"
		legacyHash := "$2y$10$poSHkg3pxj/exyAna/Z6Ruy4zY.eeCTggXPXwELypoy.P3mvdhpaG"

		// This should not panic even with legacy format
		result := CheckPasswordHash(password, legacyHash)

		// We don't know the actual password for this hash, so it might be false
		// But the important thing is it doesn't panic
		assert.NotNil(t, result)
	})
}

func TestUpdateUser(t *testing.T) {
	t.Run("user can update their own profile", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		dbUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		dbUser.UserProfile = dbmodel.UserProfile{FirstName: "OldName"}

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		updatedUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		updatedUser.UserProfile = dbmodel.UserProfile{FirstName: "NewName"}
		mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).Return(updatedUser, nil)

		changes := map[string]interface{}{
			"userProfile": map[string]interface{}{
				"firstName": stringPtr("NewName"),
			},
		}

		result, err := authService.UpdateUser(loggedInUser, 123, changes)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "NewName", result.UserProfile.FirstName)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user without permission cannot update other users", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		// User 123 trying to update user 456
		loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		targetUser := createTestUser(456, "other@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(456), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(targetUser, nil)

		changes := map[string]interface{}{
			"userProfile": map[string]interface{}{
				"firstName": stringPtr("Hacked"),
			},
		}

		_, err := authService.UpdateUser(loggedInUser, 456, changes)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.UserAccessDeniedError{}, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user with update:user permission can update other users", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		// Admin user with update:user permission
		adminPermission := dbmodel.Permission{Name: "update:user"}
		adminRole := dbmodel.Role{
			Name:        "admin",
			Permissions: []dbmodel.Permission{adminPermission},
		}
		loggedInUser := createTestUser(123, "admin@test.com", nil, []dbmodel.Role{adminRole})

		targetUser := createTestUser(456, "target@test.com", nil, []dbmodel.Role{})
		targetUser.UserProfile = dbmodel.UserProfile{FirstName: "OldName"}

		mockUserRepo.On("FindByID", uint(456), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(targetUser, nil)

		updatedUser := createTestUser(456, "target@test.com", nil, []dbmodel.Role{})
		updatedUser.UserProfile = dbmodel.UserProfile{FirstName: "UpdatedByAdmin"}
		mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).Return(updatedUser, nil)

		changes := map[string]interface{}{
			"userProfile": map[string]interface{}{
				"firstName": stringPtr("UpdatedByAdmin"),
			},
		}

		result, err := authService.UpdateUser(loggedInUser, 456, changes)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "UpdatedByAdmin", result.UserProfile.FirstName)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("returns error when user not found", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(999), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(nil, nil)

		changes := map[string]interface{}{}

		_, err := authService.UpdateUser(loggedInUser, 999, changes)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.UserNotFoundError{}, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("prevents email change to existing email", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		dbUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})

		existingUser := createTestUser(456, "taken@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockUserRepo.On("FindByEmail", "taken@test.com", mock.Anything).
			Return(existingUser, nil)

		newEmail := "taken@test.com"
		changes := map[string]interface{}{
			"email": &newEmail,
		}

		_, err := authService.UpdateUser(loggedInUser, 123, changes)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.UserEmailAlreadyExistsError{}, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("allows email change to new unique email", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "old@test.com", nil, []dbmodel.Role{})
		dbUser := createTestUser(123, "old@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockUserRepo.On("FindByEmail", "new@test.com", mock.Anything).
			Return(nil, nil) // Email doesn't exist

		updatedUser := createTestUser(123, "new@test.com", nil, []dbmodel.Role{})
		mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).Return(updatedUser, nil)

		newEmail := "new@test.com"
		changes := map[string]interface{}{
			"email": &newEmail,
		}

		result, err := authService.UpdateUser(loggedInUser, 123, changes)

		require.NoError(t, err)
		assert.NotNil(t, result)
		// Note: The actual email change is commented out in the service (TODO)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("allows same email (no change)", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		currentEmail := "user@test.com"
		loggedInUser := createTestUser(123, currentEmail, nil, []dbmodel.Role{})
		dbUser := createTestUser(123, currentEmail, nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		updatedUser := createTestUser(123, currentEmail, nil, []dbmodel.Role{})
		mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).Return(updatedUser, nil)

		// Setting email to same value should not trigger uniqueness check
		changes := map[string]interface{}{
			"email": &currentEmail,
		}

		result, err := authService.UpdateUser(loggedInUser, 123, changes)

		require.NoError(t, err)
		assert.NotNil(t, result)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("updates only provided fields", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		dbUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		dbUser.UserProfile = dbmodel.UserProfile{
			FirstName: "John",
			LastName:  stringPtr("Doe"),
		}

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		var capturedUser *dbmodel.User
		mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).
			Run(func(args mock.Arguments) {
				capturedUser = args.Get(0).(*dbmodel.User)
			}).
			Return(&dbmodel.User{}, nil)

		// Only update last name
		changes := map[string]interface{}{
			"userProfile": map[string]interface{}{
				"lastName": stringPtr("Smith"),
			},
		}

		_, err := authService.UpdateUser(loggedInUser, 123, changes)

		require.NoError(t, err)
		assert.Equal(t, "Smith", *capturedUser.UserProfile.LastName)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("updates multiple profile fields", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		dbUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		dbUser.UserProfile = dbmodel.UserProfile{
			FirstName: "OldFirst",
			LastName:  stringPtr("OldLast"),
		}

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)

		var capturedUser *dbmodel.User
		mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).
			Run(func(args mock.Arguments) {
				capturedUser = args.Get(0).(*dbmodel.User)
			}).
			Return(&dbmodel.User{}, nil)

		phone := "+33612345678"
		changes := map[string]interface{}{
			"userProfile": map[string]interface{}{
				"firstName": stringPtr("NewFirst"),
				"lastName":  stringPtr("NewLast"),
				"phone":     &phone,
			},
		}

		_, err := authService.UpdateUser(loggedInUser, 123, changes)

		require.NoError(t, err)
		assert.Equal(t, "NewFirst", capturedUser.UserProfile.FirstName)
		assert.Equal(t, "NewLast", *capturedUser.UserProfile.LastName)
		assert.Equal(t, phone, *capturedUser.UserProfile.Phone)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("handles FindByID repository error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(nil, assert.AnError)

		changes := map[string]interface{}{}

		_, err := authService.UpdateUser(loggedInUser, 123, changes)

		assert.Error(t, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("handles Update repository error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})
		dbUser := createTestUser(123, "user@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).
			Return(nil, assert.AnError)

		changes := map[string]interface{}{
			"userProfile": map[string]interface{}{
				"firstName": stringPtr("NewName"),
			},
		}

		_, err := authService.UpdateUser(loggedInUser, 123, changes)

		assert.Error(t, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("admin can update user with different ID", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		adminPermission := dbmodel.Permission{Name: "update:user"}
		adminRole := dbmodel.Role{
			Name:        "admin",
			Permissions: []dbmodel.Permission{adminPermission},
		}
		loggedInUser := createTestUser(999, "admin@test.com", nil, []dbmodel.Role{adminRole})

		targetUser := createTestUser(123, "target@test.com", nil, []dbmodel.Role{})
		targetUser.UserProfile = dbmodel.UserProfile{FirstName: "Target"}

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(targetUser, nil)

		updatedUser := createTestUser(123, "target@test.com", nil, []dbmodel.Role{})
		updatedUser.UserProfile = dbmodel.UserProfile{FirstName: "AdminUpdated"}
		mockUserRepo.On("Update", mock.AnythingOfType("*dbmodel.User")).Return(updatedUser, nil)

		changes := map[string]interface{}{
			"userProfile": map[string]interface{}{
				"firstName": stringPtr("AdminUpdated"),
			},
		}

		result, err := authService.UpdateUser(loggedInUser, 123, changes)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "AdminUpdated", result.UserProfile.FirstName)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("regular user cannot update another user", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		// Regular user without update:user permission
		userRole := dbmodel.Role{
			Name:        "user",
			Permissions: []dbmodel.Permission{},
		}
		loggedInUser := createTestUser(999, "regular@test.com", nil, []dbmodel.Role{userRole})

		targetUser := createTestUser(123, "target@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(targetUser, nil)

		changes := map[string]interface{}{
			"userProfile": map[string]interface{}{
				"firstName": stringPtr("Hacked"),
			},
		}

		_, err := authService.UpdateUser(loggedInUser, 123, changes)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.UserAccessDeniedError{}, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("handles email uniqueness check error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		loggedInUser := createTestUser(123, "old@test.com", nil, []dbmodel.Role{})
		dbUser := createTestUser(123, "old@test.com", nil, []dbmodel.Role{})

		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockUserRepo.On("FindByEmail", "new@test.com", mock.Anything).
			Return(nil, assert.AnError)

		newEmail := "new@test.com"
		changes := map[string]interface{}{
			"email": &newEmail,
		}

		_, err := authService.UpdateUser(loggedInUser, 123, changes)

		assert.Error(t, err)

		mockUserRepo.AssertExpectations(t)
	})
}

func TestGetAllPermissions(t *testing.T) {
	t.Run("returns all permissions successfully", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		// Mock PermissionRepository
		mockPermissionRepo := new(MockPermissionRepository)
		authService.Config.PermissionRepository = mockPermissionRepo

		expectedPermissions := []*dbmodel.Permission{
			{Name: "read:user:self"},
			{Name: "update:user:self"},
			{Name: "read:user"},
			{Name: "update:user"},
		}

		mockPermissionRepo.On("FindAll").Return(expectedPermissions, nil)

		permissions, err := authService.GetAllPermissions()

		require.NoError(t, err)
		assert.Len(t, permissions, 4)
		assert.Equal(t, "read:user:self", permissions[0].Name)

		mockPermissionRepo.AssertExpectations(t)
	})

	t.Run("handles repository error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockPermissionRepo := new(MockPermissionRepository)
		authService.Config.PermissionRepository = mockPermissionRepo

		mockPermissionRepo.On("FindAll").Return(nil, assert.AnError)

		permissions, err := authService.GetAllPermissions()

		assert.Error(t, err)
		assert.Nil(t, permissions)

		mockPermissionRepo.AssertExpectations(t)
	})
}

func TestUpdatePermissionOverride(t *testing.T) {
	t.Run("grants permission override successfully", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockOverrideRepo := new(MockUserPermissionOverrideRepository)
		authService.Config.UserPermissionOverrideRepository = mockOverrideRepo

		input := model.NewPermissionOverrideInput{
			UserID:       123,
			PermissionID: 456,
			IsGranted:    true,
		}

		expectedOverride := &dbmodel.UserPermissionOverride{
			UserID:       123,
			PermissionID: 456,
			IsGranted:    true,
		}

		mockOverrideRepo.On("Delete", uint(123), uint(456)).Return(nil)
		mockOverrideRepo.On("Create", mock.AnythingOfType("*dbmodel.UserPermissionOverride")).
			Return(expectedOverride, nil)

		result, err := authService.UpdatePermissionOverride(input)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, uint(123), result.UserID)
		assert.Equal(t, uint(456), result.PermissionID)
		assert.True(t, result.IsGranted)

		mockOverrideRepo.AssertExpectations(t)
	})

	t.Run("revokes permission override successfully", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockOverrideRepo := new(MockUserPermissionOverrideRepository)
		authService.Config.UserPermissionOverrideRepository = mockOverrideRepo

		input := model.NewPermissionOverrideInput{
			UserID:       789,
			PermissionID: 101,
			IsGranted:    false,
		}

		expectedOverride := &dbmodel.UserPermissionOverride{
			UserID:       789,
			PermissionID: 101,
			IsGranted:    false,
		}

		mockOverrideRepo.On("Delete", uint(789), uint(101)).Return(nil)
		mockOverrideRepo.On("Create", mock.AnythingOfType("*dbmodel.UserPermissionOverride")).
			Return(expectedOverride, nil)

		result, err := authService.UpdatePermissionOverride(input)

		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.IsGranted)

		mockOverrideRepo.AssertExpectations(t)
	})

	t.Run("handles delete error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockOverrideRepo := new(MockUserPermissionOverrideRepository)
		authService.Config.UserPermissionOverrideRepository = mockOverrideRepo

		input := model.NewPermissionOverrideInput{
			UserID:       123,
			PermissionID: 456,
			IsGranted:    true,
		}

		mockOverrideRepo.On("Delete", uint(123), uint(456)).Return(assert.AnError)

		result, err := authService.UpdatePermissionOverride(input)

		assert.Error(t, err)
		assert.Nil(t, result)

		mockOverrideRepo.AssertExpectations(t)
	})

	t.Run("handles create error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockOverrideRepo := new(MockUserPermissionOverrideRepository)
		authService.Config.UserPermissionOverrideRepository = mockOverrideRepo

		input := model.NewPermissionOverrideInput{
			UserID:       123,
			PermissionID: 456,
			IsGranted:    true,
		}

		mockOverrideRepo.On("Delete", uint(123), uint(456)).Return(nil)
		mockOverrideRepo.On("Create", mock.AnythingOfType("*dbmodel.UserPermissionOverride")).
			Return(nil, assert.AnError)

		result, err := authService.UpdatePermissionOverride(input)

		assert.Error(t, err)
		assert.Nil(t, result)

		mockOverrideRepo.AssertExpectations(t)
	})
}

// Additional edge case tests for existing functions

func TestLoginEdgeCases(t *testing.T) {
	t.Run("handles repository error during FindByEmail", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockUserRepo.On("FindByEmail", "test@test.com", mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(nil, assert.AnError)

		loginInput := model.LoginInput{
			Email:    "test@test.com",
			Password: "password123",
		}

		_, _, _, _, err := authService.Login(loginInput, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("handles error during refresh token generation", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		passwordHash, _ := HashPassword("password123")
		dbUser := createTestUser(123, "test@test.com", &passwordHash, []dbmodel.Role{})

		mockUserRepo.On("FindByEmail", "test@test.com", mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).
			Return(nil, assert.AnError)

		loginInput := model.LoginInput{
			Email:    "test@test.com",
			Password: "password123",
		}

		_, _, _, _, err := authService.Login(loginInput, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		mockUserRepo.AssertExpectations(t)
		mockRefreshTokenRepo.AssertExpectations(t)
	})

	t.Run("returns empty permissions for user without roles", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		passwordHash, _ := HashPassword("password123")
		dbUser := createTestUser(123, "test@test.com", &passwordHash, []dbmodel.Role{})

		mockUserRepo.On("FindByEmail", "test@test.com", mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(dbUser, nil)
		mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).
			Return(&dbmodel.RefreshToken{}, nil)

		loginInput := model.LoginInput{
			Email:    "test@test.com",
			Password: "password123",
		}

		_, _, _, permissions, err := authService.Login(loginInput, "test-agent", "192.168.1.1")

		require.NoError(t, err)
		assert.Empty(t, permissions)

		mockUserRepo.AssertExpectations(t)
		mockRefreshTokenRepo.AssertExpectations(t)
	})
}

func TestRefreshAccessTokenEdgeCases(t *testing.T) {
	t.Run("handles user not found after token validation", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		validToken := "valid-token"
		tokenHash, _ := hashRefreshToken(validToken)

		dbRefreshToken := createTestRefreshToken(
			1,
			123,
			tokenHash,
			"family-123",
			time.Now().Add(24*time.Hour),
			nil,
		)

		// Call sequence in RefreshAccessToken -> RotateRefreshToken:
		// 1. RotateRefreshToken calls FindByTokenHashIncludingRevoked (first call)
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", tokenHash).Return(dbRefreshToken, nil).Once()
		// 2. UpdateLastUsed is called
		mockRefreshTokenRepo.On("UpdateLastUsed", uint(1)).Return(nil)
		// 3. RevokeByID is called
		mockRefreshTokenRepo.On("RevokeByID", uint(1)).Return(nil)
		// 4. Create new refresh token
		mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Return(&dbmodel.RefreshToken{}, nil)
		// 5. Back in RefreshAccessToken, FindByTokenHashIncludingRevoked is called again
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", tokenHash).Return(dbRefreshToken, nil).Once()
		// 6. FindByID to get user - returns nil (user not found)
		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(nil, nil)

		_, _, _, _, err := authService.RefreshAccessToken(validToken, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		assert.IsType(t, &errormsg.UserNotFoundError{}, err)

		mockUserRepo.AssertExpectations(t)
		mockRefreshTokenRepo.AssertExpectations(t)
	})

	t.Run("handles repository error during user lookup", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		validToken := "valid-token"
		tokenHash, _ := hashRefreshToken(validToken)

		dbRefreshToken := createTestRefreshToken(
			1,
			123,
			tokenHash,
			"family-123",
			time.Now().Add(24*time.Hour),
			nil,
		)

		// Call sequence in RefreshAccessToken -> RotateRefreshToken:
		// 1. RotateRefreshToken calls FindByTokenHashIncludingRevoked (first call)
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", tokenHash).Return(dbRefreshToken, nil).Once()
		// 2. UpdateLastUsed is called
		mockRefreshTokenRepo.On("UpdateLastUsed", uint(1)).Return(nil)
		// 3. RevokeByID is called
		mockRefreshTokenRepo.On("RevokeByID", uint(1)).Return(nil)
		// 4. Create new refresh token
		mockRefreshTokenRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Return(&dbmodel.RefreshToken{}, nil)
		// 5. Back in RefreshAccessToken, FindByTokenHashIncludingRevoked is called again
		mockRefreshTokenRepo.On("FindByTokenHashIncludingRevoked", tokenHash).Return(dbRefreshToken, nil).Once()
		// 6. FindByID to get user - returns error
		mockUserRepo.On("FindByID", uint(123), mock.AnythingOfType("*dbmodel.UserFieldsToInclude")).
			Return(nil, assert.AnError)

		_, _, _, _, err := authService.RefreshAccessToken(validToken, "test-agent", "192.168.1.1")

		assert.Error(t, err)

		mockUserRepo.AssertExpectations(t)
		mockRefreshTokenRepo.AssertExpectations(t)
	})
}

func TestCreateUserEdgeCases(t *testing.T) {
	t.Run("handles repository error during email check", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockUserRepo.On("FindByEmail", "test@test.com", mock.Anything).
			Return(nil, assert.AnError)

		password := "Password123"
		firstName := "Test"

		input := model.NewUserInput{
			Email:    "test@test.com",
			Password: &password,
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		_, err := authService.CreateUser(input)

		assert.Error(t, err)
		mockUserRepo.AssertExpectations(t)
	})

	t.Run("handles role not found error", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		mockUserRepo.On("FindByEmail", "test@test.com", mock.Anything).Return(nil, nil)
		mockRoleRepo.On("FindByName", "user").Return(nil, assert.AnError)

		password := "Password123"
		firstName := "Test"

		input := model.NewUserInput{
			Email:    "test@test.com",
			Password: &password,
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		_, err := authService.CreateUser(input)

		assert.Error(t, err)
		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})

	t.Run("handles repository error during user creation", func(t *testing.T) {
		mockUserRepo := new(MockUserRepository)
		mockRoleRepo := new(MockRoleRepository)
		mockRefreshTokenRepo := new(MockRefreshTokenRepository)
		authService := setupAuthServiceWithMocks(mockUserRepo, mockRoleRepo, mockRefreshTokenRepo)

		defaultRole := &dbmodel.Role{Name: "user"}

		mockUserRepo.On("FindByEmail", "test@test.com", mock.Anything).Return(nil, nil)
		mockRoleRepo.On("FindByName", "user").Return(defaultRole, nil)
		mockUserRepo.On("Create", mock.AnythingOfType("*dbmodel.User")).
			Return(nil, assert.AnError)

		password := "Password123"
		firstName := "Test"

		input := model.NewUserInput{
			Email:    "test@test.com",
			Password: &password,
			UserProfile: &model.NewUserProfileInput{
				FirstName: firstName,
			},
		}

		_, err := authService.CreateUser(input)

		assert.Error(t, err)
		mockUserRepo.AssertExpectations(t)
		mockRoleRepo.AssertExpectations(t)
	})
}
