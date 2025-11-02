package authentication

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
	"katalyx.fr/katabasegql/pkg/errormsg"
)

// Mock RefreshTokenRepository
type MockRefreshTokenRepository struct {
	mock.Mock
}

func (m *MockRefreshTokenRepository) Create(token *dbmodel.RefreshToken) (*dbmodel.RefreshToken, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) FindByTokenHash(tokenHash string) (*dbmodel.RefreshToken, error) {
	args := m.Called(tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) FindByTokenHashIncludingRevoked(tokenHash string) (*dbmodel.RefreshToken, error) {
	args := m.Called(tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*dbmodel.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) FindByFamilyID(familyID string) ([]*dbmodel.RefreshToken, error) {
	args := m.Called(familyID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*dbmodel.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) RevokeByFamilyID(familyID string) error {
	args := m.Called(familyID)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) RevokeByID(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) UpdateLastUsed(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) DeleteExpired() error {
	args := m.Called()
	return args.Error(0)
}

func setupAuthService(mockRefreshTokenRepo *MockRefreshTokenRepository) *AuthenticationService {
	cfg := &config.Config{
		RefreshTokenRepository: mockRefreshTokenRepo,
	}
	cfg.Constants.JWT.Secret = testSecret
	cfg.Constants.JWT.AccessTokenTTL = 15 * time.Minute
	cfg.Constants.JWT.RefreshTokenTTL = 7 * 24 * time.Hour

	return &AuthenticationService{
		Config: cfg,
	}
}

func TestHashRefreshToken(t *testing.T) {
	t.Run("produces consistent hashes for same input", func(t *testing.T) {
		token := "test-token-123"

		hash1, err1 := hashRefreshToken(token)
		hash2, err2 := hashRefreshToken(token)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.Equal(t, hash1, hash2, "Same input should produce same hash")
	})

	t.Run("produces different hashes for different inputs", func(t *testing.T) {
		token1 := "test-token-123"
		token2 := "test-token-456"

		hash1, err1 := hashRefreshToken(token1)
		hash2, err2 := hashRefreshToken(token2)

		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, hash1, hash2, "Different inputs should produce different hashes")
	})

	t.Run("produces valid base64 encoded string", func(t *testing.T) {
		token := "test-token-789"

		hash, err := hashRefreshToken(token)

		require.NoError(t, err)
		assert.NotEmpty(t, hash)

		// Should be decodable as base64
		_, decodeErr := base64.URLEncoding.DecodeString(hash)
		assert.NoError(t, decodeErr)
	})
}

func TestGenerateRefreshToken(t *testing.T) {
	t.Run("creates cryptographically secure token", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		mockRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Return(&dbmodel.RefreshToken{}, nil)

		token, familyID, err := authService.GenerateRefreshToken(123, "test-agent", "192.168.1.1")

		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.NotEmpty(t, familyID)

		// Token should be base64 encoded (44 chars for 32 bytes)
		assert.Greater(t, len(token), 40)

		mockRepo.AssertExpectations(t)
	})

	t.Run("stores hashed token in database", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		var capturedToken *dbmodel.RefreshToken
		mockRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Run(func(args mock.Arguments) {
			capturedToken = args.Get(0).(*dbmodel.RefreshToken)
		}).Return(&dbmodel.RefreshToken{}, nil)

		token, _, err := authService.GenerateRefreshToken(123, "test-agent", "192.168.1.1")

		require.NoError(t, err)

		// Verify token is hashed (should be SHA256 hash of the token)
		expectedHash := sha256.Sum256([]byte(token))
		expectedHashString := base64.URLEncoding.EncodeToString(expectedHash[:])

		assert.Equal(t, expectedHashString, capturedToken.TokenHash)
		assert.NotEqual(t, token, capturedToken.TokenHash, "Token should be hashed, not stored in plain text")

		mockRepo.AssertExpectations(t)
	})

	t.Run("generates unique family ID", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		mockRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Return(&dbmodel.RefreshToken{}, nil)

		_, familyID1, err := authService.GenerateRefreshToken(123, "test-agent", "192.168.1.1")
		require.NoError(t, err)

		_, familyID2, err := authService.GenerateRefreshToken(123, "test-agent", "192.168.1.1")
		require.NoError(t, err)

		assert.NotEqual(t, familyID1, familyID2, "Each token should have a unique family ID")

		mockRepo.AssertExpectations(t)
	})

	t.Run("captures user agent and IP address", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		userAgent := "Mozilla/5.0 Test Browser"
		ipAddress := "203.0.113.42"

		var capturedToken *dbmodel.RefreshToken
		mockRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Run(func(args mock.Arguments) {
			capturedToken = args.Get(0).(*dbmodel.RefreshToken)
		}).Return(&dbmodel.RefreshToken{}, nil)

		_, _, err := authService.GenerateRefreshToken(123, userAgent, ipAddress)

		require.NoError(t, err)
		assert.Equal(t, userAgent, capturedToken.UserAgent)
		assert.Equal(t, ipAddress, capturedToken.IPAddress)

		mockRepo.AssertExpectations(t)
	})

	t.Run("sets correct expiration time", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		var capturedToken *dbmodel.RefreshToken
		mockRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Run(func(args mock.Arguments) {
			capturedToken = args.Get(0).(*dbmodel.RefreshToken)
		}).Return(&dbmodel.RefreshToken{}, nil)

		beforeTime := time.Now()
		_, _, err := authService.GenerateRefreshToken(123, "test-agent", "192.168.1.1")
		afterTime := time.Now()

		require.NoError(t, err)

		// ExpiresAt should be approximately 7 days from now
		expectedExpiry := beforeTime.Add(authService.Constants.JWT.RefreshTokenTTL)
		assert.WithinDuration(t, expectedExpiry, capturedToken.ExpiresAt, afterTime.Sub(beforeTime)+time.Second)

		mockRepo.AssertExpectations(t)
	})
}

func TestValidateRefreshToken(t *testing.T) {
	t.Run("accepts valid non-expired token", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		token := "valid-token"
		tokenHash, _ := hashRefreshToken(token)

		dbToken := &dbmodel.RefreshToken{
			UserID:    123,
			TokenHash: tokenHash,
			ExpiresAt: time.Now().Add(24 * time.Hour),
			RevokedAt: nil,
		}

		mockRepo.On("FindByTokenHash", tokenHash).Return(dbToken, nil)

		userID, err := authService.ValidateRefreshToken(token)

		require.NoError(t, err)
		assert.Equal(t, uint(123), userID)

		mockRepo.AssertExpectations(t)
	})

	t.Run("rejects expired token", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		token := "expired-token"
		tokenHash, _ := hashRefreshToken(token)

		dbToken := &dbmodel.RefreshToken{
			UserID:    123,
			TokenHash: tokenHash,
			ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
			RevokedAt: nil,
		}

		mockRepo.On("FindByTokenHash", tokenHash).Return(dbToken, nil)

		_, err := authService.ValidateRefreshToken(token)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenExpiredError{}, err)

		mockRepo.AssertExpectations(t)
	})

	t.Run("rejects revoked token", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		token := "revoked-token"
		tokenHash, _ := hashRefreshToken(token)

		// FindByTokenHash filters out revoked tokens, so it returns nil
		mockRepo.On("FindByTokenHash", tokenHash).Return(nil, nil)

		_, err := authService.ValidateRefreshToken(token)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenInvalidError{}, err) // Changed from RefreshTokenRevokedError

		mockRepo.AssertExpectations(t)
	})

	t.Run("rejects non-existent token", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		token := "non-existent-token"
		tokenHash, _ := hashRefreshToken(token)

		mockRepo.On("FindByTokenHash", tokenHash).Return(nil, nil)

		_, err := authService.ValidateRefreshToken(token)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenInvalidError{}, err)

		mockRepo.AssertExpectations(t)
	})
}

func TestRotateRefreshToken(t *testing.T) {
	t.Run("revokes old token and creates new one in same family", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		oldToken := "old-token"
		oldTokenHash, _ := hashRefreshToken(oldToken)
		familyID := "test-family-id"

		dbToken := createTestRefreshToken(
			1,
			123,
			oldTokenHash,
			familyID,
			time.Now().Add(24*time.Hour),
			nil,
		)

		mockRepo.On("FindByTokenHashIncludingRevoked", oldTokenHash).Return(dbToken, nil)
		mockRepo.On("UpdateLastUsed", uint(1)).Return(nil)
		mockRepo.On("RevokeByID", uint(1)).Return(nil)

		var capturedNewToken *dbmodel.RefreshToken
		mockRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Run(func(args mock.Arguments) {
			capturedNewToken = args.Get(0).(*dbmodel.RefreshToken)
		}).Return(&dbmodel.RefreshToken{}, nil)

		newToken, err := authService.RotateRefreshToken(oldToken, "test-agent", "192.168.1.1")

		require.NoError(t, err)
		assert.NotEmpty(t, newToken)
		assert.NotEqual(t, oldToken, newToken)

		// Verify new token is in same family
		assert.Equal(t, familyID, capturedNewToken.FamilyID)
		assert.Equal(t, uint(123), capturedNewToken.UserID)

		mockRepo.AssertExpectations(t)
	})

	t.Run("detects token reuse and revokes entire family", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		reuseToken := "reused-token"
		reuseTokenHash, _ := hashRefreshToken(reuseToken)
		familyID := "test-family-id"
		revokedTime := time.Now().Add(-1 * time.Hour)

		dbToken := createTestRefreshToken(
			1,
			123,
			reuseTokenHash,
			familyID,
			time.Now().Add(24*time.Hour),
			&revokedTime, // Already revoked
		)

		mockRepo.On("FindByTokenHashIncludingRevoked", reuseTokenHash).Return(dbToken, nil)
		mockRepo.On("RevokeByFamilyID", familyID).Return(nil)

		_, err := authService.RotateRefreshToken(reuseToken, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenReuseDetectedError{}, err)

		mockRepo.AssertCalled(t, "RevokeByFamilyID", familyID)
		mockRepo.AssertExpectations(t)
	})

	t.Run("rejects expired token during rotation", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		expiredToken := "expired-token"
		expiredTokenHash, _ := hashRefreshToken(expiredToken)

		dbToken := createTestRefreshToken(
			1,
			123,
			expiredTokenHash,
			"test-family",
			time.Now().Add(-24*time.Hour), // Expired
			nil,
		)

		mockRepo.On("FindByTokenHashIncludingRevoked", expiredTokenHash).Return(dbToken, nil)

		_, err := authService.RotateRefreshToken(expiredToken, "test-agent", "192.168.1.1")

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenExpiredError{}, err)

		mockRepo.AssertExpectations(t)
	})

	t.Run("updates last used timestamp before rotation", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		oldToken := "old-token"
		oldTokenHash, _ := hashRefreshToken(oldToken)

		dbToken := createTestRefreshToken(
			1,
			123,
			oldTokenHash,
			"test-family",
			time.Now().Add(24*time.Hour),
			nil,
		)

		mockRepo.On("FindByTokenHashIncludingRevoked", oldTokenHash).Return(dbToken, nil)
		mockRepo.On("UpdateLastUsed", uint(1)).Return(nil)
		mockRepo.On("RevokeByID", uint(1)).Return(nil)
		mockRepo.On("Create", mock.AnythingOfType("*dbmodel.RefreshToken")).Return(&dbmodel.RefreshToken{}, nil)

		_, err := authService.RotateRefreshToken(oldToken, "test-agent", "192.168.1.1")

		require.NoError(t, err)
		mockRepo.AssertCalled(t, "UpdateLastUsed", uint(1))
		mockRepo.AssertExpectations(t)
	})
}

func TestRevokeRefreshToken(t *testing.T) {
	t.Run("successfully revokes valid token", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		token := "valid-token"
		tokenHash, _ := hashRefreshToken(token)

		dbToken := createTestRefreshToken(1, 123, tokenHash, "family", time.Now().Add(24*time.Hour), nil)

		mockRepo.On("FindByTokenHashIncludingRevoked", tokenHash).Return(dbToken, nil)
		mockRepo.On("RevokeByID", uint(1)).Return(nil)

		err := authService.RevokeRefreshToken(token)

		require.NoError(t, err)
		mockRepo.AssertExpectations(t)
	})

	t.Run("returns error for non-existent token", func(t *testing.T) {
		mockRepo := new(MockRefreshTokenRepository)
		authService := setupAuthService(mockRepo)

		token := "non-existent-token"
		tokenHash, _ := hashRefreshToken(token)

		mockRepo.On("FindByTokenHashIncludingRevoked", tokenHash).Return(nil, nil)

		err := authService.RevokeRefreshToken(token)

		assert.Error(t, err)
		assert.IsType(t, &errormsg.RefreshTokenInvalidError{}, err)

		mockRepo.AssertExpectations(t)
	})
}
