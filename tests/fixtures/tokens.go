//go:build integration
// +build integration

package fixtures

import (
	"time"

	"gorm.io/gorm"
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/internal/authentication"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
)

const TestJWTSecret = "test-secret-key-for-integration-tests"

// GenerateValidAccessToken generates a valid JWT access token for testing
func GenerateValidAccessToken(userID uint, permissions []string) (string, error) {
	token, _, err := authentication.GenerateToken(TestJWTSecret, userID, 15*time.Minute)
	return token, err
}

// GenerateExpiredAccessToken generates an expired JWT access token for testing
func GenerateExpiredAccessToken(userID uint) (string, error) {
	token, _, err := authentication.GenerateToken(TestJWTSecret, userID, -1*time.Hour)
	return token, err
}

// GenerateValidRefreshToken generates a valid refresh token and stores it in DB
func GenerateValidRefreshToken(db *gorm.DB, userID uint) (string, error) {
	cfg := &config.Config{
		RefreshTokenRepository: dbmodel.NewRefreshTokenRepository(db),
	}
	cfg.Constants.JWT.RefreshTokenTTL = 7 * 24 * time.Hour

	authService := &authentication.AuthenticationService{Config: cfg}
	token, _, err := authService.GenerateRefreshToken(userID, "test-user-agent", "127.0.0.1")
	return token, err
}

// GenerateExpiredRefreshToken generates an expired refresh token in DB
func GenerateExpiredRefreshToken(db *gorm.DB, userID uint) (string, error) {
	cfg := &config.Config{
		RefreshTokenRepository: dbmodel.NewRefreshTokenRepository(db),
	}
	cfg.Constants.JWT.RefreshTokenTTL = -1 * time.Hour // Already expired

	authService := &authentication.AuthenticationService{Config: cfg}
	token, _, err := authService.GenerateRefreshToken(userID, "test-user-agent", "127.0.0.1")
	return token, err
}

// GenerateRevokedRefreshToken generates a refresh token and immediately revokes it
func GenerateRevokedRefreshToken(db *gorm.DB, userID uint) (string, error) {
	token, err := GenerateValidRefreshToken(db, userID)
	if err != nil {
		return "", err
	}

	// Revoke the token
	tokenHash, _ := authentication.HashRefreshToken(token)
	var dbToken dbmodel.RefreshToken
	db.Where("token_hash = ?", tokenHash).First(&dbToken)

	now := time.Now()
	dbToken.RevokedAt = &now
	db.Save(&dbToken)

	return token, nil
}

// CreateRefreshTokenFamily creates a family of refresh tokens for reuse detection testing
func CreateRefreshTokenFamily(db *gorm.DB, userID uint, familyID string, count int) ([]string, error) {
	tokens := make([]string, count)

	cfg := &config.Config{
		RefreshTokenRepository: dbmodel.NewRefreshTokenRepository(db),
	}
	cfg.Constants.JWT.RefreshTokenTTL = 7 * 24 * time.Hour
	authService := &authentication.AuthenticationService{Config: cfg}

	for i := 0; i < count; i++ {
		token, _, err := authService.GenerateRefreshToken(userID, "test-user-agent", "127.0.0.1")
		if err != nil {
			return nil, err
		}

		// Update family ID
		tokenHash, _ := authentication.HashRefreshToken(token)
		var dbToken dbmodel.RefreshToken
		db.Where("token_hash = ?", tokenHash).First(&dbToken)
		dbToken.FamilyID = familyID
		db.Save(&dbToken)

		tokens[i] = token
	}

	return tokens, nil
}
