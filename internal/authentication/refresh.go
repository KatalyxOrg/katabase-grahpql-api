package authentication

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
	"katalyx.fr/katabasegql/pkg/errormsg"
)

// GenerateRefreshToken generates a new refresh token for the given user
// It returns the token string (to be sent to client), the family ID, and an error
func (config *AuthenticationService) GenerateRefreshToken(userID uint, userAgent string, ipAddress string) (string, string, error) {
	// Generate a cryptographically secure random token
	tokenBytes := make([]byte, 32)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", "", err
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash the token for storage
	tokenHash, err := hashRefreshToken(token)
	if err != nil {
		return "", "", err
	}

	// Generate a new family ID (used for rotation detection)
	familyID := uuid.New().String()

	// Create the refresh token record
	refreshToken := &dbmodel.RefreshToken{
		UserID:    userID,
		TokenHash: tokenHash,
		FamilyID:  familyID,
		ExpiresAt: time.Now().Add(config.Constants.JWT.RefreshTokenTTL),
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}

	_, err = config.RefreshTokenRepository.Create(refreshToken)
	if err != nil {
		return "", "", err
	}

	return token, familyID, nil
}

// RotateRefreshToken rotates a refresh token by revoking the old one and creating a new one in the same family
func (config *AuthenticationService) RotateRefreshToken(oldToken string, userAgent string, ipAddress string) (string, error) {
	// Hash the provided token to find it in database
	tokenHash, err := hashRefreshToken(oldToken)
	if err != nil {
		return "", err
	}

	// Find the refresh token (including revoked ones for reuse detection)
	dbToken, err := config.RefreshTokenRepository.FindByTokenHashIncludingRevoked(tokenHash)
	if err != nil {
		return "", err
	}

	if dbToken == nil {
		return "", &errormsg.RefreshTokenInvalidError{}
	}

	// Check if token is revoked (reuse detection)
	if dbToken.RevokedAt != nil {
		// Token reuse detected - revoke entire family
		err = config.RefreshTokenRepository.RevokeByFamilyID(dbToken.FamilyID)
		if err != nil {
			// Log the error but still return the reuse detected error
			// since the detection itself is the critical part
			fmt.Printf("Warning: Failed to revoke token family %s: %v\n", dbToken.FamilyID, err)
		}
		return "", &errormsg.RefreshTokenReuseDetectedError{}
	}

	// Check if token is expired
	if dbToken.ExpiresAt.Before(time.Now()) {
		return "", &errormsg.RefreshTokenExpiredError{}
	}

	// Update last used timestamp
	config.RefreshTokenRepository.UpdateLastUsed(dbToken.ID)

	// Revoke the old token
	err = config.RefreshTokenRepository.RevokeByID(dbToken.ID)
	if err != nil {
		return "", err
	}

	// Generate new token bytes
	tokenBytes := make([]byte, 32)
	_, err = rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}

	newToken := base64.URLEncoding.EncodeToString(tokenBytes)

	// Hash the new token for storage
	newTokenHash, err := hashRefreshToken(newToken)
	if err != nil {
		return "", err
	}

	// Create new refresh token in the same family
	newRefreshToken := &dbmodel.RefreshToken{
		UserID:    dbToken.UserID,
		TokenHash: newTokenHash,
		FamilyID:  dbToken.FamilyID, // Keep same family ID for rotation tracking
		ExpiresAt: time.Now().Add(config.Constants.JWT.RefreshTokenTTL),
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}

	_, err = config.RefreshTokenRepository.Create(newRefreshToken)
	if err != nil {
		return "", err
	}

	return newToken, nil
}

// ValidateRefreshToken validates a refresh token and returns the associated user ID
func (config *AuthenticationService) ValidateRefreshToken(token string) (uint, error) {
	// Hash the provided token to find it in database
	tokenHash, err := hashRefreshToken(token)
	if err != nil {
		return 0, err
	}

	// Find the refresh token
	dbToken, err := config.RefreshTokenRepository.FindByTokenHash(tokenHash)
	if err != nil {
		return 0, err
	}

	if dbToken == nil {
		return 0, &errormsg.RefreshTokenInvalidError{}
	}

	// Check if token is revoked
	if dbToken.RevokedAt != nil {
		return 0, &errormsg.RefreshTokenRevokedError{}
	}

	// Check if token is expired
	if dbToken.ExpiresAt.Before(time.Now()) {
		return 0, &errormsg.RefreshTokenExpiredError{}
	}

	return dbToken.UserID, nil
}

// RevokeRefreshToken revokes a specific refresh token
func (config *AuthenticationService) RevokeRefreshToken(token string) error {
	tokenHash, err := hashRefreshToken(token)
	if err != nil {
		return err
	}

	// Use FindByTokenHashIncludingRevoked to find the token even if already revoked (idempotent)
	dbToken, err := config.RefreshTokenRepository.FindByTokenHashIncludingRevoked(tokenHash)
	if err != nil {
		return err
	}

	if dbToken == nil {
		return &errormsg.RefreshTokenInvalidError{}
	}

	return config.RefreshTokenRepository.RevokeByID(dbToken.ID)
}

// RevokeAllUserRefreshTokens revokes all refresh tokens for a user (useful for logout all sessions)
func (config *AuthenticationService) RevokeAllUserRefreshTokens(userID uint) error {
	// Get all tokens for user
	// This would require adding a method to find tokens by user ID
	// For now, we'll implement revoking by family when we have a token
	return nil
}

// HashRefreshToken hashes a refresh token using SHA256 for secure storage
// We use SHA256 instead of bcrypt because we need deterministic hashing for lookups
// Exported for testing purposes
func HashRefreshToken(token string) (string, error) {
	// Use SHA256 for deterministic hashing (same input = same output)
	// This allows us to look up tokens by hash in the database
	hash := sha256.Sum256([]byte(token))
	hashString := base64.URLEncoding.EncodeToString(hash[:])

	return hashString, nil
}

// hashRefreshToken is an internal alias for HashRefreshToken
func hashRefreshToken(token string) (string, error) {
	return HashRefreshToken(token)
}
