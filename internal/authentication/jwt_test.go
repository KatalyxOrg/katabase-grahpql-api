package authentication

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-secret-key-for-jwt"

func TestGenerateToken(t *testing.T) {
	t.Run("creates valid token with correct claims", func(t *testing.T) {
		userID := uint(123)
		ttl := 15 * time.Minute

		tokenString, jti, err := GenerateToken(testSecret, userID, ttl)

		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)
		assert.NotEmpty(t, jti)

		// Parse and verify token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(testSecret), nil
		})
		require.NoError(t, err)
		assert.True(t, token.Valid)

		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)

		// Verify claims
		assert.Equal(t, float64(userID), claims["id"])
		assert.Equal(t, jti, claims["jti"])
		assert.NotNil(t, claims["exp"])
		assert.NotNil(t, claims["iat"])
	})

	t.Run("respects custom TTL", func(t *testing.T) {
		userID := uint(456)
		ttl := 1 * time.Hour

		tokenString, _, err := GenerateToken(testSecret, userID, ttl)
		require.NoError(t, err)

		// Parse token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(testSecret), nil
		})
		require.NoError(t, err)

		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)

		// Verify expiration is approximately 1 hour from now
		exp := int64(claims["exp"].(float64))
		iat := int64(claims["iat"].(float64))
		actualTTL := exp - iat

		// Allow 1 second tolerance
		assert.InDelta(t, int64(ttl.Seconds()), actualTTL, 1)
	})

	t.Run("generates unique JTI for each token", func(t *testing.T) {
		userID := uint(789)
		ttl := 15 * time.Minute

		_, jti1, err := GenerateToken(testSecret, userID, ttl)
		require.NoError(t, err)

		_, jti2, err := GenerateToken(testSecret, userID, ttl)
		require.NoError(t, err)

		assert.NotEqual(t, jti1, jti2, "Each token should have a unique JTI")
	})

	t.Run("token contains required fields", func(t *testing.T) {
		userID := uint(999)
		ttl := 30 * time.Minute

		tokenString, jti, err := GenerateToken(testSecret, userID, ttl)
		require.NoError(t, err)

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte(testSecret), nil
		})
		require.NoError(t, err)

		claims, ok := token.Claims.(jwt.MapClaims)
		require.True(t, ok)

		// Check all required fields exist
		assert.Contains(t, claims, "id")
		assert.Contains(t, claims, "jti")
		assert.Contains(t, claims, "exp")
		assert.Contains(t, claims, "iat")

		// Verify JTI matches returned value
		assert.Equal(t, jti, claims["jti"])
	})
}

func TestParseToken(t *testing.T) {
	t.Run("correctly extracts user ID from valid token", func(t *testing.T) {
		userID := uint(123)
		ttl := 15 * time.Minute

		tokenString, _, err := GenerateToken(testSecret, userID, ttl)
		require.NoError(t, err)

		parsedUserID, err := ParseToken(testSecret, tokenString)
		require.NoError(t, err)
		assert.Equal(t, userID, parsedUserID)
	})

	t.Run("handles Bearer prefix in token string", func(t *testing.T) {
		userID := uint(456)
		ttl := 15 * time.Minute

		tokenString, _, err := GenerateToken(testSecret, userID, ttl)
		require.NoError(t, err)

		// Add Bearer prefix
		bearerToken := "Bearer " + tokenString

		parsedUserID, err := ParseToken(testSecret, bearerToken)
		require.NoError(t, err)
		assert.Equal(t, userID, parsedUserID)
	})

	t.Run("rejects expired tokens", func(t *testing.T) {
		userID := uint(789)
		ttl := -1 * time.Hour // Negative TTL creates already expired token

		tokenString, _, err := GenerateToken(testSecret, userID, ttl)
		require.NoError(t, err)

		_, err = ParseToken(testSecret, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("rejects malformed tokens", func(t *testing.T) {
		malformedToken := "not.a.valid.jwt.token"

		_, err := ParseToken(testSecret, malformedToken)
		assert.Error(t, err)
	})

	t.Run("rejects tokens with invalid signature", func(t *testing.T) {
		userID := uint(321)
		ttl := 15 * time.Minute

		// Generate token with different secret
		tokenString, _, err := GenerateToken("different-secret", userID, ttl)
		require.NoError(t, err)

		// Try to parse with testSecret
		_, err = ParseToken(testSecret, tokenString)
		assert.Error(t, err)
	})

	t.Run("handles missing user ID claim", func(t *testing.T) {
		// Create token without user ID
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["jti"] = "some-jti"
		claims["exp"] = time.Now().Add(15 * time.Minute).Unix()
		claims["iat"] = time.Now().Unix()
		// Intentionally omit "id" claim

		tokenString, err := token.SignedString([]byte(testSecret))
		require.NoError(t, err)

		_, err = ParseToken(testSecret, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("handles empty user ID claim", func(t *testing.T) {
		// Create token with empty user ID
		token := jwt.New(jwt.SigningMethodHS256)
		claims := token.Claims.(jwt.MapClaims)
		claims["id"] = ""
		claims["jti"] = "some-jti"
		claims["exp"] = time.Now().Add(15 * time.Minute).Unix()
		claims["iat"] = time.Now().Unix()

		tokenString, err := token.SignedString([]byte(testSecret))
		require.NoError(t, err)

		_, err = ParseToken(testSecret, tokenString)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid token")
	})

	t.Run("handles completely invalid token format", func(t *testing.T) {
		invalidTokens := []string{
			"",
			"random-string",
			"Bearer ",
			"Bearer",
			strings.Repeat("a", 1000),
		}

		for _, invalidToken := range invalidTokens {
			_, err := ParseToken(testSecret, invalidToken)
			assert.Error(t, err, "Should reject invalid token: %s", invalidToken)
		}
	})
}
