package authentication

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

func GenerateToken(secret string, id uint, ttl time.Duration) (string, string, error) {
	secretKey := []byte(secret)
	token := jwt.New(jwt.SigningMethodHS256)

	jti := uuid.New().String()

	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = id
	claims["jti"] = jti
	claims["exp"] = time.Now().Add(ttl).Unix()
	claims["iat"] = time.Now().Unix()

	tokenString, err := token.SignedString(secretKey)

	if err != nil {
		return "", "", err
	}

	return tokenString, jti, nil
}

func ParseToken(secret string, tokenString string) (uint, error) {
	secretKey := []byte(secret)
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["id"] == nil || claims["id"] == "" {
			return 0, errors.New("invalid token")
		}

		id := claims["id"].(float64)

		return uint(id), nil
	} else {
		return 0, err
	}
}
