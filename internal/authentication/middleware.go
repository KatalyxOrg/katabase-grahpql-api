package authentication

import (
	"context"
	"net/http"

	"github.com/99designs/gqlgen/graphql/handler/transport"
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
)

var UserCtxKey = contextKey{"user"}

type contextKey struct {
	name string
}

func Middleware(c *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")

			if header == "" {
				next.ServeHTTP(w, r)
				return
			}

			tokenString := header
			userID, err := ParseToken(c.Constants.JWT.Secret, tokenString)

			if err != nil {
				http.Error(w, "Invalid token", http.StatusForbidden)
				return
			}

			var user *dbmodel.User
			user, err = c.UserRepository.FindByID(userID, &dbmodel.UserFieldsToInclude{
				UserProfile:       false,
				Roles:             true,
				Roles_Permissions: true,
			})

			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			userCtx := context.WithValue(r.Context(), UserCtxKey, user)

			r = r.WithContext(userCtx)
			next.ServeHTTP(w, r)
		})
	}
}

// WebsocketInitFunc handles WebSocket authentication during connection initialization
func WebsocketInitFunc(ctx context.Context, initPayload transport.InitPayload, config *config.Config) (context.Context, *transport.InitPayload, error) {
	// Try to get token from initPayload first (recommended approach)
	var tokenString string

	// Check if authorization is provided in the connection parameters
	if auth, ok := initPayload["Authorization"]; ok {
		if authStr, ok := auth.(string); ok {
			tokenString = authStr
		}
	}

	// Also check for "authorization" (case-insensitive)
	if tokenString == "" {
		if auth, ok := initPayload["authorization"]; ok {
			if authStr, ok := auth.(string); ok {
				tokenString = authStr
			}
		}
	}

	// Check for token in other common formats
	if tokenString == "" {
		if token, ok := initPayload["token"]; ok {
			if tokenStr, ok := token.(string); ok {
				tokenString = tokenStr
			}
		}
	}

	// If no token provided, return context without user (allows anonymous access)
	if tokenString == "" {
		return ctx, &initPayload, nil
	}

	// Parse the token
	userID, err := ParseToken(config.Constants.JWT.Secret, tokenString)
	if err != nil {
		// Return error for invalid tokens
		return ctx, nil, err
	}

	// Load user from database
	user, err := config.UserRepository.FindByID(userID, &dbmodel.UserFieldsToInclude{
		UserProfile:       false,
		Roles:             true,
		Roles_Permissions: true,
	})

	if err != nil || user == nil {
		// Return error if user not found
		return ctx, nil, err
	}

	// Add user to context
	userCtx := context.WithValue(ctx, UserCtxKey, user)

	return userCtx, &initPayload, nil
}

func ForContext(ctx context.Context) *dbmodel.User {
	rawUser, _ := ctx.Value(UserCtxKey).(*dbmodel.User)

	return rawUser
}

// WithAuthContext adds authentication context for testing purposes
func WithAuthContext(ctx context.Context, userID uint, token string) context.Context {
	// For testing, we create a minimal User object
	// In real tests, the full user should be loaded from DB for accurate RBAC
	user := &dbmodel.User{}
	user.ID = userID
	return context.WithValue(ctx, UserCtxKey, user)
}
