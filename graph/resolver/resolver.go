//go:generate go run github.com/99designs/gqlgen generate

package resolver

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

import (
	"katalyx.fr/katabasegql/internal/authentication"
	"katalyx.fr/katabasegql/internal/user"
	"katalyx.fr/katabasegql/pkg/maps"
)

type Resolver struct {
	AuthenticationService *authentication.AuthenticationService
	MapsService           *maps.Config
	UsersService          *user.UsersService
}
