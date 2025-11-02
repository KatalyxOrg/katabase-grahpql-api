package user

import (
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
)

// New create a new instance of the users service with the given configuration.
// It takes a configuration object as a parameter and returns a new instance of the user service.
func New(config *config.Config) *UsersService {
	return &UsersService{config}
}

// Get returns the user with the given ID.
// It takes an uint as a parameter and a dbmodel.UserFieldsToInclude object and returns a (dbmodel.User, error) object.
func (config *UsersService) Get(id uint, fieldsToInclude *dbmodel.UserFieldsToInclude) (*dbmodel.User, error) {
	return config.UserRepository.FindByID(uint(id), fieldsToInclude)
}
