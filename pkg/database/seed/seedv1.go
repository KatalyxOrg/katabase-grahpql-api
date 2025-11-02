package seed

import (
	"gorm.io/gorm"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
)

func ptr[T any](v T) *T {
	return &v
}

func SeedV1(database *gorm.DB) error {
	// Create permissions
	permissions := []dbmodel.Permission{
		{Model: gorm.Model{ID: 1}, Name: "create:user", ReadableName: ptr("Create User"), Description: ptr("Allows creating new users"), Category: ptr("User Management")},
		{Model: gorm.Model{ID: 2}, Name: "read:user", ReadableName: ptr("Read User"), Description: ptr("Allows reading user data"), Category: ptr("User Management")},
		{Model: gorm.Model{ID: 3}, Name: "read:user:self", ReadableName: ptr("Read User Self"), Description: ptr("Allows reading own user data"), Category: ptr("User Management")},
		{Model: gorm.Model{ID: 4}, Name: "update:user", ReadableName: ptr("Update User"), Description: ptr("Allows updating user data"), Category: ptr("User Management")},
		{Model: gorm.Model{ID: 5}, Name: "update:user:self", ReadableName: ptr("Update User Self"), Description: ptr("Allows updating own user data"), Category: ptr("User Management")},
		{Model: gorm.Model{ID: 6}, Name: "delete:user", ReadableName: ptr("Delete User"), Description: ptr("Allows deleting user data"), Category: ptr("User Management")},
		{Model: gorm.Model{ID: 7}, Name: "delete:user:self", ReadableName: ptr("Delete User Self"), Description: ptr("Allows deleting own user data"), Category: ptr("User Management")},
	}

	for _, permission := range permissions {
		database.Create(&permission)
	}

	// Create roles
	roles := []dbmodel.Role{
		{
			Model: gorm.Model{ID: 1},
			Name:  "admin",
			Permissions: []dbmodel.Permission{
				permissions[0], // create:user
				permissions[1], // read:user
				permissions[2], // read:user:self
				permissions[3], // update:user
				permissions[4], // update:user:self
				permissions[5], // delete:user
				permissions[6], // delete:user:self
			},
		},
		{
			Model: gorm.Model{ID: 2},
			Name:  "user",
			Permissions: []dbmodel.Permission{
				permissions[2], // read:user:self
				permissions[4], // update:user:self
				permissions[6], // delete:user:self
			},
		},
		{
			Model: gorm.Model{ID: 3},
			Name:  "landlord",
			Permissions: []dbmodel.Permission{
				permissions[2], // read:user:self
				permissions[4], // update:user:self
				permissions[6], // delete:user:self
			},
		},
	}

	for _, role := range roles {
		database.Create(&role)
	}

	return nil
}
