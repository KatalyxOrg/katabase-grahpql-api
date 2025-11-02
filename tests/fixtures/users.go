//go:build integration
// +build integration

package fixtures

import (
	"fmt"

	"gorm.io/gorm"
	"katalyx.fr/katabasegql/internal/authentication"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
)

var userCounter = 0

// CreateAdminUser creates a user with admin role and all permissions
func CreateAdminUser(db *gorm.DB) *dbmodel.User {
	userCounter++
	email := fmt.Sprintf("admin%d@test.com", userCounter)

	passwordHash, _ := authentication.HashPassword("Admin123!")

	// Get admin role
	var adminRole dbmodel.Role
	db.Where("name = ?", "admin").Preload("Permissions").First(&adminRole)

	user := &dbmodel.User{
		Email:        email,
		PasswordHash: &passwordHash,
		Roles:        []dbmodel.Role{adminRole},
		UserProfile: dbmodel.UserProfile{
			FirstName: "Admin",
			LastName:  stringPtr("User"),
		},
	}

	db.Create(user)

	// Reload with associations
	db.Where("id = ?", user.ID).
		Preload("Roles").
		Preload("Roles.Permissions").
		Preload("UserProfile").
		First(user)

	return user
}

// CreateRegularUser creates a user with default user role
func CreateRegularUser(db *gorm.DB) *dbmodel.User {
	userCounter++
	email := fmt.Sprintf("user%d@test.com", userCounter)

	passwordHash, _ := authentication.HashPassword("User123!")

	// Get user role
	var userRole dbmodel.Role
	db.Where("name = ?", "user").Preload("Permissions").First(&userRole)

	user := &dbmodel.User{
		Email:        email,
		PasswordHash: &passwordHash,
		Roles:        []dbmodel.Role{userRole},
		UserProfile: dbmodel.UserProfile{
			FirstName: "Regular",
			LastName:  stringPtr("User"),
		},
	}

	result := db.Create(user)
	if result.Error != nil {
		panic(fmt.Sprintf("Failed to create regular user %s: %v", email, result.Error))
	}

	// Reload with associations
	db.Where("id = ?", user.ID).
		Preload("Roles").
		Preload("Roles.Permissions").
		Preload("UserProfile").
		First(user)

	return user
}

// CreateLandlordUser creates a user with landlord role
func CreateLandlordUser(db *gorm.DB) *dbmodel.User {
	userCounter++
	email := fmt.Sprintf("landlord%d@test.com", userCounter)

	passwordHash, _ := authentication.HashPassword("Landlord123!")

	// Get user role (landlord role might not exist yet, use user role)
	var userRole dbmodel.Role
	db.Where("name = ?", "user").Preload("Permissions").First(&userRole)

	user := &dbmodel.User{
		Email:        email,
		PasswordHash: &passwordHash,
		Roles:        []dbmodel.Role{userRole},
		UserProfile: dbmodel.UserProfile{
			FirstName: "Landlord",
			LastName:  stringPtr("Owner"),
		},
	}

	db.Create(user)

	// Reload with associations
	db.Where("id = ?", user.ID).
		Preload("Roles").
		Preload("Roles.Permissions").
		Preload("UserProfile").
		First(user)

	return user
}

// CreateOAuthUser creates a user without password (OAuth scenario)
func CreateOAuthUser(db *gorm.DB) *dbmodel.User {
	userCounter++
	email := fmt.Sprintf("oauth%d@test.com", userCounter)

	// Get user role
	var userRole dbmodel.Role
	db.Where("name = ?", "user").Preload("Permissions").First(&userRole)

	user := &dbmodel.User{
		Email:        email,
		PasswordHash: nil, // No password for OAuth users
		Roles:        []dbmodel.Role{userRole},
		UserProfile: dbmodel.UserProfile{
			FirstName: "OAuth",
			LastName:  stringPtr("User"),
		},
	}

	db.Create(user)

	// Reload with associations
	db.Where("id = ?", user.ID).
		Preload("Roles").
		Preload("Roles.Permissions").
		Preload("UserProfile").
		First(user)

	return user
}

// CreateUserWithProfile creates a user with complete profile
func CreateUserWithProfile(db *gorm.DB, firstName string, lastName string, email string) *dbmodel.User {
	passwordHash, _ := authentication.HashPassword("Test123!")

	var userRole dbmodel.Role
	db.Where("name = ?", "user").Preload("Permissions").First(&userRole)

	phone := "+33612345678"
	user := &dbmodel.User{
		Email:        email,
		PasswordHash: &passwordHash,
		Roles:        []dbmodel.Role{userRole},
		UserProfile: dbmodel.UserProfile{
			FirstName: firstName,
			LastName:  &lastName,
			Phone:     &phone,
		},
	}

	db.Create(user)

	// Reload with associations
	db.Where("id = ?", user.ID).
		Preload("Roles").
		Preload("Roles.Permissions").
		Preload("UserProfile").
		First(user)

	return user
}

// CreateUserWithAddress creates a user with complete profile and address
func CreateUserWithAddress(db *gorm.DB) *dbmodel.User {
	userCounter++
	email := fmt.Sprintf("useraddress%d@test.com", userCounter)

	passwordHash, _ := authentication.HashPassword("Test123!")

	var userRole dbmodel.Role
	db.Where("name = ?", "user").Preload("Permissions").First(&userRole)

	// Create address
	address := &dbmodel.Address{
		Number:        "123",
		Route:         "Rue de Test",
		OptionalRoute: nil,
		City:          "Paris",
		ZipCode:       "75001",
		Country:       "France",
		Latitude:      48.8566,
		Longitude:     2.3522,
	}
	db.Create(address)

	phone := "+33612345678"
	user := &dbmodel.User{
		Email:        email,
		PasswordHash: &passwordHash,
		Roles:        []dbmodel.Role{userRole},
		UserProfile: dbmodel.UserProfile{
			FirstName: "User",
			LastName:  stringPtr("WithAddress"),
			Phone:     &phone,
			AddressID: &address.ID,
		},
	}

	db.Create(user)

	// Reload with associations
	db.Where("id = ?", user.ID).
		Preload("Roles").
		Preload("Roles.Permissions").
		Preload("UserProfile").
		Preload("UserProfile.Address").
		First(user)

	return user
}

func stringPtr(s string) *string {
	return &s
}
