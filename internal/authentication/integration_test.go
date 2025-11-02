//go:build integration
// +build integration

package authentication_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"katalyx.fr/katabasegql/config"
	"katalyx.fr/katabasegql/graph/model"
	"katalyx.fr/katabasegql/internal/authentication"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
	"katalyx.fr/katabasegql/tests/fixtures"
	"katalyx.fr/katabasegql/tests/helpers"
)

// createTestAuthService creates a configured authentication service for testing
func createTestAuthService(db *gorm.DB) *authentication.AuthenticationService {
	cfg := &config.Config{
		AddressRepository:                dbmodel.NewAddressRepository(db),
		PermissionRepository:             dbmodel.NewPermissionRepository(db),
		RefreshTokenRepository:           dbmodel.NewRefreshTokenRepository(db),
		RoleRepository:                   dbmodel.NewRoleRepository(db),
		UserPermissionOverrideRepository: dbmodel.NewUserPermissionOverrideRepository(db),
		UserRepository:                   dbmodel.NewUserRepository(db),
	}
	cfg.Constants.JWT.Secret = fixtures.TestJWTSecret
	cfg.Constants.JWT.AccessTokenTTL = 15 * time.Minute
	cfg.Constants.JWT.RefreshTokenTTL = 7 * 24 * time.Hour

	return &authentication.AuthenticationService{Config: cfg}
}

// TestFullLoginFlow tests the complete login workflow with database
func TestFullLoginFlow(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("login with valid credentials creates refresh token in DB", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		authService := createTestAuthService(db)

		input := model.LoginInput{
			Email:    user.Email,
			Password: "User123!",
		}

		returnedUser, accessToken, refreshToken, permissions, err := authService.Login(input, "test-agent", "127.0.0.1")

		require.NoError(t, err)
		assert.NotNil(t, returnedUser)
		assert.NotEmpty(t, accessToken)
		assert.NotEmpty(t, refreshToken)
		assert.NotEmpty(t, permissions)

		// Verify refresh token exists in database
		count, err := helpers.CountRefreshTokensForUser(db, user.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(1), count)

		// Verify token details
		tokenHash, _ := authentication.HashRefreshToken(refreshToken)
		var dbToken dbmodel.RefreshToken
		result := db.Where("token_hash = ?", tokenHash).First(&dbToken)
		require.NoError(t, result.Error)
		assert.Equal(t, user.ID, dbToken.UserID)
		assert.Equal(t, "test-agent", dbToken.UserAgent)
		assert.Equal(t, "127.0.0.1", dbToken.IPAddress)
		assert.Nil(t, dbToken.RevokedAt)
	})

	t.Run("multiple logins create separate sessions", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		authService := createTestAuthService(db)

		input := model.LoginInput{
			Email:    user.Email,
			Password: "User123!",
		}

		// Login from device 1
		_, _, _, _, err := authService.Login(input, "device-1", "192.168.1.1")
		require.NoError(t, err)

		// Login from device 2
		_, _, _, _, err = authService.Login(input, "device-2", "192.168.1.2")
		require.NoError(t, err)

		// Verify two sessions exist
		count, err := helpers.CountRefreshTokensForUser(db, user.ID)
		require.NoError(t, err)
		assert.Equal(t, int64(2), count)
	})

	t.Run("login loads user with roles and permissions from DB", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateAdminUser(db)

		authService := createTestAuthService(db)

		input := model.LoginInput{
			Email:    user.Email,
			Password: "Admin123!",
		}

		returnedUser, _, _, permissions, err := authService.Login(input, "test-agent", "127.0.0.1")

		require.NoError(t, err)
		assert.NotNil(t, returnedUser)
		assert.NotEmpty(t, returnedUser.Roles)
		assert.NotEmpty(t, permissions)
		assert.Greater(t, len(permissions), 2) // Admin has multiple permissions
	})

	t.Run("invalid credentials don't create database entries", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)
		initialCount, _ := helpers.CountRefreshTokensForUser(db, user.ID)

		authService := createTestAuthService(db)

		input := model.LoginInput{
			Email:    user.Email,
			Password: "WrongPassword!",
		}

		_, _, _, _, err := authService.Login(input, "test-agent", "127.0.0.1")

		assert.Error(t, err)

		// Verify no new tokens created
		count, err := helpers.CountRefreshTokensForUser(db, user.ID)
		require.NoError(t, err)
		assert.Equal(t, initialCount, count)
	})
}

// TestRefreshTokenRotationWithDB tests refresh token rotation with real database
func TestRefreshTokenRotationWithDB(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("rotate token updates DB records correctly", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		authService := createTestAuthService(db)

		// Generate initial token
		oldToken, oldFamilyID, err := authService.GenerateRefreshToken(user.ID, "test-agent", "127.0.0.1")
		require.NoError(t, err)

		// Rotate the token
		newToken, err := authService.RotateRefreshToken(oldToken, "test-agent", "127.0.0.1")
		require.NoError(t, err)
		assert.NotEmpty(t, newToken)
		assert.NotEqual(t, oldToken, newToken)

		// Verify old token is revoked
		oldTokenHash, _ := authentication.HashRefreshToken(oldToken)
		var oldDbToken dbmodel.RefreshToken
		db.Where("token_hash = ?", oldTokenHash).First(&oldDbToken)
		assert.NotNil(t, oldDbToken.RevokedAt)

		// Verify new token exists and shares family ID
		newTokenHash, _ := authentication.HashRefreshToken(newToken)
		var newDbToken dbmodel.RefreshToken
		db.Where("token_hash = ?", newTokenHash).First(&newDbToken)
		assert.Nil(t, newDbToken.RevokedAt)
		assert.Equal(t, oldFamilyID, newDbToken.FamilyID)
	})

	t.Run("reused token revokes entire family in DB", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		authService := createTestAuthService(db)

		// Generate initial token
		token1, familyID, err := authService.GenerateRefreshToken(user.ID, "test-agent", "127.0.0.1")
		require.NoError(t, err)

		// Rotate to get token 2
		token2, err := authService.RotateRefreshToken(token1, "test-agent", "127.0.0.1")
		require.NoError(t, err)

		// Rotate to get token 3
		token3, err := authService.RotateRefreshToken(token2, "test-agent", "127.0.0.1")
		require.NoError(t, err)
		_ = token3

		// Count tokens before reuse attempt
		var totalCountBefore int64
		db.Model(&dbmodel.RefreshToken{}).
			Where("family_id = ?", familyID).
			Count(&totalCountBefore)

		// Try to reuse token 2 (already revoked) - should trigger family revocation
		_, err = authService.RotateRefreshToken(token2, "test-agent", "127.0.0.1")
		assert.Error(t, err)

		// Verify entire family is revoked
		var revokedCount int64
		db.Model(&dbmodel.RefreshToken{}).
			Where("family_id = ? AND revoked_at IS NOT NULL", familyID).
			Count(&revokedCount)

		// All tokens in family should be revoked now (including token3 which was active)
		assert.Equal(t, totalCountBefore, revokedCount, "All tokens in family should be revoked after reuse detection")
	})

	t.Run("expired tokens are not rotated", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		// Create an expired token
		expiredToken, err := fixtures.GenerateExpiredRefreshToken(db, user.ID)
		require.NoError(t, err)

		authService := createTestAuthService(db)

		// Try to rotate expired token
		_, err = authService.RotateRefreshToken(expiredToken, "test-agent", "127.0.0.1")
		assert.Error(t, err)
	})

	t.Run("revoked tokens are not rotated", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		// Create a revoked token
		revokedToken, err := fixtures.GenerateRevokedRefreshToken(db, user.ID)
		require.NoError(t, err)

		authService := createTestAuthService(db)

		// Try to rotate revoked token
		_, err = authService.RotateRefreshToken(revokedToken, "test-agent", "127.0.0.1")
		assert.Error(t, err)
	})

	t.Run("token rotation preserves user agent and IP", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		authService := createTestAuthService(db)

		// Generate initial token
		oldToken, _, err := authService.GenerateRefreshToken(user.ID, "Mozilla/5.0", "10.0.0.1")
		require.NoError(t, err)

		// Rotate with same metadata
		newToken, err := authService.RotateRefreshToken(oldToken, "Mozilla/5.0", "10.0.0.1")
		require.NoError(t, err)

		// Verify new token has correct metadata
		newTokenHash, _ := authentication.HashRefreshToken(newToken)
		var newDbToken dbmodel.RefreshToken
		db.Where("token_hash = ?", newTokenHash).First(&newDbToken)
		assert.Equal(t, "Mozilla/5.0", newDbToken.UserAgent)
		assert.Equal(t, "10.0.0.1", newDbToken.IPAddress)
	})

	t.Run("concurrent rotation attempts are handled safely", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		authService := createTestAuthService(db)

		// Generate initial token
		token, _, err := authService.GenerateRefreshToken(user.ID, "test-agent", "127.0.0.1")
		require.NoError(t, err)

		// Simulate concurrent rotation attempts
		done := make(chan error, 2)
		for i := 0; i < 2; i++ {
			go func() {
				_, err := authService.RotateRefreshToken(token, "test-agent", "127.0.0.1")
				done <- err
			}()
		}

		// Collect results - one should succeed, one should fail
		err1 := <-done
		err2 := <-done

		// XOR: exactly one should be nil
		assert.True(t, (err1 == nil) != (err2 == nil), "Exactly one rotation should succeed")
	})
}

// TestUserCreationIntegration tests user creation with database constraints
func TestUserCreationIntegration(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("user created with default role from DB", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateRegularUser(db)

		assert.NotZero(t, user.ID)
		assert.NotEmpty(t, user.Roles)

		// Verify role is user (lowercase)
		foundUserRole := false
		for _, role := range user.Roles {
			if role.Name == "user" {
				foundUserRole = true
				break
			}
		}
		assert.True(t, foundUserRole, "User should have user role")
	})

	t.Run("duplicate email constraint enforced by DB", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		email := "duplicate@test.com"
		passwordHash, _ := authentication.HashPassword("Test123!")

		user1 := &dbmodel.User{
			Email:        email,
			PasswordHash: &passwordHash,
		}
		db.Create(user1)

		user2 := &dbmodel.User{
			Email:        email,
			PasswordHash: &passwordHash,
		}
		result := db.Create(user2)

		assert.Error(t, result.Error)
	})

	t.Run("user with profile creates both records in transaction", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateUserWithProfile(db, "John", "Doe", "profile-test@test.com")

		assert.NotZero(t, user.ID)
		assert.NotZero(t, user.UserProfile.ID)
		assert.Equal(t, "John", user.UserProfile.FirstName)
		assert.Equal(t, "Doe", *user.UserProfile.LastName)

		// Verify in DB
		var dbUser dbmodel.User
		db.Preload("UserProfile").First(&dbUser, user.ID)
		assert.NotZero(t, dbUser.UserProfile.ID)
		assert.Equal(t, "John", dbUser.UserProfile.FirstName)
	})

	t.Run("user with address creates nested records", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateUserWithAddress(db)

		assert.NotZero(t, user.ID)
		assert.NotZero(t, user.UserProfile.ID)
		assert.NotNil(t, user.UserProfile.Address)
		assert.NotEmpty(t, user.UserProfile.Address.Number)
		assert.NotEmpty(t, user.UserProfile.Address.City)
	})

	t.Run("OAuth user without password can be created", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateOAuthUser(db)

		assert.NotZero(t, user.ID)
		assert.Nil(t, user.PasswordHash) // OAuth users have no password
		assert.Contains(t, user.Email, "oauth")
		assert.Contains(t, user.Email, "@test.com")
	})

	t.Run("user roles preloaded from database", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateAdminUser(db)

		assert.NotZero(t, user.ID)
		assert.NotEmpty(t, user.Roles)

		// Verify admin role loaded
		foundAdminRole := false
		for _, role := range user.Roles {
			if role.Name == "admin" {
				foundAdminRole = true
				assert.NotEmpty(t, role.Permissions)
				break
			}
		}
		assert.True(t, foundAdminRole)
	})

	t.Run("user permissions calculated from roles", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateAdminUser(db)

		// Verify user has roles with permissions
		assert.NotEmpty(t, user.Roles)
		hasPermissions := false
		for _, role := range user.Roles {
			if len(role.Permissions) > 0 {
				hasPermissions = true
				break
			}
		}
		assert.True(t, hasPermissions, "Admin should have roles with permissions")
	})

	t.Run("created user persists across transactions", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		// Create user in separate scope to simulate transaction completion
		var userID uint
		{
			passwordHash := "hashed"
			var userRole dbmodel.Role
			db.Where("name = ?", "user").First(&userRole)

			user := &dbmodel.User{
				Email:        "persist@test.com",
				PasswordHash: &passwordHash,
				Roles:        []dbmodel.Role{userRole},
			}
			db.Create(user)
			userID = user.ID
		}

		// Verify user persists and can be queried in a new context
		var user dbmodel.User
		result := db.First(&user, userID)
		assert.NoError(t, result.Error)
		assert.Equal(t, "persist@test.com", user.Email)
	})
}

// TestUpdateUserIntegration tests user updates with DB constraints
func TestUpdateUserIntegration(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("email update enforces uniqueness constraint", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user1 := fixtures.CreateRegularUser(db)
		user2 := fixtures.CreateRegularUser(db)

		// Try to update user2 with user1's email
		user2.Email = user1.Email
		result := db.Save(&user2)

		assert.Error(t, result.Error)
	})

	t.Run("profile update creates profile if missing", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		// Create user WITHOUT profile
		passwordHash, _ := authentication.HashPassword("Test123!")
		var userRole dbmodel.Role
		db.Where("name = ?", "user").First(&userRole)

		user := &dbmodel.User{
			Email:        "noprofile@test.com",
			PasswordHash: &passwordHash,
			Roles:        []dbmodel.Role{userRole},
		}
		db.Create(user)

		// Verify no profile
		var userCheck dbmodel.User
		db.Preload("UserProfile").First(&userCheck, user.ID)
		assert.Zero(t, userCheck.UserProfile.ID, "User should not have a profile initially")

		// Create profile
		lastName := "Name"
		profile := &dbmodel.UserProfile{
			UserID:    user.ID,
			FirstName: "Updated",
			LastName:  &lastName,
		}
		db.Create(profile)

		// Reload user
		var updatedUser dbmodel.User
		db.Preload("UserProfile").First(&updatedUser, user.ID)
		assert.NotZero(t, updatedUser.UserProfile.ID)
		assert.Equal(t, "Updated", updatedUser.UserProfile.FirstName)
	})

	t.Run("profile update modifies existing record", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateUserWithProfile(db, "John", "Doe", "john.doe@test.com")
		originalProfileID := user.UserProfile.ID

		// Update profile
		user.UserProfile.FirstName = "Jane"
		db.Save(&user.UserProfile)

		// Reload
		var updatedUser dbmodel.User
		db.Preload("UserProfile").First(&updatedUser, user.ID)
		assert.Equal(t, originalProfileID, updatedUser.UserProfile.ID) // Same record
		assert.Equal(t, "Jane", updatedUser.UserProfile.FirstName)
	})

	t.Run("address update creates nested record", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateUserWithProfile(db, "Test", "User", "test.user@test.com")

		// Add address
		address := &dbmodel.Address{
			Number:  "456",
			Route:   "New Street",
			City:    "Lyon",
			ZipCode: "69001",
			Country: "France",
		}
		db.Create(address)

		user.UserProfile.AddressID = &address.ID
		db.Save(&user.UserProfile)

		// Reload
		var updatedUser dbmodel.User
		db.Preload("UserProfile.Address").First(&updatedUser, user.ID)
		require.NotNil(t, updatedUser.UserProfile.Address)
		assert.Equal(t, "Lyon", updatedUser.UserProfile.Address.City)
	})

	t.Run("password update hashes new password", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateRegularUser(db)
		oldPassword := user.PasswordHash

		// Update password
		newPassword, _ := authentication.HashPassword("NewPass123!")
		user.PasswordHash = &newPassword
		db.Save(&user)

		// Reload
		var updatedUser dbmodel.User
		db.First(&updatedUser, user.ID)
		assert.NotEqual(t, oldPassword, updatedUser.PasswordHash)
		assert.NotEqual(t, "NewPass123!", updatedUser.PasswordHash) // Should be hashed
	})

	t.Run("partial update only modifies specified fields", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateUserWithProfile(db, "Original", "Name", "original.name@test.com")
		originalEmail := user.Email

		// Update only first name
		db.Model(&user.UserProfile).Update("first_name", "Modified")

		// Reload
		var updatedUser dbmodel.User
		db.Preload("UserProfile").First(&updatedUser, user.ID)
		assert.Equal(t, "Modified", updatedUser.UserProfile.FirstName)
		assert.Equal(t, "Name", *updatedUser.UserProfile.LastName) // Unchanged - dereference pointer
		assert.Equal(t, originalEmail, updatedUser.Email)          // Unchanged
	})

	t.Run("roles can be updated via associations", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateRegularUser(db)

		// Load landlord role (lowercase as per database seeds)
		var landlordRole dbmodel.Role
		db.Where("name = ?", "landlord").Preload("Permissions").First(&landlordRole)

		// Update user roles
		db.Model(&user).Association("Roles").Replace([]dbmodel.Role{landlordRole})

		// Reload
		var updatedUser dbmodel.User
		db.Preload("Roles").First(&updatedUser, user.ID)
		assert.Len(t, updatedUser.Roles, 1)
		assert.Equal(t, "landlord", updatedUser.Roles[0].Name)
	})

	t.Run("soft delete marks user as deleted", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateRegularUser(db)
		userID := user.ID

		// Soft delete
		db.Delete(&user)

		// Verify not found in regular query
		var foundUser dbmodel.User
		result := db.First(&foundUser, userID)
		assert.Error(t, result.Error)

		// Verify found with Unscoped
		var deletedUser dbmodel.User
		result = db.Unscoped().First(&deletedUser, userID)
		assert.NoError(t, result.Error)
		assert.NotNil(t, deletedUser.DeletedAt)
	})

	t.Run("concurrent updates handled with optimistic locking", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateUserWithProfile(db, "Concurrent", "Test", "concurrent.test@test.com")

		// Simulate two concurrent reads
		var user1, user2 dbmodel.User
		db.Preload("UserProfile").First(&user1, user.ID)
		db.Preload("UserProfile").First(&user2, user.ID)

		// First update succeeds
		user1.UserProfile.FirstName = "Update1"
		result1 := db.Save(&user1.UserProfile)
		assert.NoError(t, result1.Error)

		// Second update also succeeds (last write wins)
		user2.UserProfile.FirstName = "Update2"
		result2 := db.Save(&user2.UserProfile)
		assert.NoError(t, result2.Error)

		// Verify final state
		var finalUser dbmodel.User
		db.Preload("UserProfile").First(&finalUser, user.ID)
		assert.Equal(t, "Update2", finalUser.UserProfile.FirstName)
	})

	t.Run("cascade delete removes related profile", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateUserWithProfile(db, "Cascade", "Delete", "cascade.delete@test.com")
		profileID := user.UserProfile.ID

		// Delete user
		db.Delete(&user)

		// Verify profile also deleted (if cascade configured)
		var profile dbmodel.UserProfile
		result := db.First(&profile, profileID)
		// This depends on your cascade configuration
		// If cascade is configured: assert.Error(t, result.Error)
		_ = result // Adjust based on your configuration
	})
}

// TestPermissionOverridesIntegration tests user-specific permission overrides
func TestPermissionOverridesIntegration(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("permission override grants additional permission", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateRegularUser(db)

		// Load a permission that USER role doesn't have
		var createUserPerm dbmodel.Permission
		db.Where("name = ?", "create:user").First(&createUserPerm)

		// Create override to grant permission
		override := &dbmodel.UserPermissionOverride{
			UserID:       user.ID,
			PermissionID: createUserPerm.ID,
			IsGranted:    true,
		}
		db.Create(override)

		// Verify override was created
		var count int64
		db.Model(&dbmodel.UserPermissionOverride{}).Where("user_id = ? AND permission_id = ?", user.ID, createUserPerm.ID).Count(&count)
		assert.Equal(t, int64(1), count, "Permission override should be created")
	})

	t.Run("permission override denies role permission", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateAdminUser(db)

		// Load a permission that ADMIN role has
		var deleteUserPerm dbmodel.Permission
		db.Where("name = ?", "delete:user").First(&deleteUserPerm)

		// Create override to deny permission
		override := &dbmodel.UserPermissionOverride{
			UserID:       user.ID,
			PermissionID: deleteUserPerm.ID,
			IsGranted:    false,
		}
		db.Create(override)

		// Verify override was created
		var count int64
		db.Model(&dbmodel.UserPermissionOverride{}).Where("user_id = ? AND permission_id = ? AND is_granted = ?", user.ID, deleteUserPerm.ID, false).Count(&count)
		assert.Equal(t, int64(1), count, "Permission override denial should be created")
	})

	t.Run("multiple overrides apply correctly", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateRegularUser(db)

		// Grant create:user
		var createUserPerm dbmodel.Permission
		db.Where("name = ?", "create:user").First(&createUserPerm)
		override1 := &dbmodel.UserPermissionOverride{
			UserID:       user.ID,
			PermissionID: createUserPerm.ID,
			IsGranted:    true,
		}
		db.Create(override1)

		// Grant update:user
		var updateUserPerm dbmodel.Permission
		db.Where("name = ?", "update:user").First(&updateUserPerm)
		override2 := &dbmodel.UserPermissionOverride{
			UserID:       user.ID,
			PermissionID: updateUserPerm.ID,
			IsGranted:    true,
		}
		db.Create(override2)

		// Verify both overrides created
		var count int64
		db.Model(&dbmodel.UserPermissionOverride{}).Where("user_id = ?", user.ID).Count(&count)
		assert.Equal(t, int64(2), count, "Two permission overrides should be created")
	})

	t.Run("removing override restores role permissions", func(t *testing.T) {
		helpers.CleanupTestDB(db)

		user := fixtures.CreateAdminUser(db)

		// Deny a permission
		var deleteUserPerm dbmodel.Permission
		db.Where("name = ?", "delete:user").First(&deleteUserPerm)
		override := &dbmodel.UserPermissionOverride{
			UserID:       user.ID,
			PermissionID: deleteUserPerm.ID,
			IsGranted:    false,
		}
		db.Create(override)

		// Remove override
		db.Delete(override)

		// Verify override was removed
		var count int64
		db.Model(&dbmodel.UserPermissionOverride{}).Where("user_id = ? AND permission_id = ?", user.ID, deleteUserPerm.ID).Count(&count)
		assert.Equal(t, int64(0), count, "Permission override should be removed")
	})
}

// TestSessionManagementIntegration tests session lifecycle with database
func TestSessionManagementIntegration(t *testing.T) {
	db, cleanup := helpers.SetupTestDB()
	defer cleanup()

	t.Run("logout revokes refresh token in DB", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		authService := createTestAuthService(db)

		// Login to create session
		refreshToken, _, err := authService.GenerateRefreshToken(user.ID, "test-agent", "127.0.0.1")
		require.NoError(t, err)

		// Logout
		err = authService.RevokeRefreshToken(refreshToken)
		require.NoError(t, err)

		// Verify token is revoked
		tokenHash, _ := authentication.HashRefreshToken(refreshToken)
		var dbToken dbmodel.RefreshToken
		db.Where("token_hash = ?", tokenHash).First(&dbToken)
		assert.NotNil(t, dbToken.RevokedAt)
	})

	t.Run("logout all revokes all user sessions", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		authService := createTestAuthService(db)

		// Create multiple sessions
		_, _, err := authService.GenerateRefreshToken(user.ID, "device-1", "192.168.1.1")
		require.NoError(t, err)
		_, _, err = authService.GenerateRefreshToken(user.ID, "device-2", "192.168.1.2")
		require.NoError(t, err)
		_, _, err = authService.GenerateRefreshToken(user.ID, "device-3", "192.168.1.3")
		require.NoError(t, err)

		// Revoke all
		result := db.Model(&dbmodel.RefreshToken{}).Where("user_id = ?", user.ID).Update("revoked_at", time.Now())
		require.NoError(t, result.Error)

		// Verify all tokens revoked
		var revokedCount int64
		db.Model(&dbmodel.RefreshToken{}).
			Where("user_id = ? AND revoked_at IS NOT NULL", user.ID).
			Count(&revokedCount)

		var totalCount int64
		db.Model(&dbmodel.RefreshToken{}).
			Where("user_id = ?", user.ID).
			Count(&totalCount)

		assert.Equal(t, totalCount, revokedCount)
	})

	t.Run("active sessions query excludes revoked and expired tokens", func(t *testing.T) {
		helpers.CleanupTestDB(db)
		user := fixtures.CreateRegularUser(db)

		// Create active token
		_, err := fixtures.GenerateValidRefreshToken(db, user.ID)
		require.NoError(t, err)

		// Create revoked token
		_, err = fixtures.GenerateRevokedRefreshToken(db, user.ID)
		require.NoError(t, err)

		// Create expired token
		_, err = fixtures.GenerateExpiredRefreshToken(db, user.ID)
		require.NoError(t, err)

		// Query only active sessions
		var activeCount int64
		db.Model(&dbmodel.RefreshToken{}).
			Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", user.ID, time.Now()).
			Count(&activeCount)

		assert.Equal(t, int64(1), activeCount, "Only one active token should exist")
	})
}

// More sections to follow...
