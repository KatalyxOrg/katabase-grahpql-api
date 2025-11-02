//go:build integration
// +build integration

package helpers

import (
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"katalyx.fr/katabasegql/pkg/database"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
	"katalyx.fr/katabasegql/pkg/database/seed"
)

// SetupTestDB creates a test database connection, runs migrations, and seeds initial data
func SetupTestDB() (*gorm.DB, func()) {
	// Use test database configuration
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "host=localhost user=katabasegql_test password=katabasegql_test_password dbname=katabasegql_test port=5433 sslmode=disable"
	}

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), // Quiet logs during tests
	})
	if err != nil {
		log.Fatalf("Failed to connect to test database: %v", err)
	}

	// Run migrations
	database.Migrate(db)

	// Seed initial data (roles and permissions)
	err = seed.SeedV1(db)
	if err != nil {
		log.Fatalf("Failed to seed database: %v", err)
	}

	// Return cleanup function
	cleanup := func() {
		CleanupTestDB(db)
	}

	return db, cleanup
}

// CleanupTestDB removes all test data from the database
func CleanupTestDB(db *gorm.DB) {
	// Delete in reverse order of dependencies
	// Note: Using subqueries to only delete test user data (emails ending in @test.com)
	db.Exec("DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')")
	db.Exec("DELETE FROM user_permission_overrides WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')")
	db.Exec("DELETE FROM user_roles WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')")
	// Delete addresses first, before user_profiles are deleted
	db.Exec("DELETE FROM addresses WHERE id IN (SELECT address_id FROM user_profiles WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com'))")
	db.Exec("DELETE FROM user_profiles WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@test.com')")
	db.Exec("DELETE FROM users WHERE email LIKE '%@test.com'")
}

// TruncateAllTables completely clears all tables (use with caution)
func TruncateAllTables(db *gorm.DB) {
	db.Exec("TRUNCATE TABLE refresh_tokens CASCADE")
	db.Exec("TRUNCATE TABLE user_permission_overrides CASCADE")
	db.Exec("TRUNCATE TABLE user_profiles CASCADE")
	db.Exec("TRUNCATE TABLE addresses CASCADE")
	db.Exec("TRUNCATE TABLE user_roles CASCADE") // Fixed: was users_roles
	db.Exec("TRUNCATE TABLE users CASCADE")
	db.Exec("TRUNCATE TABLE roles_permissions CASCADE") // Fixed: was roles_permissions
	db.Exec("TRUNCATE TABLE permissions CASCADE")
	db.Exec("TRUNCATE TABLE roles CASCADE")
}

// WithTransaction executes a function within a database transaction and rolls it back
func WithTransaction(db *gorm.DB, fn func(*gorm.DB) error) error {
	tx := db.Begin()
	if tx.Error != nil {
		return tx.Error
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	tx.Rollback()
	return nil // Always rollback for tests
}

// AssertRowCount checks that a table has expected number of rows
func AssertRowCount(t *testing.T, db *gorm.DB, tableName string, expected int64) {
	var count int64
	db.Table(tableName).Count(&count)
	assert.Equal(t, expected, count, "Expected %d rows in %s, got %d", expected, tableName, count)
}

// CountRefreshTokensForUser returns the count of refresh tokens for a specific user
func CountRefreshTokensForUser(db *gorm.DB, userID uint) (int64, error) {
	var count int64
	result := db.Table("refresh_tokens").Where("user_id = ?", userID).Count(&count)
	return count, result.Error
}

// GetUserByEmail retrieves a user by email for test assertions
func GetUserByEmail(db *gorm.DB, email string) (*dbmodel.User, error) {
	var user dbmodel.User
	result := db.Where("email = ?", email).
		Preload("Roles").
		Preload("Roles.Permissions").
		Preload("UserProfile").
		First(&user)
	if result.Error != nil {
		return nil, result.Error
	}
	return &user, nil
}
