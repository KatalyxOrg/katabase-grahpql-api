package database

import (
	"log"

	"gorm.io/gorm"
	"katalyx.fr/katabasegql/pkg/database/dbmodel"
	"katalyx.fr/katabasegql/pkg/database/seed"
)

func Migrate(database *gorm.DB) {
	database.AutoMigrate(
		&seed.Seed{},
		&dbmodel.Address{},
		&dbmodel.User{},
		&dbmodel.Permission{},
		&dbmodel.Role{},
		&dbmodel.UserPermissionOverride{},
		&dbmodel.UserProfile{},
		&dbmodel.RefreshToken{},
	)

	log.Println("Database migrated")

	ApplySeeds(database)
}

func ApplySeeds(database *gorm.DB) {
	seedsToApply := []struct {
		Name     string
		SeedFunc func(*gorm.DB) error
	}{
		{"SeedV1", seed.SeedV1},
	}

	for _, seedToApply := range seedsToApply {
		if !isSeedApplied(database, seedToApply.Name) {
			log.Printf("Applying seed %s", seedToApply.Name)
			if err := seedToApply.SeedFunc(database); err != nil {
				log.Fatalf("Error applying seed %s: %s", seedToApply.Name, err)
			}
			markSeedAsApplied(database, seedToApply.Name)
		}
	}

	log.Println("Seeds applied")
}

func isSeedApplied(database *gorm.DB, name string) bool {
	var count int64
	database.Model(&seed.Seed{}).Where("name = ?", name).Count(&count)

	return count > 0
}

func markSeedAsApplied(database *gorm.DB, name string) {
	database.Create(&seed.Seed{Name: name})
}
