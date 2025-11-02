package dbmodel

import (
	"context"
	"time"

	"gorm.io/gorm"
)

type Role struct {
	gorm.Model
	Name        string       `gorm:"not null;unique"`
	Permissions []Permission `gorm:"many2many:role_permissions;"`
}

type RoleRepository interface {
	FindByName(name string) (*Role, error)
}

type roleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) RoleRepository {
	return &roleRepository{db: db}
}

func (r *roleRepository) FindByName(name string) (*Role, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var role Role
	tx := r.db.WithContext(ctx)

	err := tx.Where("name = ?", name).First(&role).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}

		return nil, err
	}

	return &role, nil
}
