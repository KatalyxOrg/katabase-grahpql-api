package dbmodel

import (
	"context"
	"time"

	"gorm.io/gorm"
)

type UserPermissionOverride struct {
	gorm.Model

	UserID       uint       `gorm:"not null;index"` // L'utilisateur concerné
	PermissionID uint       `gorm:"not null;index"` // La permission concernée
	Permission   Permission `gorm:"foreignKey:PermissionID"`
	IsGranted    bool       `gorm:"not null"` // true = ajouté, false = interdit
}

type UserPermissionOverrideRepository interface {
	Create(userPermissionOverride *UserPermissionOverride) (*UserPermissionOverride, error)
	Delete(userID, permissionID uint) error
}

type userPermissionOverrideRepository struct {
	db *gorm.DB
}

func NewUserPermissionOverrideRepository(db *gorm.DB) UserPermissionOverrideRepository {
	return &userPermissionOverrideRepository{db: db}
}

func (r *userPermissionOverrideRepository) Create(userPermissionOverride *UserPermissionOverride) (*UserPermissionOverride, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	err := tx.Create(userPermissionOverride).Error

	return userPermissionOverride, err
}

func (r *userPermissionOverrideRepository) Delete(userID, permissionID uint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	// Delete where user id and permission id match
	err := tx.Where("user_id = ? AND permission_id = ?", userID, permissionID).Delete(&UserPermissionOverride{}).Error

	return err
}
