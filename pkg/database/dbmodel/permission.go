package dbmodel

import (
	"context"
	"time"

	"gorm.io/gorm"
	"katalyx.fr/katabasegql/graph/model"
)

type Permission struct {
	gorm.Model
	Name string `gorm:"not null;unique"`

	ReadableName *string
	Description  *string
	Category     *string
}

func (p *Permission) ToModel() *model.Permission {
	return &model.Permission{
		ID:           p.ID,
		CreatedAt:    p.CreatedAt,
		Name:         p.Name,
		ReadableName: p.ReadableName,
		Description:  p.Description,
		Category:     p.Category,
	}
}

type PermissionRepository interface {
	FindAll() ([]*Permission, error)
}

type permissionRepository struct {
	db *gorm.DB
}

func NewPermissionRepository(db *gorm.DB) PermissionRepository {
	return &permissionRepository{db: db}
}

func (r *permissionRepository) FindAll() ([]*Permission, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var permissions []*Permission
	tx := r.db.WithContext(ctx).Model(&Permission{})

	err := tx.Find(&permissions).Error

	if err != nil {
		return nil, err
	}

	return permissions, nil
}
