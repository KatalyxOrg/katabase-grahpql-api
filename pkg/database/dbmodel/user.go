package dbmodel

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"katalyx.fr/katabasegql/graph/model"
)

type User struct {
	gorm.Model

	Email string `gorm:"not null;unique"`

	PasswordHash *string

	Roles               []Role                   `gorm:"many2many:user_roles;"`
	PermissionOverrides []UserPermissionOverride `gorm:"foreignKey:UserID"`
	UserProfile         UserProfile              `gorm:"foreignKey:UserID"`
}

func (u *User) ToModel() *model.User {
	var permissionsSet = make(map[string]bool)
	var roles []string

	if len(u.Roles) > 0 {
		for _, role := range u.Roles {
			if len(role.Permissions) > 0 {
				for _, permission := range role.Permissions {
					permissionsSet[permission.Name] = true
				}
			}

			roles = append(roles, role.Name)
		}
	}

	if len(u.PermissionOverrides) > 0 {
		for _, override := range u.PermissionOverrides {
			if override.IsGranted {
				permissionsSet[override.Permission.Name] = true
			} else {
				permissionsSet[override.Permission.Name] = false
			}
		}
	}

	var permissions []string
	for permission, granted := range permissionsSet {
		if granted {
			permissions = append(permissions, permission)
		}
	}

	return &model.User{
		ID:          u.ID,
		CreatedAt:   u.CreatedAt,
		Email:       u.Email,
		Permissions: permissions,
		Roles:       roles,
	}
}

func (u *User) HasPermission(permission string) bool {
	for _, override := range u.PermissionOverrides {
		if override.Permission.Name == permission {
			return override.IsGranted
		}
	}

	for _, role := range u.Roles {
		for _, p := range role.Permissions {
			if p.Name == permission {
				return true
			}
		}
	}

	return false
}

type UserFieldsToInclude struct {
	UserProfile       bool
	Roles             bool
	Roles_Permissions bool
	Interests         bool
}

type UserRepository interface {
	FindByID(id uint, fieldsToInclude *UserFieldsToInclude) (*User, error)
	FindByEmail(email string, fieldsToInclude *UserFieldsToInclude) (*User, error)
	FindByLinkedInID(linkedInID string, fieldsToInclude *UserFieldsToInclude) (*User, error)
	FindByGroupID(groupID uint) ([]*User, error)
	Create(user *User) (*User, error)
	Update(user *User) (*User, error)
	Delete(id uint) error
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) FindByID(id uint, fieldsToInclude *UserFieldsToInclude) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	tx := r.db.WithContext(ctx).Model(&user)

	if fieldsToInclude != nil {
		if fieldsToInclude.UserProfile {
			tx = tx.Preload("UserProfile")
		}

		if fieldsToInclude.Roles {
			tx = tx.Preload("Roles")
		}

		if fieldsToInclude.Interests {
			tx = tx.Preload("Interests")
		}

		// if fieldsToInclude.Roles_Permissions {
		// 	tx = tx.Preload("Roles.Permissions").Preload("PermissionOverrides").Preload("PermissionOverrides.Permission")
		// }
	}
	tx = tx.Preload("Roles.Permissions").Preload("PermissionOverrides").Preload("PermissionOverrides.Permission")

	err := tx.Where("id = ?", id).First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}

		return nil, err
	}

	return &user, nil
}

func (r *userRepository) FindByLinkedInID(linkedInID string, fieldsToInclude *UserFieldsToInclude) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	tx := r.db.WithContext(ctx).Model(&user)

	if fieldsToInclude != nil {
		if fieldsToInclude.UserProfile {
			tx = tx.Preload("UserProfile")
		}

		if fieldsToInclude.Roles {
			tx = tx.Preload("Roles")
		}

		if fieldsToInclude.Roles_Permissions {
			tx = tx.Preload("Roles.Permissions")
		}

		if fieldsToInclude.Interests {
			tx = tx.Preload("Interests")
		}
	}

	err := tx.Where("linked_in_id = ?", linkedInID).First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}

		return nil, err
	}

	return &user, nil
}

func (r *userRepository) FindByEmail(email string, fieldsToInclude *UserFieldsToInclude) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	tx := r.db.WithContext(ctx).Model(&user)

	if fieldsToInclude != nil {
		if fieldsToInclude.UserProfile {
			tx = tx.Preload("UserProfile")
		}

		if fieldsToInclude.Roles {
			tx = tx.Preload("Roles")
		}

		if fieldsToInclude.Roles_Permissions {
			tx = tx.Preload("Roles.Permissions")
		}

		if fieldsToInclude.Interests {
			tx = tx.Preload("Interests")
		}
	}

	err := tx.Where("email = ?", email).First(&user).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}

		return nil, err
	}

	return &user, nil
}

func (r *userRepository) FindByGroupID(groupID uint) ([]*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var users []*User
	tx := r.db.WithContext(ctx).Model(&User{}).Preload("UserProfile").Preload("Roles").Preload("Roles.Permissions").Preload("PermissionOverrides").Preload("PermissionOverrides.Permission")

	err := tx.Joins("JOIN group_users ON group_users.user_id = users.id").
		Where("group_users.group_id = ?", groupID).
		Find(&users).Error

	return users, err
}

func (r *userRepository) Create(user *User) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	err := tx.Create(user).Error

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *userRepository) Update(user *User) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.Session(&gorm.Session{FullSaveAssociations: true}).WithContext(ctx)
	// tx := r.db.WithContext(ctx)

	err := tx.Save(user).Error

	if err != nil {
		return nil, err
	}

	return user, nil
}

func (r *userRepository) Delete(id uint) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	err := tx.Select(clause.Associations).Delete(&User{}, id).Error

	if err != nil {
		return err
	}

	return nil
}
