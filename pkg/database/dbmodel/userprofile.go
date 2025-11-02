package dbmodel

import (
	"gorm.io/gorm"
	"katalyx.fr/katabasegql/graph/model"
)

type UserProfile struct {
	gorm.Model

	FirstName string `gorm:"not null"`
	LastName  *string

	AvatarName *string

	Phone *string

	Address *Address `gorm:"foreignKey:AddressID"`

	// Foreign objects
	AddressID *uint
	UserID    uint `gorm:"not null;unique"`
}

func (up *UserProfile) ToModel() *model.UserProfile {
	return &model.UserProfile{
		ID:         up.ID,
		CreatedAt:  up.CreatedAt,
		FirstName:  up.FirstName,
		LastName:   up.LastName,
		Phone:      up.Phone,
		AddressID:  up.AddressID,
		AvatarName: up.AvatarName,
	}
}
