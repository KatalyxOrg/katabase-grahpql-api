package dbmodel

import (
	"context"
	"time"

	"gorm.io/gorm"
	"katalyx.fr/katabasegql/graph/model"
)

type Address struct {
	gorm.Model

	Number        string `gorm:"not null"`
	Route         string `gorm:"not null"`
	OptionalRoute *string
	City          string `gorm:"not null"`
	ZipCode       string `gorm:"not null"`
	Country       string `gorm:"not null"`

	Latitude  float64 `gorm:"not null"`
	Longitude float64 `gorm:"not null"`
}

func (address *Address) ToModel() *model.Address {
	return &model.Address{
		Number:        address.Number,
		Route:         address.Route,
		OptionalRoute: address.OptionalRoute,
		City:          address.City,
		ZipCode:       address.ZipCode,
		Country:       address.Country,
		Coordinates: []float64{
			address.Latitude,
			address.Longitude,
		},
	}
}

func (address *Address) Detailed() string {
	result := address.Number + " " + address.Route

	if address.OptionalRoute != nil {
		result += " " + *address.OptionalRoute
	}

	result += ", " + address.ZipCode + " " + address.City + ", " + address.Country

	return result
}

type AddressRepository interface {
	FindByID(id uint) (*Address, error)
	Create(address *Address) (*Address, error)
}

type addressRepository struct {
	db *gorm.DB
}

func NewAddressRepository(db *gorm.DB) AddressRepository {
	return &addressRepository{db: db}
}

func (r *addressRepository) FindByID(id uint) (*Address, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var address Address
	tx := r.db.WithContext(ctx)

	err := tx.Where("id = ?", id).First(&address).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}

		return nil, err
	}

	return &address, nil
}

func (r *addressRepository) Create(address *Address) (*Address, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tx := r.db.WithContext(ctx)

	err := tx.Create(address).Error

	return address, err
}
