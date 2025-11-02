package maps

import "katalyx.fr/katabasegql/pkg/database/dbmodel"

// Get returns the address of the given id.
// It takes an uint as a parameter and returns a (Address, error) object.
func (c *Config) Get(id uint) (*dbmodel.Address, error) {
	return c.AddressRepository.FindByID(id)
}
