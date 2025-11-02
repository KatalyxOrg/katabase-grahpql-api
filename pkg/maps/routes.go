package maps

import (
	"github.com/go-chi/chi/v5"
	"katalyx.fr/katabasegql/config"
)

func New(configuration *config.Config) *Config {
	return &Config{configuration}
}

func (config *Config) Routes() *chi.Mux {
	router := chi.NewRouter()

	router.Get("/autocomplete", config.AutoComplete)
	router.Get("/details", config.PlaceDetails)

	return router
}
