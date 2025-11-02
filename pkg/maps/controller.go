package maps

import (
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/render"
	"katalyx.fr/katabasegql/internal/authentication"
	"katalyx.fr/katabasegql/pkg/httperrors"
)

// Autocomplete address godoc
//
//	@Summary		Get autocompletion for address
//	@Description	Get autocompletion for address
//	@ID				autocomplete-address
//	@Tags			Autocomplete
//	@Success		200	{object}	[]AutocompleteAddress
//	@Router			/autocomplete/address [get]
func (config *Config) AutoComplete(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("input")
	autocompleteType := r.URL.Query().Get("type")
	sessionToken := r.URL.Query().Get("sessiontoken")

	if input == "" || sessionToken == "" {
		render.Render(w, r, httperrors.ErrInvalidRequest(errors.New("not enough parameters")))
		return
	}

	if autocompleteType == "" {
		autocompleteType = "address"
	}

	user := authentication.ForContext(r.Context())
	if user == nil {
		render.Render(w, r, httperrors.ErrUnauthorized("not authorized to get autocompletion"))
		return
	}

	input = strings.ReplaceAll(input, " ", "+")
	resp, err := http.Get("https://maps.googleapis.com/maps/api/place/autocomplete/json?input=" + input + "&types=" + autocompleteType + "&language=french&key=" + config.Config.Constants.Maps.ApiKey + "&sessiontoken=" + sessionToken)
	if err != nil {
		render.Render(w, r, httperrors.ErrServerError(err))
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		render.Render(w, r, httperrors.ErrServerError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// Details godoc
// @Summary Get Google Place API place details
// @Description Get Google Place API place details
// @ID maps-place-details
// @Tags Maps
// @Success 200 {object} string
// @Failure 401 {object} ErrResponse
// @Router /maps/details [get]
func (config *Config) PlaceDetails(w http.ResponseWriter, r *http.Request) {
	placeID := r.URL.Query().Get("place_id")

	if placeID == "" {
		render.Render(w, r, httperrors.ErrInvalidRequest(&NoEnoughParamsError{}))
		return
	}

	user := authentication.ForContext(r.Context())
	if user == nil {
		render.Render(w, r, httperrors.ErrUnauthorized("not authorized to get details"))
		return
	}

	resp, err := http.Get("https://maps.googleapis.com/maps/api/place/details/json?place_id=" + placeID + "&fields=geometry,address_components&key=" + config.Config.Constants.Maps.ApiKey)
	if err != nil {
		render.Render(w, r, httperrors.ErrServerError(err))
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		render.Render(w, r, httperrors.ErrServerError(err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}
