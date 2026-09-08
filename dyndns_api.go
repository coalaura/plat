package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

func HandleListDynDNSUsers(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		okay(w, storage.GetDynDNSUsers())
	}
}

func HandleCreateDynDNSUser(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request, err := decodeDynDNSUserRequest(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		err = storage.CreateDynDNSUser(request)
		if err != nil {
			abort(w, dynDNSUserErrorStatus(err), err.Error())

			return
		}

		okay(w, nil)
	}
}

func HandleUpdateDynDNSUser(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")
		if username == "" {
			abort(w, http.StatusBadRequest, "missing username")

			return
		}

		request, err := decodeDynDNSUserRequest(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		err = storage.UpdateDynDNSUser(username, request)
		if err != nil {
			abort(w, dynDNSUserErrorStatus(err), err.Error())

			return
		}

		okay(w, nil)
	}
}

func HandleDeleteDynDNSUser(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username := chi.URLParam(r, "username")
		if username == "" {
			abort(w, http.StatusBadRequest, "missing username")

			return
		}

		err := storage.DeleteDynDNSUser(username)
		if err != nil {
			abort(w, dynDNSUserErrorStatus(err), err.Error())

			return
		}

		okay(w, nil)
	}
}

func decodeDynDNSUserRequest(request *http.Request) (DynDNSUserRequest, error) {
	var user DynDNSUserRequest

	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()

	err := decoder.Decode(&user)
	if err != nil {
		return DynDNSUserRequest{}, err
	}

	return user, nil
}

func dynDNSUserErrorStatus(err error) int {
	message := err.Error()
	if strings.Contains(message, "not found") {
		return http.StatusNotFound
	}

	if strings.Contains(message, "already exists") {
		return http.StatusConflict
	}

	switch message {
	case "username is required", "invalid username", "password is required", "DynDNS records must be A or AAAA", "unknown zone", "invalid record name":
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}
