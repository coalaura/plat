package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func HandleListRecords(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		list, err := storage.GetRecords(zone)
		if err != nil {
			abort(w, http.StatusNotFound, err.Error())

			return
		}

		okay(w, list)
	}
}

func HandleSetRecord(storage *Storage, override bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		var record Record

		err = json.NewDecoder(r.Body).Decode(&record)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		err = storage.SetRecord(zone, record, override)
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		err = storage.Store()
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		okay(w, nil)
	}
}

func HandleUnsetRecord(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		name := chi.URLParam(r, "record")
		if name == "" {
			abort(w, http.StatusBadRequest, "missing record name")

			return
		}

		err = storage.UnsetRecord(zone, name)
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		err = storage.Store()
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		okay(w, nil)
	}
}

func resolveZone(r *http.Request) (string, error) {
	zone := chi.URLParam(r, "zone")
	if zone == "" {
		return "", errors.New("missing zone")
	}

	if len(zone) < 2 || zone[len(zone)-1] != '.' {
		return "", errors.New("invalid zone")
	}

	for _, r := range zone {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' {
			return "", errors.New("invalid zone")
		}
	}

	return zone, nil
}
