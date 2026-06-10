package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func DoListRecords(storage *Storage, w http.ResponseWriter, zone string) {
	list, err := storage.GetRecords(zone)
	if err != nil {
		abort(w, http.StatusNotFound, err.Error())

		return
	}

	okay(w, list)
}

func HandleListRecords(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		DoListRecords(storage, w, zone)
	}
}

func HandleFetchRecords(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zone, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		err = storage.FetchRecords(zone)
		if err != nil {
			abort(w, http.StatusInternalServerError, err.Error())

			return
		}

		DoListRecords(storage, w, zone)
	}
}

func HandleFetchAllRecords(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zones := storage.GetZones()

		var (
			index = 1
			total = len(zones)
		)

		for zone := range zones {
			flushPart(w, map[string]any{
				"zone":  zone,
				"index": index,
				"total": total,
			})

			err := storage.FetchRecords(zone)
			if err != nil {
				abort(w, http.StatusInternalServerError, err.Error())

				return
			}
		}

		json.NewEncoder(w).Encode(map[string]bool{
			"completed": true,
		})
	}
}

func HandleSetRecord(storage *Storage, isCreate bool) http.HandlerFunc {
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

		if isCreate {
			record.ID = ""
		} else if record.ID == "" {
			abort(w, http.StatusBadRequest, "missing record id")

			return
		}

		err = storage.SetRecord(zone, &record)
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

	if len(zone) != 32 {
		return "", errors.New("invalid zone")
	}

	for _, r := range zone {
		if (r < 'a' || r > 'f') && (r < '0' || r > '9') {
			return "", errors.New("invalid zone")
		}
	}

	return zone, nil
}
