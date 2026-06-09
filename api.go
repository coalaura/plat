package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
)

func HandleListRecords(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := resolveDomain(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		list, err := storage.GetRecords(domain)
		if err != nil {
			abort(w, http.StatusNotFound, err.Error())

			return
		}

		okay(w, list)
	}
}

func HandleSetRecord(storage *Storage, override bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := resolveDomain(r)
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

		err = storage.SetRecord(domain, record, override)
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
		domain, err := resolveDomain(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		name := chi.URLParam(r, "record")
		if name == "" {
			abort(w, http.StatusBadRequest, "missing record name")

			return
		}

		err = storage.UnsetRecord(domain, name)
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

func resolveDomain(r *http.Request) (string, error) {
	raw := chi.URLParam(r, "domain")
	if raw == "" {
		return "", errors.New("missing domain")
	}

	uri, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid domain")
	}

	return uri.Hostname(), nil
}
