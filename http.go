package main

import (
	"encoding/json"
	"net/http"
)

func abort(w http.ResponseWriter, code int, err string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(code)

	json.NewEncoder(w).Encode(map[string]string{
		"error": err,
	})
}

func okay(w http.ResponseWriter, data any) {
	if data != nil {
		w.Header().Add("Content-Type", "application/json")
	}

	w.WriteHeader(http.StatusOK)

	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}
