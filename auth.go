package main

import (
	"net/http"
	"strings"
)

func authenticate(config *Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !isAuthenticated(config, r) {
				abort(w, http.StatusUnauthorized, "unauthorized")

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isAuthenticated(config *Config, r *http.Request) bool {
	token := r.Header.Get("Authorization")

	if !strings.HasPrefix(token, "Bearer ") {
		return false
	}

	token = strings.TrimPrefix(token, "Bearer ")

	return token == config.Server.Token
}
