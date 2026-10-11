package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func HandleDNSRequests(domain string, server *DNSServer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if server != nil {
				doh, err := NewDoHRequest(request)
				if err != nil {
					abort(writer, http.StatusBadRequest, err.Error())

					return
				}

				if doh != nil {
					server.HandleDoH(writer, doh)

					return
				}
			}

			host, _, _ := strings.Cut(request.Host, ":")
			if domain != "" && strings.EqualFold(strings.TrimSuffix(host, "."), domain) {
				http.NotFound(writer, request)

				return
			}

			next.ServeHTTP(writer, request)
		})
	}
}

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

func writeNDJson(w http.ResponseWriter, f http.Flusher, data any) {
	json.NewEncoder(w).Encode(data)
	w.Write([]byte("\n"))

	f.Flush()
}
