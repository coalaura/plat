package main

import (
	"encoding/json"
	"errors"
	"net/http"
)

func HandleDNSSEC(storage *Storage, config *Config, update bool) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		zoneID, err := resolveZone(request)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		if update {
			var settings DNSSECRequest

			decoder := json.NewDecoder(http.MaxBytesReader(w, request.Body, 16384))

			decoder.DisallowUnknownFields()

			err = decoder.Decode(&settings)
			if err != nil {
				abort(w, http.StatusBadRequest, err.Error())

				return
			}

			if settings.Enabled && settings.Provider != "cloudflare" && !config.DNS.Enabled {
				abort(w, http.StatusBadRequest, "enable plat's DNS server in config.yml before enabling plat DNSSEC")

				return
			}

			details, err := storage.ConfigureDNSSEC(request.Context(), zoneID, settings)
			if err != nil {
				abort(w, http.StatusBadRequest, err.Error())

				return
			}

			okay(w, details)

			return
		}

		provider := request.URL.Query().Get("provider")

		details, err := storage.DNSSECDetails(request.Context(), zoneID, provider)
		if err != nil {
			status := http.StatusBadGateway

			if errors.Is(err, errLocalZoneNotFound) {
				status = http.StatusNotFound
			}

			abort(w, status, err.Error())

			return
		}

		okay(w, details)
	}
}
