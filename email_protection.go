package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"plat/internal/storage"
	"strings"
)

type EmailProtectionRequest struct {
	ReportingEmail string `json:"reporting_email"`
}

var errEmailConfigured = storage.ErrEmailConfigured

func HandleProtectEmail(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		zoneID, err := resolveZone(r)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		var request EmailProtectionRequest

		err = json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			abort(w, http.StatusBadRequest, err.Error())

			return
		}

		request.ReportingEmail = strings.TrimSpace(request.ReportingEmail)
		if !validReportingEmail(request.ReportingEmail) {
			abort(w, http.StatusBadRequest, "enter a single reporting email address without a display name")

			return
		}

		if storage.Client() != nil && !isLocalZoneID(zoneID) {
			err = storage.FetchRecords(zoneID)
			if err != nil {
				abort(w, http.StatusInternalServerError, err.Error())

				return
			}
		}

		err = storage.ProtectEmail(zoneID, request.ReportingEmail)

		storeErr := storage.Store()

		if err != nil {
			status := http.StatusInternalServerError

			if errors.Is(err, errEmailConfigured) {
				status = http.StatusConflict
			}

			abort(w, status, err.Error())

			return
		}

		if storeErr != nil {
			abort(w, http.StatusInternalServerError, storeErr.Error())

			return
		}

		okay(w, nil)
	}
}

func validReportingEmail(value string) bool {
	if value == "" {
		return true
	}

	if strings.ContainsAny(value, "\"\\;, \t\r\n?#%&") {
		return false
	}

	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}
