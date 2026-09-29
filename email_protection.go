package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
)

type EmailProtectionRequest struct {
	ReportingEmail string `json:"reporting_email"`
}

var errEmailConfigured = errors.New("this zone already has email records; configure its email policy manually")

func (s *Storage) ProtectEmail(zoneID, reportingEmail string) error {
	s.mx.RLock()

	zone, exists := s.zones[zoneID]
	if !exists {
		s.mx.RUnlock()

		return fmt.Errorf("unknown zone %q", zoneID)
	}

	zone.mx.Lock()
	defer zone.mx.Unlock()

	s.mx.RUnlock()

	for _, record := range zone.Records {
		if isEmailRecord(record, zone.Name) {
			return errEmailConfigured
		}
	}

	dmarc := "v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;"

	if reportingEmail != "" {
		dmarc += " rua=mailto:" + reportingEmail + ";"
	}

	records := [3]Record{
		{Type: "TXT", Name: "@", Content: `"v=spf1 -all"`, TTL: 1},
		{Type: "TXT", Name: "*._domainkey", Content: `"v=DKIM1; p="`, TTL: 1},
		{Type: "TXT", Name: "_dmarc", Content: encodeTXT(dmarc), TTL: 1},
	}

	for index := range records {
		err := s.setRecordLocked(zoneID, zone, &records[index])
		if err != nil {
			return fmt.Errorf("created %d of 3 email protection records: %w", index, err)
		}
	}

	return nil
}

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

		if storage.client != nil && !isLocalZoneID(zoneID) {
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

func isEmailRecord(record *Record, zoneName string) bool {
	name := strings.ToLower(strings.TrimSuffix(record.Name, "."))
	name = strings.TrimSuffix(name, "."+strings.ToLower(strings.TrimSuffix(zoneName, ".")))

	typeName := strings.ToUpper(record.Type)

	if typeName == "MX" || typeName == "SPF" {
		return true
	}

	if name == "_dmarc" || strings.HasPrefix(name, "_dmarc.") || name == "_domainkey" || strings.HasSuffix(name, "._domainkey") || strings.Contains(name, "._domainkey.") {
		return true
	}

	content := strings.ToLower(strings.TrimSpace(decodeTXT(record.Content)))

	return typeName == "TXT" && (strings.HasPrefix(content, "v=spf1") || strings.HasPrefix(content, "v=dkim1") || strings.HasPrefix(content, "v=dmarc1"))
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
