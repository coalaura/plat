package storage

import (
	"errors"
	"fmt"
	"strings"
)

var ErrEmailConfigured = errors.New("this zone already has email records; configure its email policy manually")

func (s *Storage) ProtectEmail(zoneID, reportingEmail string) error {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	zone := cloneZone(s.zones[zoneID])
	if zone == nil {
		return fmt.Errorf("unknown zone %q", zoneID)
	}

	for _, record := range zone.Records {
		if isEmailRecord(record, zone.Name) {
			return ErrEmailConfigured
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
