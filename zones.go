package main

import (
	"sort"
	"strings"
	"sync"
)

type Zone struct {
	mx sync.RWMutex

	ID      string             `yaml:"id"`
	Name    string             `yaml:"name"`
	Records map[string]*Record `yaml:"-"`

	dnssec *DNSSECConfig
	signed *SignedZone
	serial uint32
}

type zoneData struct {
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name"`
	Records []Record `yaml:"records"`
	Serial  uint32   `yaml:"dns_serial,omitempty"`
}

func (z *Zone) MatchesName(name string) bool {
	return name == z.Name || strings.HasSuffix(name, "."+z.Name)
}

func (z *Zone) IsLocal() bool {
	return isLocalZoneID(z.ID)
}

func (z *Zone) RecordsList() []Record {
	records := make([]Record, 0, len(z.Records))

	for _, rec := range z.Records {
		records = append(records, *rec)
	}

	sort.Slice(records, func(i, j int) bool {
		if records[i].Name == records[j].Name {
			return records[i].Type < records[j].Type
		}

		return records[i].Name < records[j].Name
	})

	return records
}

func (z *Zone) ZoneData() zoneData {
	return zoneData{
		ID:      z.ID,
		Name:    z.Name,
		Records: z.RecordsList(),
		Serial:  z.serial,
	}
}

func (z *Zone) UnmarshalYAML(unmarshal func(any) error) error {
	var data zoneData

	err := unmarshal(&data)
	if err != nil {
		return err
	}

	z.ID = data.ID
	z.Name = data.Name
	z.serial = data.Serial
	z.Records = make(map[string]*Record, len(data.Records))

	for _, rec := range data.Records {
		err = rec.Update(z.Name)
		if err != nil {
			return err
		}

		z.Records[rec.ID] = &rec
	}

	return nil
}

func (z *Zone) MarshalYAML() (any, error) {
	return z.ZoneData(), nil
}

func isLocalZoneID(id string) bool {
	return strings.HasPrefix(id, "local-")
}
