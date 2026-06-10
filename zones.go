package main

import (
	"sort"
	"sync"
)

type Zone struct {
	mx sync.RWMutex

	ID      string             `yaml:"id"`
	Name    string             `yaml:"name"`
	Records map[string]*Record `yaml:"-"`
}

type zoneData struct {
	ID      string   `yaml:"id"`
	Name    string   `yaml:"name"`
	Records []Record `yaml:"records"`
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

func (z *Zone) UnmarshalYAML(unmarshal func(any) error) error {
	var data zoneData

	err := unmarshal(&data)
	if err != nil {
		return err
	}

	z.ID = data.ID
	z.Name = data.Name
	z.Records = make(map[string]*Record, len(data.Records))

	for _, rec := range data.Records {
		z.Records[rec.Name] = &rec
	}

	return nil
}

func (z *Zone) MarshalYAML() (any, error) {
	return zoneData{
		Name:    z.Name,
		Records: z.RecordsList(),
	}, nil
}
