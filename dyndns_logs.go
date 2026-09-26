package main

import (
	"database/sql"
	"errors"
	"slices"
	"time"

	"github.com/coalaura/schgo"
	_ "github.com/mattn/go-sqlite3"
)

const (
	dynDNSLogDatabasePath = "dyndns-logs.db"
	dynDNSLogLimit        = 50
)

type DynDNSLog struct {
	Time     time.Time `json:"time"`
	Source   string    `json:"source"`
	Hostname string    `json:"hostname"`
	Address  string    `json:"address"`
	Result   string    `json:"result"`
	Error    string    `json:"error,omitempty"`
}

var errDynDNSUserNotFound = errors.New("user not found")

func (s *Storage) GetDynDNSLogs(username string) ([]DynDNSLog, error) {
	s.dmx.RLock()
	defer s.dmx.RUnlock()

	user, exists := s.dyndnsUsers[username]
	if !exists {
		return nil, errDynDNSUserNotFound
	}

	rows, err := s.logDB.Query("SELECT time_ms, source, hostname, address, result, error FROM dyndns_logs WHERE endpoint_id = ? ORDER BY id DESC LIMIT ?", user.ID, dynDNSLogLimit)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	logs := make([]DynDNSLog, 0, dynDNSLogLimit)

	for rows.Next() {
		var (
			entry     DynDNSLog
			timestamp int64
		)

		err = rows.Scan(&timestamp, &entry.Source, &entry.Hostname, &entry.Address, &entry.Result, &entry.Error)
		if err != nil {
			return nil, err
		}

		entry.Time = time.UnixMilli(timestamp).UTC()

		logs = append(logs, entry)
	}

	err = rows.Err()
	if err != nil {
		return nil, err
	}

	slices.Reverse(logs)

	return logs, nil
}

func (s *Storage) AppendDynDNSLogs(username, endpointID string, logs []DynDNSLog) error {
	if len(logs) == 0 {
		return nil
	}

	s.dmx.RLock()
	defer s.dmx.RUnlock()

	user, exists := s.dyndnsUsers[username]
	if !exists || user.ID != endpointID {
		return nil
	}

	transaction, err := s.logDB.Begin()
	if err != nil {
		return err
	}

	defer transaction.Rollback()

	statement, err := transaction.Prepare("INSERT INTO dyndns_logs (endpoint_id, time_ms, source, hostname, address, result, error) VALUES (?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}

	for _, entry := range logs {
		_, err = statement.Exec(endpointID, entry.Time.UnixMilli(), entry.Source, entry.Hostname, entry.Address, entry.Result, entry.Error)
		if err != nil {
			statement.Close()

			return err
		}
	}

	err = statement.Close()
	if err != nil {
		return err
	}

	_, err = transaction.Exec("DELETE FROM dyndns_logs WHERE endpoint_id = ? AND id NOT IN (SELECT id FROM dyndns_logs WHERE endpoint_id = ? ORDER BY id DESC LIMIT ?)", endpointID, endpointID, dynDNSLogLimit)
	if err != nil {
		return err
	}

	return transaction.Commit()
}

func (s *Storage) deleteDynDNSLogs(endpointID string) error {
	_, err := s.logDB.Exec("DELETE FROM dyndns_logs WHERE endpoint_id = ?", endpointID)

	return err
}

func OpenDynDNSLogDatabase() (*sql.DB, error) {
	database, err := sql.Open("sqlite3", dynDNSLogDatabasePath+"?_journal_mode=WAL&_busy_timeout=5000&_sync=NORMAL")
	if err != nil {
		return nil, err
	}

	database.SetMaxOpenConns(16)
	database.SetMaxIdleConns(16)

	schema, err := schgo.NewSchema(database)
	if err != nil {
		database.Close()

		return nil, err
	}

	table := schema.Table("dyndns_logs")

	table.Primary("id", "INTEGER")

	table.Column("endpoint_id", "TEXT").NotNull()
	table.Column("time_ms", "INTEGER").NotNull()
	table.Column("source", "TEXT").NotNull()
	table.Column("hostname", "TEXT").NotNull()
	table.Column("address", "TEXT").NotNull()
	table.Column("result", "TEXT").NotNull()
	table.Column("error", "TEXT").NotNull()

	table.Index("idx_dyndns_logs_endpoint_id", "endpoint_id", "id")

	err = schema.Apply()
	if err != nil {
		database.Close()

		return nil, err
	}

	return database, nil
}
