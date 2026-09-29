package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/goccy/go-yaml"
)

const (
	DynDNSFile = "dyndns.yml"

	DynDNSHashIterations = 600000
	DynDNSSaltSize       = 16
	DynDNSKeySize        = 32
)

type DynDNSRecord struct {
	Zone string `yaml:"zone" json:"zone"`
	Type string `yaml:"type" json:"type"`
	Name string `yaml:"name" json:"name"`
}

type DynDNSUser struct {
	ID           string         `yaml:"id" json:"-"`
	Username     string         `yaml:"username" json:"username"`
	PasswordHash string         `yaml:"password" json:"-"`
	Records      []DynDNSRecord `yaml:"records" json:"records"`
}

type DynDNSUserRequest struct {
	Username string         `json:"username"`
	Password string         `json:"password"`
	Records  []DynDNSRecord `json:"records"`
}

func (s *Storage) GetDynDNSUsers() []DynDNSUser {
	s.dmx.RLock()
	defer s.dmx.RUnlock()

	users := make([]DynDNSUser, 0, len(s.dyndnsUsers))

	for _, user := range s.dyndnsUsers {
		users = append(users, copyDynDNSUser(user))
	}

	slices.SortFunc(users, func(first, second DynDNSUser) int {
		return strings.Compare(first.Username, second.Username)
	})

	return users
}

func (s *Storage) CreateDynDNSUser(request DynDNSUserRequest) error {
	user, err := s.prepareDynDNSUser(request, true)
	if err != nil {
		return err
	}

	user.ID, err = newDynDNSUserID()
	if err != nil {
		return err
	}

	s.dmx.Lock()
	defer s.dmx.Unlock()

	if _, exists := s.dyndnsUsers[user.Username]; exists {
		return errors.New("username already exists")
	}

	s.dyndnsUsers[user.Username] = user

	err = s.storeDynDNSLocked()
	if err != nil {
		delete(s.dyndnsUsers, user.Username)

		return err
	}

	return nil
}

func (s *Storage) UpdateDynDNSUser(username string, request DynDNSUserRequest) error {
	user, err := s.prepareDynDNSUser(request, false)
	if err != nil {
		return err
	}

	s.dmx.Lock()
	defer s.dmx.Unlock()

	current, exists := s.dyndnsUsers[username]
	if !exists {
		return errors.New("user not found")
	}

	if user.Username != username {
		if _, exists := s.dyndnsUsers[user.Username]; exists {
			return errors.New("username already exists")
		}
	}

	if request.Password == "" {
		user.PasswordHash = current.PasswordHash
	}

	user.ID = current.ID

	delete(s.dyndnsUsers, username)

	s.dyndnsUsers[user.Username] = user

	err = s.storeDynDNSLocked()
	if err != nil {
		delete(s.dyndnsUsers, user.Username)
		s.dyndnsUsers[username] = current

		return err
	}

	return nil
}

func (s *Storage) DeleteDynDNSUser(username string) error {
	s.dmx.Lock()
	defer s.dmx.Unlock()

	user, exists := s.dyndnsUsers[username]
	if !exists {
		return errors.New("user not found")
	}

	delete(s.dyndnsUsers, username)

	err := s.storeDynDNSLocked()
	if err != nil {
		s.dyndnsUsers[username] = user

		return err
	}

	err = s.deleteDynDNSLogs(user.ID)
	if err != nil {
		log.Warnf("DynDNS log cleanup failed for %s: %v", username, err)
	}

	return nil
}

func (s *Storage) AuthenticateDynDNS(username, password string) (DynDNSUser, bool) {
	s.dmx.RLock()

	user, exists := s.dyndnsUsers[username]
	if !exists {
		s.dmx.RUnlock()

		return DynDNSUser{}, false
	}

	copy := copyDynDNSUser(user)
	s.dmx.RUnlock()

	return copy, verifyDynDNSPassword(copy.PasswordHash, password)
}

func (s *Storage) UpdateDynDNSRecord(assignment DynDNSRecord, address string) (bool, error) {
	s.mx.RLock()

	zone, exists := s.zones[assignment.Zone]
	if !exists {
		s.mx.RUnlock()

		return false, errors.New("assigned zone not found")
	}

	zone.mx.Lock()
	defer zone.mx.Unlock()

	s.mx.RUnlock()

	matches := make([]*Record, 0, 1)

	for _, record := range zone.Records {
		if strings.EqualFold(record.Type, assignment.Type) && strings.EqualFold(record.Name, assignment.Name) {
			matches = append(matches, record)
		}
	}

	if len(matches) == 0 {
		record := Record{
			Type:    assignment.Type,
			Name:    assignment.Name,
			Content: address,
			TTL:     1,
		}

		err := record.Update(zone.Name)
		if err != nil {
			return false, err
		}

		err = s.setRecordLocked(assignment.Zone, zone, &record)
		if err != nil {
			return false, err
		}

		return true, nil
	}

	updated := false

	for _, current := range matches {
		if current.Content == address {
			continue
		}

		record := *current
		record.Content = address

		err := record.Update(zone.Name)
		if err != nil {
			return false, err
		}

		err = s.setRecordLocked(assignment.Zone, zone, &record)
		if err != nil {
			return false, err
		}

		updated = true
	}

	return updated, nil
}

func (s *Storage) prepareDynDNSUser(request DynDNSUserRequest, requirePassword bool) (*DynDNSUser, error) {
	username := strings.TrimSpace(request.Username)
	if username == "" {
		return nil, errors.New("username is required")
	}

	if !validDynDNSUsername(username) {
		return nil, errors.New("invalid username")
	}

	if requirePassword && request.Password == "" {
		return nil, errors.New("password is required")
	}

	records := make([]DynDNSRecord, 0, len(request.Records))
	seen := make(map[DynDNSRecord]struct{}, len(request.Records))

	for _, record := range request.Records {
		record, err := s.normalizeDynDNSRecord(record)
		if err != nil {
			return nil, err
		}

		if _, exists := seen[record]; exists {
			continue
		}

		seen[record] = struct{}{}
		records = append(records, record)
	}

	slices.SortFunc(records, compareDynDNSRecords)

	user := &DynDNSUser{
		Username: username,
		Records:  records,
	}

	if request.Password != "" {
		hash, err := hashDynDNSPassword(request.Password)
		if err != nil {
			return nil, err
		}

		user.PasswordHash = hash
	}

	return user, nil
}

func (s *Storage) normalizeDynDNSRecord(record DynDNSRecord) (DynDNSRecord, error) {
	record.Zone = strings.TrimSpace(record.Zone)
	record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
	record.Name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(record.Name)), ".")

	if record.Type != "A" && record.Type != "AAAA" {
		return DynDNSRecord{}, errors.New("DynDNS records must be A or AAAA")
	}

	s.mx.RLock()

	zone, exists := s.zones[record.Zone]
	if !exists {
		s.mx.RUnlock()

		return DynDNSRecord{}, errors.New("unknown zone")
	}

	zoneName := strings.ToLower(zone.Name)
	s.mx.RUnlock()

	if record.Name == zoneName {
		record.Name = "@"
	} else if strings.HasSuffix(record.Name, "."+zoneName) {
		record.Name = record.Name[:len(record.Name)-len(zoneName)-1]
	}

	if record.Name == "" || (record.Name != "@" && !validDNSName(record.Name+"."+zoneName)) {
		return DynDNSRecord{}, errors.New("invalid record name")
	}

	return record, nil
}

func (s *Storage) LoadDynDNS() error {
	file, err := OpenFileForReading(DynDNSFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}

		return err
	}

	var users []DynDNSUser

	err = yaml.NewDecoder(file).Decode(&users)

	closeErr := file.Close()

	if err != nil {
		return err
	}

	if closeErr != nil {
		return closeErr
	}

	assignedIDs := make(map[string]struct{}, len(users))

	var needsStore bool

	for index := range users {
		user := users[index]

		if user.Username == "" || user.PasswordHash == "" {
			return errors.New("invalid DynDNS user")
		}

		if _, exists := s.dyndnsUsers[user.Username]; exists {
			return fmt.Errorf("duplicate DynDNS username %q", user.Username)
		}

		if user.ID == "" {
			user.ID, err = newDynDNSUserID()
			if err != nil {
				return err
			}

			needsStore = true
		}

		if _, exists := assignedIDs[user.ID]; exists {
			return fmt.Errorf("duplicate DynDNS user ID %q", user.ID)
		}

		assignedIDs[user.ID] = struct{}{}

		if user.Records == nil {
			user.Records = make([]DynDNSRecord, 0)
		}

		s.dyndnsUsers[user.Username] = &user
	}

	if needsStore {
		return s.storeDynDNSLocked()
	}

	return nil
}

func (s *Storage) storeDynDNSLocked() error {
	s.fx.Lock()
	defer s.fx.Unlock()

	users := make([]DynDNSUser, 0, len(s.dyndnsUsers))

	for _, user := range s.dyndnsUsers {
		users = append(users, *user)
	}

	slices.SortFunc(users, func(first, second DynDNSUser) int {
		return strings.Compare(first.Username, second.Username)
	})

	tempPath := DynDNSFile + ".tmp"

	file, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer file.Close()
	defer os.Remove(tempPath)

	err = file.Chmod(0600)
	if err != nil {
		return err
	}

	err = yaml.NewEncoder(file).Encode(users)
	if err != nil {
		return err
	}

	err = file.Close()
	if err != nil {
		return err
	}

	return os.Rename(tempPath, DynDNSFile)
}

func HandleDynDNSUpdate(storage *Storage) http.HandlerFunc {
	return func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		username, password, ok := request.BasicAuth()
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="DynDNS"`)
			writeDynDNSResponse(w, http.StatusUnauthorized, "badauth")

			return
		}

		user, ok := storage.AuthenticateDynDNS(username, password)
		if !ok {
			writeDynDNSResponse(w, http.StatusUnauthorized, "badauth")

			return
		}

		hostnames := parseDynDNSHostnames(request.URL.Query().Get("hostname"))

		logs := make([]DynDNSLog, 0, max(1, len(hostnames)))

		entry := DynDNSLog{
			Time:   time.Now().UTC(),
			Source: requestClientAddress(request),
		}

		defer func() {
			err := storage.AppendDynDNSLogs(username, user.ID, logs)
			if err != nil {
				log.Warnf("DynDNS log persistence failed for %s: %v", username, err)
			}
		}()

		if len(hostnames) == 0 {
			entry.Result = "nohost"

			logs = append(logs, entry)

			writeDynDNSResponse(w, http.StatusOK, "nohost")

			return
		}

		address := strings.TrimSpace(request.URL.Query().Get("myip"))
		if address == "" {
			address = requestClientAddress(request)
		}

		ip := net.ParseIP(address)
		if ip == nil {
			for _, hostname := range hostnames {
				result := entry

				result.Hostname = hostname
				result.Result = "badip"

				logs = append(logs, result)
			}

			writeDynDNSResponse(w, http.StatusBadRequest, "badip")

			return
		}

		address = ip.String()
		recordType := "AAAA"

		if ip.To4() != nil {
			recordType = "A"
		}

		responses := make([]string, 0, len(hostnames))

		for _, hostname := range hostnames {
			result := entry

			result.Hostname = hostname
			result.Address = address

			assignment, hostAssigned, familyAssigned := findDynDNSAssignment(storage, user.Records, hostname, recordType)
			if !hostAssigned {
				result.Result = "nohost"

				logs = append(logs, result)
				responses = append(responses, "nohost")

				continue
			}

			if !familyAssigned {
				result.Result = "badip"

				logs = append(logs, result)
				responses = append(responses, "badip")

				continue
			}

			updated, err := storage.UpdateDynDNSRecord(assignment, address)
			if err != nil {
				result.Result = "911"
				result.Error = err.Error()

				logs = append(logs, result)

				writeDynDNSResponse(w, http.StatusInternalServerError, "911")

				return
			}

			err = storage.Store()
			if err != nil {
				result.Result = "911"
				result.Error = err.Error()

				logs = append(logs, result)

				writeDynDNSResponse(w, http.StatusInternalServerError, "911")

				return
			}

			if updated {
				result.Result = "good"

				responses = append(responses, "good "+address)
			} else {
				result.Result = "nochg"

				responses = append(responses, "nochg "+address)
			}

			logs = append(logs, result)
		}

		writeDynDNSResponse(w, http.StatusOK, strings.Join(responses, "\n"))
	}
}

func hashDynDNSPassword(password string) (string, error) {
	salt := make([]byte, DynDNSSaltSize)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	key, err := pbkdf2.Key(sha256.New, password, salt, DynDNSHashIterations, DynDNSKeySize)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", DynDNSHashIterations, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

func verifyDynDNSPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" || parts[1] != fmt.Sprint(DynDNSHashIterations) {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) != DynDNSSaltSize {
		return false
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(want) != DynDNSKeySize {
		return false
	}

	got, err := pbkdf2.Key(sha256.New, password, salt, DynDNSHashIterations, DynDNSKeySize)
	if err != nil {
		return false
	}

	return subtle.ConstantTimeCompare(got, want) == 1
}

func copyDynDNSUser(user *DynDNSUser) DynDNSUser {
	copy := *user
	copy.Records = slices.Clone(user.Records)

	return copy
}

func newDynDNSUserID() (string, error) {
	var random [16]byte

	_, err := rand.Read(random[:])
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(random[:]), nil
}

func compareDynDNSRecords(first, second DynDNSRecord) int {
	result := strings.Compare(first.Zone, second.Zone)
	if result != 0 {
		return result
	}

	result = strings.Compare(first.Name, second.Name)
	if result != 0 {
		return result
	}

	return strings.Compare(first.Type, second.Type)
}

func validDNSName(name string) bool {
	if len(name) > 253 {
		return false
	}

	for label := range strings.SplitSeq(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' && character != '_' {
				return false
			}
		}
	}

	return true
}

func validDynDNSUsername(username string) bool {
	if len(username) > 128 {
		return false
	}

	for _, character := range username {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') && (character < '0' || character > '9') && character != '-' && character != '_' && character != '.' && character != '@' {
			return false
		}
	}

	return true
}

func parseDynDNSHostnames(value string) []string {
	hostnames := make([]string, 0, strings.Count(value, ",")+1)
	seen := make(map[string]struct{}, strings.Count(value, ",")+1)

	for hostname := range strings.SplitSeq(value, ",") {
		hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
		if hostname == "" {
			continue
		}

		if _, exists := seen[hostname]; exists {
			continue
		}

		seen[hostname] = struct{}{}
		hostnames = append(hostnames, hostname)
	}

	return hostnames
}

func requestClientAddress(request *http.Request) string {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err == nil {
		return host
	}

	return strings.Trim(request.RemoteAddr, "[]")
}

func findDynDNSAssignment(storage *Storage, records []DynDNSRecord, hostname, recordType string) (DynDNSRecord, bool, bool) {
	hostAssigned := false

	for _, record := range records {
		storage.mx.RLock()

		zone := storage.zones[record.Zone]
		zoneName := ""

		if zone != nil {
			zoneName = zone.Name
		}

		storage.mx.RUnlock()

		if zoneName == "" {
			continue
		}

		name := record.Name + "." + zoneName

		if record.Name == "@" {
			name = zoneName
		}

		if !strings.EqualFold(name, hostname) {
			continue
		}

		hostAssigned = true

		if record.Type == recordType {
			return record, true, true
		}
	}

	return DynDNSRecord{}, hostAssigned, false
}

func writeDynDNSResponse(writer http.ResponseWriter, status int, response string) {
	writer.WriteHeader(status)

	fmt.Fprintln(writer, response)
}
