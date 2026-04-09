// Package store provides persistent storage for certificate check results.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cert-watcher/cert-watcher/internal/checker"
)

// Store manages persistent storage of certificate information.
type Store struct {
	dataDir    string
	dataFile   string
	historyDir string
	mu         sync.RWMutex
	data       *StoreData
}

// StoreData represents the persisted data structure.
type StoreData struct {
	Hosts         map[string]*HostData `json:"hosts"`
	LastUpdated   time.Time            `json:"last_updated"`
	Version       string               `json:"version"`
}

// HostData holds certificate data and metadata for a single host.
type HostData struct {
	Host            string    `json:"host"`
	Subject         string    `json:"subject"`
	Issuer          string    `json:"issuer"`
	Serial          string    `json:"serial"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	DaysRemaining  int       `json:"days_remaining"`
	IsValid         bool      `json:"is_valid"`
	Error           string    `json:"error,omitempty"`
	LastChecked     time.Time `json:"last_checked"`
	LastNotified    time.Time `json:"last_notified,omitempty"`
	NotificationCount int     `json:"notification_count"`
	CheckCount      int       `json:"check_count"`
}

// New creates a new Store instance.
func New(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	historyDir := filepath.Join(dataDir, "history")
	if err := os.MkdirAll(historyDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create history directory: %w", err)
	}

	s := &Store{
		dataDir:    dataDir,
		dataFile:   filepath.Join(dataDir, "certs.json"),
		historyDir: historyDir,
		data: &StoreData{
			Hosts:   make(map[string]*HostData),
			Version: "1.0",
		},
	}

	// Load existing data if available
	if err := s.Load(); err != nil {
		// It's okay if the file doesn't exist yet
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load existing data: %w", err)
		}
	}

	return s, nil
}

// Save persists the current state to disk.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.data.LastUpdated = time.Now()

	data, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	if err := os.WriteFile(s.dataFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write data file: %w", err)
	}

	return nil
}

// Load reads persisted data from disk.
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.dataFile)
	if err != nil {
		return err
	}

	var storeData StoreData
	if err := json.Unmarshal(data, &storeData); err != nil {
		return fmt.Errorf("failed to unmarshal data: %w", err)
	}

	s.data = &storeData
	return nil
}

// Update updates the stored data for a host.
func (s *Store) Update(host string, certInfo *checker.CertInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.data.Hosts[host]
	if !exists {
		existing = &HostData{Host: host}
	}

	existing.Subject = certInfo.Subject
	existing.Issuer = certInfo.Issuer
	existing.Serial = certInfo.Serial
	existing.NotBefore = certInfo.NotBefore
	existing.NotAfter = certInfo.NotAfter
	existing.DaysRemaining = certInfo.DaysRemaining
	existing.IsValid = certInfo.IsValid
	existing.Error = certInfo.Error
	existing.LastChecked = certInfo.CheckedAt
	existing.CheckCount++

	s.data.Hosts[host] = existing
	s.data.LastUpdated = time.Now()

	return nil
}

// UpdateNotificationTime records when a notification was sent for a host.
func (s *Store) UpdateNotificationTime(host string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	hostData, exists := s.data.Hosts[host]
	if !exists {
		hostData = &HostData{Host: host}
	}

	hostData.LastNotified = time.Now()
	hostData.NotificationCount++
	s.data.Hosts[host] = hostData

	return nil
}

// GetHost retrieves the stored data for a specific host.
func (s *Store) GetHost(host string) (*HostData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.data.Hosts[host]
	return data, exists
}

// GetAllHosts returns all stored host data.
func (s *Store) GetAllHosts() map[string]*HostData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]*HostData)
	for k, v := range s.data.Hosts {
		result[k] = v
	}
	return result
}

// GetLastChecked returns the last check time for a host.
func (s *Store) GetLastChecked(host string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.data.Hosts[host]
	if !exists {
		return time.Time{}, false
	}
	return data.LastChecked, true
}

// GetLastNotified returns the last notification time for a host.
func (s *Store) GetLastNotified(host string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, exists := s.data.Hosts[host]
	if !exists {
		return time.Time{}, false
	}
	return data.LastNotified, data.LastNotified != time.Time{}
}

// AddHistoryEntry saves a check result to the history file for a host.
func (s *Store) AddHistoryEntry(host string, certInfo *checker.CertInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	historyFile := filepath.Join(s.historyDir, fmt.Sprintf("%s.json", host))

	var history []checker.CertInfo
	data, err := os.ReadFile(historyFile)
	if err == nil {
		if err := json.Unmarshal(data, &history); err != nil {
			history = []checker.CertInfo{}
		}
	}

	history = append(history, *certInfo)

	// Keep only last 100 entries
	if len(history) > 100 {
		history = history[len(history)-100:]
	}

	out, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal history: %w", err)
	}

	if err := os.WriteFile(historyFile, out, 0644); err != nil {
		return fmt.Errorf("failed to write history file: %w", err)
	}

	return nil
}

// GetHistory retrieves the check history for a host.
func (s *Store) GetHistory(host string, limit int) ([]checker.CertInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	historyFile := filepath.Join(s.historyDir, fmt.Sprintf("%s.json", host))

	data, err := os.ReadFile(historyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read history file: %w", err)
	}

	var history []checker.CertInfo
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("failed to unmarshal history: %w", err)
	}

	if limit > 0 && len(history) > limit {
		return history[len(history)-limit:], nil
	}
	return history, nil
}

// Data returns the underlying store data (for dashboard).
func (s *Store) Data() *StoreData {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data
}

// LastUpdated returns the last time the store was updated.
func (s *Store) LastUpdated() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.data.LastUpdated
}
