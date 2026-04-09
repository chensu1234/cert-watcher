// Package notifier provides notification services for certificate alerts.
package notifier

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cert-watcher/cert-watcher/internal/checker"
)

// AlertLevel represents the severity of an alert.
type AlertLevel string

const (
	// LevelWarning indicates a warning-level alert (> critical but < normal).
	LevelWarning AlertLevel = "warning"
	// LevelCritical indicates a critical alert (<= critical threshold).
	LevelCritical AlertLevel = "critical"
)

// Notifier is the interface for sending notifications.
type Notifier interface {
	Send(level AlertLevel, certInfo *checker.CertInfo) error
	Name() string
}

// Manager manages multiple notifiers and handles deduplication.
type Manager struct {
	notifiers   []Notifier
	lastNotified map[string]time.Time
	mu           sync.RWMutex
	dedupWindow  time.Duration
}

// NewManager creates a new notification manager.
func NewManager(notifiers []Notifier, dedupWindow time.Duration) *Manager {
	return &Manager{
		notifiers:   notifiers,
		lastNotified: make(map[string]time.Time),
		dedupWindow:  dedupWindow,
	}
}

// ShouldNotify determines whether a notification should be sent based on deduplication.
func (m *Manager) ShouldNotify(host string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	last, exists := m.lastNotified[host]
	if !exists {
		return true
	}
	return time.Since(last) > m.dedupWindow
}

// Notify sends notifications through all configured notifiers.
func (m *Manager) Notify(level AlertLevel, certInfo *checker.CertInfo) error {
	if !m.ShouldNotify(certInfo.Host) {
		log.Printf("[DEBUG] Skipping notification for %s (deduplicated)", certInfo.Host)
		return nil
	}

	var lastErr error
	for _, n := range m.notifiers {
		if err := n.Send(level, certInfo); err != nil {
			log.Printf("[ERROR] Failed to notify via %s: %v", n.Name(), err)
			lastErr = err
		}
	}

	// Update last notification time only if at least one notifier succeeded
	if lastErr == nil || len(m.notifiers) == 0 {
		m.mu.Lock()
		m.lastNotified[certInfo.Host] = time.Now()
		m.mu.Unlock()
	}

	return lastErr
}

// NotifyAll sends notifications for all results.
func (m *Manager) NotifyAll(level AlertLevel, results []*checker.Result) {
	for _, r := range results {
		if r.CertInfo != nil && r.CertInfo.Error == "" {
			if err := m.Notify(level, r.CertInfo); err != nil {
				log.Printf("[WARN] Notification error for %s: %v", r.Host, err)
			}
		}
	}
}

// SetLastNotified sets the last notification time for a host (used for restoration from store).
func (m *Manager) SetLastNotified(host string, t time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastNotified[host] = t
}

// GetLastNotified returns the last notification time for a host.
func (m *Manager) GetLastNotified(host string) (time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, exists := m.lastNotified[host]
	return t, exists
}

// DetermineAlertLevel determines the alert level based on days remaining.
func DetermineAlertLevel(certInfo *checker.CertInfo, warningDays, criticalDays int) (AlertLevel, bool) {
	if certInfo.Error != "" {
		return "", false // No alert for errors
	}

	if certInfo.DaysRemaining <= criticalDays {
		return LevelCritical, true
	}
	if certInfo.DaysRemaining <= warningDays {
		return LevelWarning, true
	}
	return "", false
}

// FormatAlertMessage formats a notification message for a certificate.
func FormatAlertMessage(level AlertLevel, certInfo *checker.CertInfo) string {
	levelStr := "⚠️ WARNING"
	if level == LevelCritical {
		levelStr = "🚨 CRITICAL"
	}

	return fmt.Sprintf(`%s: Certificate for %s is expiring soon!

Host: %s
Days Remaining: %d
Expires: %s
Subject: %s
Issuer: %s

Please renew this certificate to avoid service interruption.`,
		levelStr,
		certInfo.Host,
		certInfo.Host,
		certInfo.DaysRemaining,
		certInfo.NotAfter.Format(time.RFC1123),
		certInfo.Subject,
		certInfo.Issuer,
	)
}
