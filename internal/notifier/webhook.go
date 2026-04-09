package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cert-watcher/cert-watcher/internal/checker"
)

// WebhookPayload represents the JSON payload sent to a webhook.
type WebhookPayload struct {
	Timestamp     string `json:"timestamp"`
	Level         string `json:"level"`
	Host          string `json:"host"`
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	Serial        string `json:"serial"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	DaysRemaining int    `json:"days_remaining"`
	Error         string `json:"error,omitempty"`
}

// WebhookNotifier sends notifications via HTTP webhooks.
type WebhookNotifier struct {
	url     string
	method  string
	headers map[string]string
	client  *http.Client
}

// NewWebhookNotifier creates a new webhook notifier.
func NewWebhookNotifier(url string, method string, headers map[string]string) *WebhookNotifier {
	return &WebhookNotifier{
		url:    url,
		method: method,
		headers: headers,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the name of this notifier.
func (w *WebhookNotifier) Name() string {
	return "webhook"
}

// Send sends a webhook notification.
func (w *WebhookNotifier) Send(level AlertLevel, certInfo *checker.CertInfo) error {
	payload := WebhookPayload{
		Timestamp:     time.Now().UTC().Format(time.RFC3339),
		Level:         string(level),
		Host:          certInfo.Host,
		Subject:       certInfo.Subject,
		Issuer:        certInfo.Issuer,
		Serial:        certInfo.Serial,
		NotBefore:     certInfo.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:      certInfo.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: certInfo.DaysRemaining,
		Error:         certInfo.Error,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest(w.method, w.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set default headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Cert-Watcher/1.0")

	// Override with custom headers
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-2xx status: %d", resp.StatusCode)
	}

	return nil
}

// SendRaw sends a raw JSON payload to the webhook.
func (w *WebhookNotifier) SendRaw(jsonPayload []byte) error {
	req, err := http.NewRequest(w.method, w.url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Cert-Watcher/1.0")

	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned non-2xx status: %d", resp.StatusCode)
	}

	return nil
}
