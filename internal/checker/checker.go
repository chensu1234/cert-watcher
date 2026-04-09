// Package checker provides TLS certificate checking functionality.
package checker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"
)

// CertInfo holds information about a TLS certificate.
type CertInfo struct {
	Host          string    `json:"host"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	Serial        string    `json:"serial"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	DaysRemaining int       `json:"days_remaining"`
	IsValid       bool      `json:"is_valid"`
	Error         string    `json:"error,omitempty"`
	CheckedAt     time.Time `json:"checked_at"`
}

// Result represents the result of a certificate check operation.
type Result struct {
	Host      string
	CertInfo  *CertInfo
	Error     error
}

// Check fetches and parses the TLS certificate for the given host.
func Check(host string) *CertInfo {
	info := &CertInfo{
		Host:      host,
		CheckedAt: time.Now(),
	}

	// Add default port if not specified
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	// Connect to the host
	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		info.Error = err.Error()
		info.IsValid = false
		return info
	}
	defer conn.Close()

	// Get the certificate chain
	state := conn.ConnectionState()
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		info.Error = "no certificate found"
		info.IsValid = false
		return info
	}

	cert := state.VerifiedChains[0][0]
	info.Subject = formatName(cert.Subject)
	info.Issuer = formatName(cert.Issuer)
	info.NotBefore = cert.NotBefore
	info.NotAfter = cert.NotAfter
	info.Serial = cert.SerialNumber.String()
	info.DaysRemaining = daysUntil(info.NotAfter)
	info.IsValid = time.Now().Before(info.NotAfter)

	return info
}

// CheckWithTimeout performs a certificate check with a timeout.
func CheckWithTimeout(host string, timeout time.Duration) *CertInfo {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resultCh := make(chan *CertInfo, 1)

	go func() {
		resultCh <- Check(host)
	}()

	select {
	case <-ctx.Done():
		return &CertInfo{
			Host:      host,
			CheckedAt: time.Now(),
			Error:     fmt.Sprintf("timeout after %v", timeout),
			IsValid:   false,
		}
	case info := <-resultCh:
		return info
	}
}

// CheckBatch checks multiple hosts concurrently.
func CheckBatch(hosts []string, timeout time.Duration) []*Result {
	results := make([]*Result, len(hosts))
	semaphore := make(chan struct{}, 10) // Limit concurrency

	for i, host := range hosts {
		semaphore <- struct{}{}
		go func(i int, host string) {
			defer func() { <-semaphore }()
			info := CheckWithTimeout(host, timeout)
			results[i] = &Result{
				Host:     host,
				CertInfo: info,
			}
		}(i, host)
	}

	// Wait for all goroutines to complete
	for i := 0; i < cap(semaphore); i++ {
		semaphore <- struct{}{}
	}

	return results
}

// formatName formats an x509.Name into a readable string.
func formatName(name any) string {
	switch n := name.(type) {
	case interface{ String() string }:
		return n.String()
	default:
		return fmt.Sprintf("%v", n)
	}
}

// daysUntil returns the number of days until the given time.
func daysUntil(t time.Time) int {
	duration := t.Sub(time.Now())
	days := int(duration.Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

// parsePeerCertificate parses the peer certificate from a connection state.
func parsePeerCertificate(state *tls.ConnectionState) (*x509.Certificate, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates")
	}
	return state.PeerCertificates[0], nil
}

// GetCertFromHost retrieves the raw certificate from a host for debugging.
func GetCertFromHost(host string) (*pem.Block, error) {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	conn, err := tls.Dial("tcp", host, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: state.PeerCertificates[0].Raw,
	}), nil
}

// LookupHost resolves a hostname to its IP addresses.
func LookupHost(host string) ([]string, error) {
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}
	hostname := strings.TrimSuffix(host, ":443")
	return net.LookupHost(hostname)
}
