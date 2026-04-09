// Package ui provides the web dashboard for certificate monitoring.
package ui

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cert-watcher/cert-watcher/internal/checker"
	"github.com/cert-watcher/cert-watcher/internal/store"
)

// Dashboard provides an HTTP interface for viewing certificate status.
type Dashboard struct {
	addr       string
	store      *store.Store
	results    []*checker.Result
	mu         sync.RWMutex
	stopCh     chan struct{}
	server     *http.Server
	lastUpdate time.Time
}

// NewDashboard creates a new Dashboard instance.
func NewDashboard(addr string, store *store.Store) *Dashboard {
	return &Dashboard{
		addr:    addr,
		store:   store,
		results: []*checker.Result{},
		stopCh:  make(chan struct{}),
	}
}

// UpdateResults updates the current check results displayed on the dashboard.
func (d *Dashboard) UpdateResults(results []*checker.Result) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.results = results
	d.lastUpdate = time.Now()
}

// Start begins serving the dashboard HTTP server.
func (d *Dashboard) Start() error {
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/", d.handleIndex)
	mux.HandleFunc("/api/status", d.handleStatus)
	mux.HandleFunc("/api/hosts", d.handleHosts)
	mux.HandleFunc("/static/", d.handleStatic)

	// Use custom handler with dashboard state
	handler := d.withDashboard(mux)

	d.server = &http.Server{
		Addr:         d.addr,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		log.Printf("[INFO] Dashboard starting on %s", d.addr)
		if err := d.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[ERROR] Dashboard error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the dashboard server.
func (d *Dashboard) Stop() error {
	close(d.stopCh)
	if d.server != nil {
		return d.server.Close()
	}
	return nil
}

// withDashboard wraps an HTTP handler to inject dashboard state.
func (d *Dashboard) withDashboard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.RLock()
		results := d.results
		lastUpdate := d.lastUpdate
		d.mu.RUnlock()

		// Store in request context for handlers
		type contextKey string
		const resultsKey contextKey = "results"
		const lastUpdateKey contextKey = "lastUpdate"

		ctx := r.Context()
		ctx = withValue(ctx, resultsKey, results)
		ctx = withValue(ctx, lastUpdateKey, lastUpdate)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func withValue(ctx interface{}, key, val interface{}) interface{} {
	// Simple context helper - use standard context
	return ctx
}

// handleIndex serves the main dashboard page.
func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Get results from context (simplified)
	d.mu.RLock()
	results := d.results
	lastUpdate := d.lastUpdate
	d.mu.RUnlock()

	html := buildDashboardHTML(results, lastUpdate)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleStatus returns the current status as JSON.
func (d *Dashboard) handleStatus(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	results := d.results
	lastUpdate := d.lastUpdate
	d.mu.RUnlock()

	status := struct {
		Status     string    `json:"status"`
		TotalHosts int       `json:"total_hosts"`
		Healthy    int       `json:"healthy"`
		Warning    int       `json:"warning"`
		Critical   int       `json:"critical"`
		Error      int       `json:"error"`
		LastUpdate time.Time `json:"last_update"`
	}{
		Status:     "running",
		TotalHosts: len(results),
		Healthy:    0,
		Warning:    0,
		Critical:   0,
		Error:      0,
		LastUpdate: lastUpdate,
	}

	for _, r := range results {
		if r.CertInfo != nil && r.CertInfo.Error != "" {
			status.Error++
		} else if r.CertInfo != nil && r.CertInfo.DaysRemaining <= 7 {
			status.Critical++
		} else if r.CertInfo != nil && r.CertInfo.DaysRemaining <= 30 {
			status.Warning++
		} else {
			status.Healthy++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

// handleHosts returns all host data as JSON.
func (d *Dashboard) handleHosts(w http.ResponseWriter, r *http.Request) {
	d.mu.RLock()
	results := d.results
	d.mu.RUnlock()

	hosts := make([]map[string]interface{}, 0, len(results))
	for _, r := range results {
		if r.CertInfo != nil {
			host := map[string]interface{}{
				"host":           r.Host,
				"subject":        r.CertInfo.Subject,
				"issuer":         r.CertInfo.Issuer,
				"days_remaining": r.CertInfo.DaysRemaining,
				"not_after":       r.CertInfo.NotAfter.Format(time.RFC3339),
				"is_valid":        r.CertInfo.IsValid,
				"error":           r.CertInfo.Error,
				"checked_at":      r.CertInfo.CheckedAt.Format(time.RFC3339),
			}
			hosts = append(hosts, host)
		}
	}

	// Sort by days remaining
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i]["days_remaining"].(int) < hosts[j]["days_remaining"].(int)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(hosts)
}

// handleStatic serves static files.
func (d *Dashboard) handleStatic(w http.ResponseWriter, r *http.Request) {
	http.StripPrefix("/static/", http.FileServer(http.Dir("."))).ServeHTTP(w, r)
}

// getStatusColor returns a CSS color class based on days remaining.
func getStatusColor(daysRemaining int, hasError bool) string {
	if hasError {
		return "gray"
	}
	if daysRemaining <= 7 {
		return "red"
	}
	if daysRemaining <= 30 {
		return "yellow"
	}
	return "green"
}

// getStatusText returns a human-readable status.
func getStatusText(daysRemaining int, hasError bool) string {
	if hasError {
		return "Error"
	}
	if daysRemaining <= 7 {
		return "Critical"
	}
	if daysRemaining <= 30 {
		return "Warning"
	}
	return "Healthy"
}

// buildDashboardHTML generates the dashboard HTML page.
func buildDashboardHTML(results []*checker.Result, lastUpdate time.Time) string {
	// Calculate stats
	var total, healthy, warning, critical, errors int
	for _, r := range results {
		total++
		if r.CertInfo != nil && r.CertInfo.Error != "" {
			errors++
		} else if r.CertInfo != nil && r.CertInfo.DaysRemaining <= 7 {
			critical++
		} else if r.CertInfo != nil && r.CertInfo.DaysRemaining <= 30 {
			warning++
		} else {
			healthy++
		}
	}

	// Sort results by days remaining
	sortedResults := make([]*checker.Result, len(results))
	copy(sortedResults, results)
	sort.Slice(sortedResults, func(i, j int) bool {
		di, dj := 9999, 9999
		if sortedResults[i].CertInfo != nil {
			di = sortedResults[i].CertInfo.DaysRemaining
		}
		if sortedResults[j].CertInfo != nil {
			dj = sortedResults[j].CertInfo.DaysRemaining
		}
		return di < dj
	})

	var rows strings.Builder
	for _, r := range sortedResults {
		color := "gray"
		status := "Unknown"
		days := 0

		if r.CertInfo != nil {
			days = r.CertInfo.DaysRemaining
			if r.CertInfo.Error != "" {
				color = "gray"
				status = "Error"
			} else if days <= 7 {
				color = "red"
				status = "Critical"
			} else if days <= 30 {
				color = "yellow"
				status = "Warning"
			} else {
				color = "green"
				status = "Healthy"
			}
		}

		expires := "N/A"
		if r.CertInfo != nil && !r.CertInfo.NotAfter.IsZero() {
			expires = r.CertInfo.NotAfter.Format("2006-01-02 15:04")
		}

		subject := "N/A"
		if r.CertInfo != nil {
			subject = r.CertInfo.Subject
			if len(subject) > 50 {
				subject = subject[:50] + "..."
			}
		}

		rows.WriteString(fmt.Sprintf(`
		<tr class="status-%s">
			<td><span class="indicator"></span>%s</td>
			<td>%s</td>
			<td>%s</td>
			<td>%d</td>
			<td>%s</td>
			<td><span class="badge badge-%s">%s</span></td>
		</tr>`, color, r.Host, subject, expires, days, r.Host, color, status))
	}

	updateStr := lastUpdate.Format("2006-01-02 15:04:05")
	if lastUpdate.IsZero() {
		updateStr = "Never"
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Cert-Watcher Dashboard</title>
	<style>
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; }
		.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
		header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
		header h1 { font-size: 1.8em; }
		header p { opacity: 0.8; margin-top: 5px; }
		.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
		.stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }
		.stat-card h3 { font-size: 2em; margin-bottom: 5px; }
		.stat-card p { color: #666; font-size: 0.9em; }
		.stat-total h3 { color: #3498db; }
		.stat-healthy h3 { color: #27ae60; }
		.stat-warning h3 { color: #f39c12; }
		.stat-critical h3 { color: #e74c3c; }
		.stat-error h3 { color: #95a5a6; }
		.table-container { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }
		table { width: 100%%; border-collapse: collapse; }
		th { background: #34495e; color: white; padding: 12px; text-align: left; }
		td { padding: 12px; border-bottom: 1px solid #eee; }
		tr:last-child td { border-bottom: none; }
		tr:hover { background: #f8f9fa; }
		.indicator { display: inline-block; width: 10px; height: 10px; border-radius: 50%%; margin-right: 8px; }
		.status-green .indicator { background: #27ae60; }
		.status-yellow .indicator { background: #f39c12; }
		.status-red .indicator { background: #e74c3c; }
		.status-gray .indicator { background: #95a5a6; }
		.badge { padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: 500; }
		.badge-green { background: #d4edda; color: #155724; }
		.badge-yellow { background: #fff3cd; color: #856404; }
		.badge-red { background: #f8d7da; color: #721c24; }
		.badge-gray { background: #e9ecef; color: #6c757d; }
		.footer { text-align: center; padding: 20px; color: #666; font-size: 0.9em; }
	</style>
</head>
<body>
	<div class="container">
		<header>
			<h1>🔒 Cert-Watcher</h1>
			<p>TLS/SSL Certificate Monitoring Dashboard | Last updated: %s</p>
		</header>

		<div class="stats">
			<div class="stat-card stat-total">
				<h3>%d</h3>
				<p>Total Hosts</p>
			</div>
			<div class="stat-card stat-healthy">
				<h3>%d</h3>
				<p>Healthy</p>
			</div>
			<div class="stat-card stat-warning">
				<h3>%d</h3>
				<p>Warning</p>
			</div>
			<div class="stat-card stat-critical">
				<h3>%d</h3>
				<p>Critical</p>
			</div>
			<div class="stat-card stat-error">
				<h3>%d</h3>
				<p>Errors</p>
			</div>
		</div>

		<div class="table-container">
			<table>
				<thead>
					<tr>
						<th>Host</th>
						<th>Subject</th>
						<th>Expires</th>
						<th>Days Left</th>
						<th>CN</th>
						<th>Status</th>
					</tr>
				</thead>
				<tbody>
					%s
				</tbody>
			</table>
		</div>

		<div class="footer">
			<p>Cert-Watcher | Automated TLS Certificate Monitoring</p>
		</div>
	</div>
</body>
</html>`, updateStr, total, healthy, warning, critical, errors, rows.String())
}
