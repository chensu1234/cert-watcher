// Package main is the entry point for cert-watcher.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cert-watcher/cert-watcher/internal/checker"
	"github.com/cert-watcher/cert-watcher/internal/config"
	"github.com/cert-watcher/cert-watcher/internal/notifier"
	"github.com/cert-watcher/cert-watcher/internal/store"
	"github.com/cert-watcher/cert-watcher/internal/ui"
)

var (
	version = "1.0.0"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "config/config.yaml", "Path to configuration file")
	checkOnce := flag.Bool("check-once", false, "Run a single check and exit")
	showVersion := flag.Bool("version", false, "Show version information")
	flag.Parse()

	if *showVersion {
		fmt.Printf("cert-watcher %s (commit: %s, date: %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set log level
	setLogLevel(cfg.LogLevel)

	log.Printf("[INFO] Cert-Watcher v%s starting...", version)
	log.Printf("[INFO] Monitoring %d hosts", len(cfg.Hosts))

	// Initialize store
	s, err := store.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}

	// Initialize notifiers
	notifiers := initNotifiers(cfg)

	// Create notification manager with 24h deduplication
	notifyManager := notifier.NewManager(notifiers, 24*time.Hour)

	// Restore notification times from store
	for _, host := range cfg.Hosts {
		if lastNotified, exists := s.GetLastNotified(host); exists {
			notifyManager.SetLastNotified(host, lastNotified)
		}
	}

	// Initialize dashboard
	var dashboard *ui.Dashboard
	if cfg.Dashboard.Enabled {
		dashboard = ui.NewDashboard(fmt.Sprintf("%s:%d", cfg.Dashboard.Host, cfg.Dashboard.Port), s)
		if err := dashboard.Start(); err != nil {
			log.Printf("[WARN] Failed to start dashboard: %v", err)
		}
	}

	// Set up graceful shutdown
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	// Run initial check
	runCheck(cfg, s, notifyManager, dashboard)

	// If check-once mode, exit after first check
	if *checkOnce {
		log.Printf("[INFO] Check-once mode, exiting")
		if dashboard != nil {
			dashboard.Stop()
		}
		os.Exit(0)
	}

	// Run periodic checks
	ticker := time.NewTicker(cfg.GetCheckInterval())
	defer ticker.Stop()

	log.Printf("[INFO] Next check in %s", cfg.GetCheckInterval())

	for {
		select {
		case <-ticker.C:
			runCheck(cfg, s, notifyManager, dashboard)
			log.Printf("[INFO] Next check in %s", cfg.GetCheckInterval())
		case <-stopCh:
			log.Printf("[INFO] Shutting down...")
			if dashboard != nil {
				dashboard.Stop()
			}
			return
		}
	}
}

// runCheck performs a certificate check for all configured hosts.
func runCheck(cfg *config.Config, s *store.Store, nm *notifier.Manager, dashboard *ui.Dashboard) {
	log.Printf("[INFO] Running certificate check for %d hosts", len(cfg.Hosts))

	results := checker.CheckBatch(cfg.Hosts, 30*time.Second)

	// Process results
	for _, result := range results {
		if result.CertInfo != nil {
			// Update store
			if err := s.Update(result.Host, result.CertInfo); err != nil {
				log.Printf("[ERROR] Failed to update store for %s: %v", result.Host, err)
			}

			// Add history entry
			if err := s.AddHistoryEntry(result.Host, result.CertInfo); err != nil {
				log.Printf("[ERROR] Failed to add history for %s: %v", result.Host, err)
			}

			// Determine if notification is needed
			if level, shouldNotify := notifier.DetermineAlertLevel(result.CertInfo, cfg.WarningDays, cfg.CriticalDays); shouldNotify {
				if err := nm.Notify(level, result.CertInfo); err != nil {
					log.Printf("[ERROR] Notification failed for %s: %v", result.Host, err)
				} else {
					log.Printf("[INFO] Notification sent for %s (%s)", result.Host, level)
					s.UpdateNotificationTime(result.Host)
				}
			}

			// Log result
			if result.CertInfo.Error != "" {
				log.Printf("[ERROR] %s: %s", result.Host, result.CertInfo.Error)
			} else {
				log.Printf("[INFO] %s: %d days remaining (expires: %s)",
					result.Host, result.CertInfo.DaysRemaining, result.CertInfo.NotAfter.Format("2006-01-02"))
			}
		}
	}

	// Update dashboard
	if dashboard != nil {
		dashboard.UpdateResults(results)
	}

	// Save store
	if err := s.Save(); err != nil {
		log.Printf("[ERROR] Failed to save store: %v", err)
	}
}

// initNotifiers creates notifier instances based on configuration.
func initNotifiers(cfg *config.Config) []notifier.Notifier {
	var notifiers []notifier.Notifier

	if cfg.Notifiers.Email.Enabled {
		emailNotifier := notifier.NewEmailNotifier(
			cfg.Notifiers.Email.SMTPHost,
			cfg.Notifiers.Email.SMTPPort,
			cfg.Notifiers.Email.SMTPUser,
			cfg.Notifiers.Email.SMTPPassword,
			cfg.Notifiers.Email.From,
			cfg.Notifiers.Email.To,
			cfg.Notifiers.Email.SubjectPrefix,
		)
		notifiers = append(notifiers, emailNotifier)
		log.Printf("[INFO] Email notifications enabled")
	}

	if cfg.Notifiers.Webhook.Enabled {
		webhookNotifier := notifier.NewWebhookNotifier(
			cfg.Notifiers.Webhook.URL,
			cfg.Notifiers.Webhook.Method,
			cfg.Notifiers.Webhook.Headers,
		)
		notifiers = append(notifiers, webhookNotifier)
		log.Printf("[INFO] Webhook notifications enabled")
	}

	return notifiers
}

// setLogLevel configures the log output level.
func setLogLevel(level string) {
	switch level {
	case "debug":
		log.SetOutput(os.Stdout)
	case "info":
		log.SetOutput(os.Stdout)
	case "warn":
		log.SetOutput(os.Stdout)
	case "error":
		log.SetOutput(os.Stderr)
	default:
		log.SetOutput(os.Stdout)
	}
}
