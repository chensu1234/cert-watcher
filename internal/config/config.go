// Package config handles configuration loading and validation for cert-watcher.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure.
type Config struct {
	Hosts        []string  `yaml:"hosts"`
	CheckInterval string    `yaml:"check_interval"`
	WarningDays  int       `yaml:"warning_days"`
	CriticalDays int       `yaml:"critical_days"`
	LogLevel     string    `yaml:"log_level"`
	DataDir      string    `yaml:"data_dir"`
	Notifiers    Notifiers `yaml:"notifiers"`
	Dashboard    Dashboard `yaml:"dashboard"`
}

// Notifiers holds all notification configuration.
type Notifiers struct {
	Email   EmailConfig   `yaml:"email"`
	Webhook WebhookConfig `yaml:"webhook"`
}

// EmailConfig holds SMTP email notification settings.
type EmailConfig struct {
	Enabled      bool     `yaml:"enabled"`
	SMTPHost     string   `yaml:"smtp_host"`
	SMTPPort     int      `yaml:"smtp_port"`
	SMTPUser     string   `yaml:"smtp_user"`
	SMTPPassword string   `yaml:"smtp_password"`
	From         string   `yaml:"from"`
	To           []string `yaml:"to"`
	SubjectPrefix string  `yaml:"subject_prefix"`
}

// WebhookConfig holds HTTP webhook notification settings.
type WebhookConfig struct {
	Enabled bool              `yaml:"enabled"`
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"`
	Headers map[string]string `yaml:"headers"`
}

// Dashboard holds the web dashboard configuration.
type Dashboard struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Host    string `yaml:"host"`
}

// Load reads and parses the configuration from the given file path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// Set defaults
	if cfg.CheckInterval == "" {
		cfg.CheckInterval = "24h"
	}
	if cfg.WarningDays == 0 {
		cfg.WarningDays = 30
	}
	if cfg.CriticalDays == 0 {
		cfg.CriticalDays = 7
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if cfg.Dashboard.Port == 0 {
		cfg.Dashboard.Port = 8080
	}
	if cfg.Dashboard.Host == "" {
		cfg.Dashboard.Host = "0.0.0.0"
	}

	return &cfg, nil
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if len(c.Hosts) == 0 {
		return fmt.Errorf("no hosts configured")
	}
	if c.CheckInterval != "" {
		if _, err := time.ParseDuration(c.CheckInterval); err != nil {
			return fmt.Errorf("invalid check_interval format: %w", err)
		}
	}
	if c.WarningDays <= 0 {
		return fmt.Errorf("warning_days must be positive")
	}
	if c.CriticalDays <= 0 {
		return fmt.Errorf("critical_days must be positive")
	}
	if c.WarningDays <= c.CriticalDays {
		return fmt.Errorf("warning_days must be greater than critical_days")
	}
	return nil
}

// GetCheckInterval returns the check interval as a time.Duration.
func (c *Config) GetCheckInterval() time.Duration {
	d, _ := time.ParseDuration(c.CheckInterval)
	if d == 0 {
		return 24 * time.Hour
	}
	return d
}
