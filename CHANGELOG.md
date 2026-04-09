# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2024-01-15

### Added
- Initial release with core functionality
- Multi-host TLS certificate monitoring
- Connect to target hosts on port 443 to retrieve TLS certificates
- Parse certificate Subject, Issuer, Serial, NotBefore, NotAfter
- Calculate days remaining until expiration
- Email notification via SMTP
- HTTP webhook notification support (POST JSON)
- Interactive web dashboard with color-coded status indicators
- JSON-based persistent storage for check history
- Configurable warning_days and critical_days thresholds
- Notification deduplication (24h window)
- Batch concurrent checking with configurable timeout
- Graceful shutdown support
- Command line flags: --config, --check-once, --version

### Features
- Color-coded dashboard: green (>30 days), yellow (7-30 days), red (<7 days), gray (error)
- Support for custom check intervals
- Error handling for connection failures
- Store last notification time for deduplication
- History tracking for each monitored host