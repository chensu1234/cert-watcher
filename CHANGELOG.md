# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-01

### Added

- Initial release
- TLS/SSL certificate expiry monitoring
- Support for Slack Webhook notifications
- Support for DingTalk (钉钉) Webhook notifications
- Configurable alert threshold per domain
- Colored terminal output
- Detailed logging
- Single-run mode (`--once`)
- Configurable check interval
- Support for custom HTTPS ports
- Multiple notification channel support

### Features

- 🛡️ Certificate expiry detection using OpenSSL
- ⏰ Configurable alert days (default: 30 days)
- 🔔 Smart color-coded output in terminal
- 📝 Comprehensive log file support
- 🔄 Continuous monitoring loop
- 🎯 Single domain check mode
- 🛠️ Flexible configuration format

### Supported Platforms

- macOS (10.15+)
- Linux (with Bash 4.0+)
- Other Unix-like systems with Bash and OpenSSL
