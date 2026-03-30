# 🔐 cert-watcher

**SSL/TLS Certificate Monitoring and Expiration Alert Tool**

Monitor your SSL/TLS certificates and receive alerts before they expire. Works with both remote hosts and local certificate files.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Shell: Bash](https://img.shields.io/badge/Shell-Bash-4EAA25.svg)](https://www.gnu.org/software/bash/)
[![Platform: macOS & Linux](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux-FF6600.svg)](https://www.apple.com/macos/)

---

## ✨ Features

- 🔍 **Remote & Local Support** - Monitor certificates on remote servers or local `.pem`/`.crt` files
- ⏰ **Automatic Monitoring** - Run continuously with configurable check intervals
- 🚨 **Smart Alerts** - State-change notifications only (no alert fatigue)
- 📊 **Multiple Status Levels** - OK, Warning, Critical, and Expired states
- 🎨 **Colored Output** - Easy-to-read terminal output with color coding
- 📝 **Detailed Logging** - All checks logged to file with timestamps
- 🔔 **Webhook Support** - Send notifications to Slack, generic webhooks, or any JSON endpoint
- 💻 **Cross-Platform** - Works on macOS and Linux with pure Bash
- 🛡️ **Safe & Reliable** - Uses `set -euo pipefail` for error handling
- 📋 **Rich Certificate Info** - Extracts CN, issuer, expiry date, and SANs

---

## 🏃 Quick Start

### Prerequisites

- `bash` 4.0+
- `openssl`
- `curl` (for webhook notifications)

### Installation

```bash
# Clone or download the repository
git clone https://github.com/yourusername/cert-watcher.git
cd cert-watcher

# Make the script executable
chmod +x bin/cert-watcher.sh

# Edit the configuration file
vim config/certs.conf

# Run a single check
./bin/cert-watcher.sh

# Or run continuous monitoring
./bin/cert-watcher.sh --config ./config/certs.conf
```

### Basic Usage

```bash
# Check certificates with default settings
./bin/cert-watcher.sh

# Check every 5 minutes
./bin/cert-watcher.sh --interval 300

# Custom warning (45 days) and critical (14 days) thresholds
./bin/cert-watcher.sh --warning 45 --critical 14

# Use custom configuration file
./bin/cert-watcher.sh --config /path/to/certs.conf

# Enable Slack notifications
./bin/cert-watcher.sh --webhook https://hooks.slack.com/services/xxx/yyy/zzz

# Check once and exit (useful for cron jobs)
./bin/cert-watcher.sh --interval 0
```

---

## ⚙️ Configuration

### Configuration File Format

The configuration file (`config/certs.conf`) contains one entry per line:

```
# Remote hosts (host:port format)
example.com:443
github.com:443
mail.google.com:993

# Local certificate files (absolute paths)
/etc/ssl/certs/ssl-cert-snakeoil.pem
/etc/letsencrypt/live/example.com/fullchain.pem
```

### Rules:
- Lines starting with `#` are comments
- Blank lines are ignored
- Remote hosts: `hostname:port`
- Local files: absolute paths starting with `/`

### Example Configuration

```bash
# Remote hosts
google.com:443
github.com:443

# Local certificates
/etc/ssl/certs/ssl-cert-snakeoil.pem

# Mail servers
# imap.gmail.com:993
# smtp.gmail.com:587
```

---

## 📋 Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config FILE` | `-c` | Path to configuration file | `./config/certs.conf` |
| `--interval SECONDS` | `-i` | Check interval in seconds (0 = single run) | `3600` (1 hour) |
| `--warning DAYS` | `-w` | Warning threshold in days | `30` |
| `--critical DAYS` | `-r` | Critical threshold in days | `7` |
| `--webhook URL` | `-u` | Webhook URL for notifications | (none) |
| `--help` | `-h` | Show help message | - |

### Examples:

```bash
# Check every 30 minutes
--interval 1800

# Warn at 60 days, critical at 30 days
--warning 60 --critical 30

# Single check without looping (for cron)
--interval 0
```

---

## 📁 Project Structure

```
cert-watcher/
├── bin/
│   └── cert-watcher.sh          # Main executable script
├── config/
│   └── cert-watcher.conf        # Example configuration
├── log/
│   └── cert-watcher.log         # Log file (created on first run)
├── var/
│   └── cert-state.json          # State tracking file
├── README.md                    # This file
├── LICENSE                      # MIT License
└── CHANGELOG.md                 # Version history
```

---

## 🌐 Certificate Status Levels

| Status | Color | Description |
|--------|-------|-------------|
| ✅ OK | Green | Certificate is valid with more days than warning threshold |
| ⚠️ WARNING | Yellow | Certificate expires within warning threshold |
| 🔴 CRITICAL | Red | Certificate expires within critical threshold |
| 💀 EXPIRED | Red | Certificate has already expired |

---

## 🔔 Webhook Notifications

When a webhook URL is configured, cert-watcher sends JSON notifications on state changes:

### Payload Format

```json
{
  "event_type": "alert",
  "target": "remote:example.com:443",
  "message": "🔴 Certificate remote:example.com:443 is now CRITICAL (5 days until expiry)",
  "days_until_expiry": 5,
  "timestamp": "2026-03-30T10:30:00+08:00"
}
```

### Slack Integration

For Slack, use an incoming webhook URL:
```bash
./bin/cert-watcher.sh --webhook https://hooks.slack.com/services/T00/B00/xxxx
```

### Generic Webhook

Any endpoint that accepts POST requests with JSON will work.

---

## 📝 Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All certificates OK (or only warnings) |
| `1` | One or more certificates are critical or expired |
| `2` | Configuration error or file not found |

---

## 📝 CHANGELOG

### v1.0.0 (2026-03-30)

**Initial Release**

- ✅ Remote SSL/TLS certificate checking via openssl s_client
- ✅ Local certificate file support (.pem, .crt, .key)
- ✅ Certificate state tracking to avoid duplicate alerts
- ✅ Webhook notifications for Slack and generic endpoints
- ✅ Configurable warning and critical thresholds
- ✅ Colored terminal output (GREEN/YELLOW/RED)
- ✅ Comprehensive logging to file
- ✅ macOS and Linux compatibility
- ✅ Pure Bash implementation (no external dependencies except openssl/curl)

---

## 📄 License

MIT License

Copyright (c) 2026 Chen Su

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
