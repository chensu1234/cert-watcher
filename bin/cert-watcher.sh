#!/usr/bin/env bash
#
# cert-watcher.sh - SSL/TLS Certificate Monitoring and Expiration Alert Tool
#
# This script monitors SSL/TLS certificates (from local files or remote hosts)
# and sends alerts before they expire. It tracks certificate state and only
# notifies on state changes to avoid alert fatigue.
#
# Usage: cert-watcher.sh [OPTIONS]
#
# Options:
#   -c, --config FILE      Configuration file path (default: ./config/certs.conf)
#   -i, --interval SECONDS Check interval in seconds (default: 3600 = 1 hour)
#   -w, --warning DAYS     Warning threshold in days (default: 30)
#   -r, --critical DAYS    Critical threshold in days (default: 7)
#   -u, --webhook URL      Webhook URL for notifications
#   -h, --help             Show this help message
#
# Requirements:
#   - openssl (for certificate extraction)
#   - curl (for webhook notifications)
#   - bash 4.0+ (for associative arrays)
#
# Author: Chen Su
# License: MIT
#

set -euo pipefail

# ----------------------------------------------------------------------
# Script Configuration - Defaults
# ----------------------------------------------------------------------

# Default paths (can be overridden via command-line arguments)
CONFIG_FILE="./config/certs.conf"
CHECK_INTERVAL=3600          # 1 hour in seconds
WARNING_THRESHOLD=30         # days
CRITICAL_THRESHOLD=7         # days
WEBHOOK_URL=""               # empty = no webhook notifications
STATE_FILE="./var/cert-state.json"
LOG_FILE="./log/cert-watcher.log"

# Color codes for terminal output (disabled if not a terminal)
if [[ -t 1 ]]; then
    COLOR_GREEN='\033[0;32m'
    COLOR_YELLOW='\033[0;33m'
    COLOR_RED='\033[0;31m'
    COLOR_BLUE='\033[0;34m'
    COLOR_RESET='\033[0m'
    COLOR_BOLD='\033[1m'
else
    COLOR_GREEN=''
    COLOR_YELLOW=''
    COLOR_RED=''
    COLOR_BLUE=''
    COLOR_RESET=''
    COLOR_BOLD=''
fi

# ----------------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------------

# Log a message to the log file and optionally to stdout
# Usage: log "INFO" "Message text"
log() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"

    # Append to log file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    # Also print to stdout if it's a terminal
    if [[ -t 1 ]]; then
        echo -e "[$timestamp] [$level] $message"
    fi
}

# Send a webhook notification (JSON payload)
# Usage: send_webhook "alert|recovery" "hostname" "message" "days_until_expiry"
send_webhook() {
    local event_type="$1"
    local target="$2"
    local message="$3"
    local days_left="$4"

    # Skip if no webhook URL configured
    if [[ -z "$WEBHOOK_URL" ]]; then
        return 0
    fi

    # Build JSON payload
    local payload
    payload=$(cat <<EOF
{
  "event_type": "$event_type",
  "target": "$target",
  "message": "$message",
  "days_until_expiry": $days_left,
  "timestamp": "$(date -Iseconds)"
}
EOF
)

    # Send webhook notification (non-blocking, with timeout)
    if command -v curl &>/dev/null; then
        curl -s -X POST \
            -H "Content-Type: application/json" \
            -d "$payload" \
            --max-time 10 \
            "$WEBHOOK_URL" &>/dev/null || true
    fi
}

# Parse command-line arguments
# Usage: parse_args "$@"
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -i|--interval)
                CHECK_INTERVAL="$2"
                shift 2
                ;;
            -w|--warning)
                WARNING_THRESHOLD="$2"
                shift 2
                ;;
            -r|--critical)
                CRITICAL_THRESHOLD="$2"
                shift 2
                ;;
            -u|--webhook)
                WEBHOOK_URL="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${COLOR_RED}Error: Unknown option: $1${COLOR_RESET}" >&2
                show_help
                exit 1
                ;;
        esac
    done
}

# Display help message
show_help() {
    cat <<'HELP_EOF'
cert-watcher.sh - SSL/TLS Certificate Monitoring and Expiration Alert Tool

USAGE:
    cert-watcher.sh [OPTIONS]

OPTIONS:
    -c, --config FILE      Configuration file path (default: ./config/certs.conf)
    -i, --interval SECONDS Check interval in seconds (default: 3600 = 1 hour)
    -w, --warning DAYS     Warning threshold in days (default: 30)
    -r, --critical DAYS    Critical threshold in days (default: 7)
    -u, --webhook URL      Webhook URL for notifications (Slack/generic)
    -h, --help             Show this help message

CONFIGURATION FILE FORMAT:
    Each line can be:
      - host:port   (e.g., example.com:443)
      - /path/to/cert.pem  (local certificate file)
    Lines starting with # are comments.
    Blank lines are ignored.

EXAMPLES:
    # Check certificates every hour (default)
    ./cert-watcher.sh

    # Check every 5 minutes with custom config
    ./cert-watcher.sh -c /path/to/certs.conf -i 300

    # Custom warning (45 days) and critical (14 days) thresholds
    ./cert-watcher.sh -w 45 -r 14

    # Enable Slack notifications
    ./cert-watcher.sh -u https://hooks.slack.com/services/xxx/yyy/zzz

EXIT CODES:
    0   All certificates are valid (or only warnings)
    1   One or more certificates are expired or critical
    2   Configuration error or file not found

HELP_EOF
}

# ----------------------------------------------------------------------
# Certificate Functions
# ----------------------------------------------------------------------

# Check a remote host's SSL certificate
# Usage: check_remote_cert "host" "port"
# Returns: JSON string with cert info or empty on failure
check_remote_cert() {
    local host="$1"
    local port="$2"

    # Use openssl to get certificate info with timeout
    # The -servername flag enables SNI (Server Name Indication)
    local cert_info
    cert_info=$(echo | openssl s_client -servername "$host" -connect "${host}:${port}" 2>/dev/null \
        | openssl x509 -noout -dates -subject -issuer -ext subjectAltName 2>/dev/null) || return 1

    # Extract expiration date
    local not_after
    not_after=$(echo "$cert_info" | grep "notAfter=" | sed 's/notAfter=//') || return 1

    # Convert to days until expiration
    local expiry_epoch
    expiry_epoch=$(date -j -f "%b %d %T %Y %Z" "$not_after" "+%s" 2>/dev/null) || return 1

    local now_epoch
    now_epoch=$(date "+%s")
    local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    # Extract subject/CN
    local subject
    subject=$(echo "$cert_info" | grep "subject=" | sed 's/subject=//') || subject="$host"

    # Extract issuer
    local issuer
    issuer=$(echo "$cert_info" | grep "issuer=" | sed 's/issuer=//') || issuer="Unknown"

    # Extract SANs (Subject Alternative Names)
    local sans
    sans=$(echo "$cert_info" | grep -A1 "Subject Alternative Name" | tail -1 \
        | sed 's/DNS://g' | tr ',' '\n' | tr -d ' ' | grep -v '^$' | tr '\n' ',' | sed 's/,$//') || sans=""

    # Build JSON result
    cat <<EOF
{
  "type": "remote",
  "host": "$host",
  "port": $port,
  "subject": "$subject",
  "issuer": "$issuer",
  "sans": "$sans",
  "not_after": "$not_after",
  "days_left": $days_left,
  "expiry_epoch": $expiry_epoch
}
EOF
}

# Check a local certificate file
# Usage: check_local_cert "/path/to/cert.pem"
# Returns: JSON string with cert info or empty on failure
check_local_cert() {
    local cert_file="$1"

    # Check if file exists and is readable
    if [[ ! -r "$cert_file" ]]; then
        return 1
    fi

    # Use openssl to extract certificate info
    local cert_info
    cert_info=$(openssl x509 -in "$cert_file" -noout -dates -subject -issuer -ext subjectAltName 2>/dev/null) || return 1

    # Extract expiration date
    local not_after
    not_after=$(echo "$cert_info" | grep "notAfter=" | sed 's/notAfter=//') || return 1

    # Convert to days until expiration
    local expiry_epoch
    expiry_epoch=$(date -j -f "%b %d %T %Y %Z" "$not_after" "+%s" 2>/dev/null) || return 1

    local now_epoch
    now_epoch=$(date "+%s")
    local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    # Extract subject/CN
    local subject
    subject=$(echo "$cert_info" | grep "subject=" | sed 's/subject=//') || subject="$(basename "$cert_file")"

    # Extract issuer
    local issuer
    issuer=$(echo "$cert_info" | grep "issuer=" | sed 's/issuer=//') || issuer="Unknown"

    # Extract SANs
    local sans
    sans=$(echo "$cert_info" | grep -A1 "Subject Alternative Name" | tail -1 \
        | sed 's/DNS://g' | tr ',' '\n' | tr -d ' ' | grep -v '^$' | tr '\n' ',' | sed 's/,$//') || sans=""

    # Build JSON result
    cat <<EOF
{
  "type": "local",
  "file": "$cert_file",
  "subject": "$subject",
  "issuer": "$issuer",
  "sans": "$sans",
  "not_after": "$not_after",
  "days_left": $days_left,
  "expiry_epoch": $expiry_epoch
}
EOF
}

# Determine certificate status based on days left
# Usage: get_status "$days_left"
get_status() {
    local days_left="$1"

    if [[ $days_left -le 0 ]]; then
        echo "EXPIRED"
    elif [[ $days_left -le CRITICAL_THRESHOLD ]]; then
        echo "CRITICAL"
    elif [[ $days_left -le WARNING_THRESHOLD ]]; then
        echo "WARNING"
    else
        echo "OK"
    fi
}

# Get a color for a status
# Usage: get_status_color "STATUS"
get_status_color() {
    case "$1" in
        EXPIRED|CRITICAL) echo "$COLOR_RED" ;;
        WARNING)          echo "$COLOR_YELLOW" ;;
        OK)               echo "$COLOR_GREEN" ;;
        *)                echo "$COLOR_RESET" ;;
    esac
}

# Get an emoji for a status
get_status_emoji() {
    case "$1" in
        EXPIRED)  echo "💀" ;;
        CRITICAL) echo "🔴" ;;
        WARNING)  echo "⚠️" ;;
        OK)       echo "✅" ;;
        *)        echo "❓" ;;
    esac
}

# ----------------------------------------------------------------------
# State Management Functions
# ----------------------------------------------------------------------

# Load previous certificate states from state file
# Usage: load_states
load_states() {
    if [[ -f "$STATE_FILE" && -r "$STATE_FILE" ]]; then
        # Parse JSON state file using grep and sed (simple parser)
        # Format: "target": { "status": "OK", "last_check": "..." }
        while IFS= read -r line; do
            # Extract target name
            target=$(echo "$line" | sed -n 's/.*"\([^"]*\)":.*/\1/p')
            status=$(echo "$line" | sed -n 's/.*"status": *"\([^"]*\)".*/\1/p')
            if [[ -n "$target" && -n "$status" ]]; then
                declare -g "STATE_$target=$status"
            fi
        done < <(grep -o '"[^"]*":.*"status"' "$STATE_FILE" 2>/dev/null || true)
    fi
}

# Save current certificate states to state file
# Usage: save_states
save_states() {
    local temp_file="${STATE_FILE}.tmp"
    mkdir -p "$(dirname "$STATE_FILE")"

    {
        echo "{"
        echo "  \"states\": {"
        local first=true
        for var in "${!STATE_@}"; do
            if [[ "$var" != "STATE_FILE" ]]; then
                local target="${var#STATE_}"
                local status="${!var}"
                if [[ "$first" == "true" ]]; then
                    first=false
                else
                    echo ","
                fi
                printf '    "%s": {"status": "%s", "updated": "%s"}' \
                    "$target" "$status" "$(date -Iseconds)"
            fi
        done
        echo ""
        echo "  }"
        echo "}"
    } > "$temp_file"

    mv "$temp_file" "$STATE_FILE"
}

# Check if state has changed and needs notification
# Usage: state_changed "target" "new_status"
# Returns: 0 if changed, 1 if unchanged
state_changed() {
    local target="$1"
    local new_status="$2"
    local var_name="STATE_${target}"
    local old_status="${!var_name:-UNCHECKED}"

    # Alert if status changed from OK to something else, or from WARNING to CRITICAL, etc.
    if [[ "$old_status" != "$new_status" ]]; then
        return 0
    fi
    return 1
}

# Update state for a target
# Usage: update_state "target" "status"
update_state() {
    local target="$1"
    local status="$2"
    declare "STATE_${target}=$status"
}

# ----------------------------------------------------------------------
# Configuration File Parsing
# ----------------------------------------------------------------------

# Parse configuration file and return list of entries
# Usage: parse_config
parse_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        log "ERROR" "Configuration file not found: $config_file"
        return 1
    fi

    if [[ ! -r "$config_file" ]]; then
        log "ERROR" "Configuration file not readable: $config_file"
        return 1
    fi

    # Read lines, skip comments and blank lines
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Trim whitespace
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Skip empty lines
        [[ -z "$line" ]] && continue

        # Skip comment lines
        [[ "$line" == \#* ]] && continue

        # Remove inline comments
        line=$(echo "$line" | sed 's/#.*//')

        # Trim again after inline comment removal
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

        # Skip if nothing left
        [[ -z "$line" ]] && continue

        # Output the entry
        echo "$line"
    done < "$config_file"
}

# ----------------------------------------------------------------------
# Main Monitoring Functions
# ----------------------------------------------------------------------

# Check a single certificate entry
# Usage: check_entry "entry"
check_entry() {
    local entry="$1"
    local cert_json=""

    # Determine if this is a file path or host:port
    if [[ "$entry" == /* ]]; then
        # Local file path
        log "INFO" "Checking local certificate: $entry"
        cert_json=$(check_local_cert "$entry") || {
            log "ERROR" "Failed to check local certificate: $entry"
            return 1
        }
    elif [[ "$entry" == *:* ]]; then
        # host:port format
        local host="${entry%:*}"
        local port="${entry#*:}"
        log "INFO" "Checking remote certificate: ${host}:${port}"
        cert_json=$(check_remote_cert "$host" "$port") || {
            log "ERROR" "Failed to check remote certificate: ${host}:${port}"
            return 1
        }
    else
        log "ERROR" "Invalid entry format: $entry"
        return 1
    fi

    # Parse JSON output
    local cert_type subject issuer sans not_after days_left
    cert_type=$(echo "$cert_json" | sed -n 's/.*"type": *"\([^"]*\)".*/\1/p')
    subject=$(echo "$cert_json" | sed -n 's/.*"subject": *"\([^"]*\)".*/\1/p')
    issuer=$(echo "$cert_json" | sed -n 's/.*"issuer": *"\([^"]*\)".*/\1/p')
    sans=$(echo "$cert_json" | sed -n 's/.*"sans": *"\([^"]*\)".*/\1/p')
    not_after=$(echo "$cert_json" | sed -n 's/.*"not_after": *"\([^"]*\)".*/\1/p')
    days_left=$(echo "$cert_json" | sed -n 's/.*"days_left": *\([0-9-]*\).*/\1/p')

    # Determine status
    local status
    status=$(get_status "$days_left")
    local color
    color=$(get_status_color "$status")
    local emoji
    emoji=$(get_status_emoji "$status")

    # Create target identifier for state tracking
    local target
    if [[ "$cert_type" == "local" ]]; then
        target="file:${entry}"
    else
        target="remote:${host}:${port}"
    fi

    # Display result with colors
    if [[ -t 1 ]]; then
        echo -e "${color}${emoji} ${target}: ${status} (${days_left} days left)${COLOR_RESET}"
        echo -e "   Subject: ${subject}"
        echo -e "   Issuer: ${issuer}"
        echo -e "   Expires: ${not_after}"
        if [[ -n "$sans" ]]; then
            echo -e "   SANs: ${sans}"
        fi
    else
        echo "${emoji} ${target}: ${status} (${days_left} days left)"
        echo "   Subject: ${subject}"
        echo "   Issuer: ${issuer}"
        echo "   Expires: ${not_after}"
        if [[ -n "$sans" ]]; then
            echo "   SANs: ${sans}"
        fi
    fi

    # Check if state changed and needs notification
    if state_changed "$target" "$status"; then
        log "INFO" "State changed for ${target}: ${status}"

        # Send webhook notification
        local event_type
        if [[ "$status" == "OK" ]]; then
            event_type="recovery"
        else
            event_type="alert"
        fi

        local message="${emoji} Certificate ${target} is now ${status} (${days_left} days until expiry)"
        send_webhook "$event_type" "$target" "$message" "$days_left"
    fi

    # Update state
    update_state "$target" "$status"

    return 0
}

# Main monitoring loop
# Usage: run_monitoring
run_monitoring() {
    log "INFO" "=========================================="
    log "INFO" "cert-watcher.sh started"
    log "INFO" "Config: $CONFIG_FILE"
    log "INFO" "Interval: ${CHECK_INTERVAL}s"
    log "INFO" "Warning threshold: ${WARNING_THRESHOLD} days"
    log "INFO" "Critical threshold: ${CRITICAL_THRESHOLD} days"
    log "INFO" "=========================================="

    # Load previous states
    load_states

    # Parse configuration and get all entries
    local entries
    entries=$(parse_config "$CONFIG_FILE") || {
        log "ERROR" "Failed to parse configuration file"
        exit 2
    }

    # Track exit status (0 = all ok, 1 = issues found)
    local overall_status=0
    local checked_count=0
    local problem_count=0

    # Check each entry
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue

        if check_entry "$entry"; then
            ((checked_count++))

            # Check if this entry has a problem status
            local target
            if [[ "$entry" == /* ]]; then
                target="file:${entry}"
            else
                target="remote:${entry}"
            fi

            local var_name="STATE_${target}"
            local status="${!var_name:-OK}"

            if [[ "$status" != "OK" ]]; then
                ((problem_count++))
                overall_status=1
            fi
        else
            ((problem_count++))
            overall_status=1
        fi
    done <<< "$entries"

    # Save states after this check
    save_states

    log "INFO" "Check complete: ${checked_count} certificates checked, ${problem_count} issue(s) found"

    return $overall_status
}

# ----------------------------------------------------------------------
# Single Run Mode
# ----------------------------------------------------------------------

# Run a single check without looping
# Usage: run_single
run_single() {
    log "INFO" "Running single certificate check"

    # Load previous states
    load_states

    # Parse configuration and get all entries
    local entries
    entries=$(parse_config "$CONFIG_FILE") || {
        log "ERROR" "Failed to parse configuration file"
        exit 2
    }

    local overall_status=0
    local checked_count=0
    local problem_count=0

    # Check each entry
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue

        if check_entry "$entry"; then
            ((checked_count++))

            # Check status for this entry
            local target
            if [[ "$entry" == /* ]]; then
                target="file:${entry}"
            else
                target="remote:${entry}"
            fi

            local var_name="STATE_${target}"
            local status="${!var_name:-OK}"

            if [[ "$status" != "OK" ]]; then
                ((problem_count++))
                overall_status=1
            fi
        else
            ((problem_count++))
            overall_status=1
        fi
    done <<< "$entries"

    # Save states after this check
    save_states

    echo ""
    echo "=========================================="
    echo "Check complete: ${checked_count} certificates checked"
    if [[ $problem_count -gt 0 ]]; then
        echo "Issues found: ${problem_count}"
    else
        echo "All certificates OK"
    fi
    echo "=========================================="

    return $overall_status
}

# ----------------------------------------------------------------------
# Continuous Monitoring Mode
# ----------------------------------------------------------------------

# Run continuous monitoring loop
# Usage: run_continuous
run_continuous() {
    log "INFO" "Starting continuous monitoring mode"

    while true; do
        # Run a single check
        run_single
        local result=$?

        # Log the result
        if [[ $result -eq 0 ]]; then
            log "INFO" "All certificates OK"
        else
            log "WARN" "Some certificates have issues"
        fi

        # Wait for next interval
        log "INFO" "Next check in ${CHECK_INTERVAL} seconds..."
        sleep "$CHECK_INTERVAL"
    done
}

# ----------------------------------------------------------------------
# Main Entry Point
# ----------------------------------------------------------------------

main() {
    # Parse command-line arguments
    parse_args "$@"

    # Ensure required directories exist
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$STATE_FILE")"

    # Run continuous monitoring (always loops)
    run_continuous
}

# Run main function with all arguments
main "$@"
