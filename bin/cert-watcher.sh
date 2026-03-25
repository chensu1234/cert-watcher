#!/bin/bash
#
# cert-watcher - SSL/TLS 证书过期监控工具
# 作者: Chen Su
# 许可证: MIT
#
# 兼容性: Bash 3.2+ (macOS/Linux)
#

set -euo pipefail

# ============================================================
# 颜色定义
# ============================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ============================================================
# 默认配置
# ============================================================
CONFIG_FILE="${CONFIG_FILE:-./config/domains.conf}"
LOG_FILE="${LOG_FILE:-./log/cert-watcher.log}"
INTERVAL="${INTERVAL:-86400}"
WARNING_DAYS="${WARNING_DAYS:-30}"
CRITICAL_DAYS="${CRITICAL_DAYS:-7}"
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
MODE="${MODE:-daemon}"

# ============================================================
# 帮助信息
# ============================================================
show_help() {
    cat << EOF
${BOLD}cert-watcher${NC} - SSL/TLS 证书过期监控工具

${BOLD}用法:${NC}
    $(basename "$0") [选项]

${BOLD}选项:${NC}
    -c, --config FILE      配置文件路径 (默认: ./config/domains.conf)
    -i, --interval SEC     检测间隔秒数 (默认: 86400)
    -d, --days N           提前告警天数 (默认: 30)
    -D, --critical N       严重告警天数 (默认: 7)
    -w, --webhook URL      Slack Webhook URL
    -r, --report           生成报告模式 (单次执行)
    -h, --help             显示帮助信息
    -v, --version          显示版本信息

${BOLD}示例:${NC}
    $(basename "$0") -c /etc/cert-watcher.conf -i 3600
    $(basename "$0") -w https://hooks.slack.com/services/xxx -d 14
    $(basename "$0") --report

EOF
}

show_version() {
    echo "cert-watcher v1.0.0"
}

# ============================================================
# 日志函数
# ============================================================
log() {
    local level="$1"
    shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo -e "$msg" | tee -a "$LOG_FILE" 2>/dev/null || echo "$msg"
}

print_banner() {
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}      cert-watcher v1.0.0${NC}"
    echo -e "${CYAN}   SSL/TLS 证书过期监控工具${NC}"
    echo -e "${CYAN}========================================${NC}"
    echo
}

# ============================================================
# 兼容 date 命令 (macOS vs Linux)
# ============================================================
parse_expiry_epoch() {
    local date_str="$1"
    # Linux (GNU)
    if date -d "$date_str" +%s >/dev/null 2>&1; then
        date -d "$date_str" +%s
    else
        # macOS (BSD) - 使用 perl 来解析
        perl -MTime::Piece -le "
            my \$t = Time::Piece->strptime('$date_str', '%b %d %H:%M:%S %Y');
            print \$t->epoch;
        " 2>/dev/null
    fi
}

format_epoch() {
    local epoch="$1"
    if date -d "@$epoch" +%Y-%m-%d >/dev/null 2>&1; then
        date -d "@$epoch" "+%Y-%m-%d %H:%M:%S"
    else
        perl -le "print scalar(localtime($epoch));" 2>/dev/null
    fi
}

# ============================================================
# 解析配置文件
# ============================================================
parse_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "配置文件不存在: $CONFIG_FILE"
        exit 1
    fi

    local domains=()
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        if [[ "$line" =~ ^([^:#]+)(:[0-9]+)? ]]; then
            local host="${BASH_REMATCH[1]}"
            local port="${BASH_REMATCH[2]:-':443'}"
            port="${port#:}"
            domains+=("$host:$port")
        fi
    done < "$CONFIG_FILE"

    printf '%s\n' "${domains[@]}"
}

# ============================================================
# 获取证书信息
# ============================================================
get_cert_info() {
    local host="$1"
    local port="$2"

    local cert_info
    cert_info=$(<<< "" timeout 15 openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null | \
                 openssl x509 -noout -dates -issuer 2>&1) || return 1

    local not_after
    not_after=$(echo "$cert_info" | grep "notAfter=" | cut -d'=' -f2)
    [[ -z "$not_after" ]] && return 1

    local issuer
    issuer=$(echo "$cert_info" | grep "issuer=" | cut -d'=' -f2- | sed 's/^ *//')

    local expiry_epoch valid_days
    expiry_epoch=$(parse_expiry_epoch "$not_after") || return 1

    local now_epoch
    now_epoch=$(date +%s)
    valid_days=$(( (expiry_epoch - now_epoch) / 86400 ))

    echo "${expiry_epoch}|${issuer}|${valid_days}"
}

# ============================================================
# 获取证书 CN
# ============================================================
get_cert_cn() {
    local host="$1"
    local port="$2"

    <<< "" timeout 15 openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null | \
           openssl x509 -noout -subject 2>/dev/null | \
           sed 's/.*CN\s*=\s*\([^,]*\).*/\1/' | sed 's/^ *//'
}

# ============================================================
# 状态判断
# ============================================================
get_status_color() {
    local days="$1"
    if [[ $days -le CRITICAL_DAYS ]]; then
        echo "$RED"
    elif [[ $days -le WARNING_DAYS ]]; then
        echo "$YELLOW"
    else
        echo "$GREEN"
    fi
}

get_status_label() {
    local days="$1"
    if [[ $days -le CRITICAL_DAYS ]]; then
        echo "🔴 CRITICAL"
    elif [[ $days -le WARNING_DAYS ]]; then
        echo "🟡 WARNING"
    else
        echo "🟢 OK"
    fi
}

# ============================================================
# 发送 Slack 通知
# ============================================================
send_slack_notification() {
    local hostname="$1" port="$2" days="$3" expiry_date="$4" status="$5" cert_cn="$6"

    [[ -z "$NOTIFY_WEBHOOK" ]] && return

    local color
    case "$status" in
        CRITICAL) color="#FF0000" ;;
        WARNING)  color="#FFA500" ;;
        OK)       color="#36A64F" ;;
    esac

    local payload="{\"attachments\":[{\"color\":\"$color\",\"title\":\"证书告警: $hostname:$port\",\"fields\":[{\"title\":\"域名\",\"value\":\"$cert_cn\",\"short\":true},{\"title\":\"剩余天数\",\"value\":\"$days 天\",\"short\":true},{\"title\":\"过期时间\",\"value\":\"$expiry_date\",\"short\":true},{\"title\":\"状态\",\"value\":\"$status\",\"short\":true}],\"footer\":\"cert-watcher\",\"ts\":$(date +%s)}]}"

    curl -s -X POST "$NOTIFY_WEBHOOK" \
        -H 'Content-Type: application/json' \
        -d "$payload" > /dev/null 2>&1 || true
}

# ============================================================
# 发送 Telegram 通知
# ============================================================
send_telegram_notification() {
    local hostname="$1" port="$2" days="$3" expiry_date="$4" status="$5" cert_cn="$6"

    [[ -z "${TELEGRAM_BOT_TOKEN:-}" ]] && [[ -z "${TELEGRAM_CHAT_ID:-}" ]] && return

    local emoji
    case "$status" in
        CRITICAL) emoji="🔴" ;;
        WARNING)  emoji="🟡" ;;
        OK)       emoji="🟢" ;;
    esac

    local message="${emoji} *证书告警*

*域名:* \`$hostname:$port\`
*证书:* \`$cert_cn\`
*剩余:* \`${days} 天\`
*过期:* \`$expiry_date\`
*状态:* \`$status\`"

    curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d "chat_id=${TELEGRAM_CHAT_ID}&text=${message}&parse_mode=Markdown" > /dev/null 2>&1 || true
}

# ============================================================
# 检查单个证书
# ============================================================
check_cert() {
    local host="$1"
    local port="$2"

    log "INFO" "检查证书: $host:$port"

    local cert_info
    cert_info=$(get_cert_info "$host" "$port") || {
        log "ERROR" "无法获取证书: $host:$port"
        return 1
    }

    local expiry_epoch issuer valid_days
    IFS='|' read -r expiry_epoch issuer valid_days <<< "$cert_info"

    local cert_cn
    cert_cn=$(get_cert_cn "$host" "$port") || cert_cn="$host"

    local expiry_date
    expiry_date=$(format_epoch "$expiry_epoch")

    local status_label status_color
    status_label=$(get_status_label "$valid_days")
    status_color=$(get_status_color "$valid_days")

    echo -e "  ${status_color}${status_label}${NC}  $host:$port"
    echo -e "         证书: $cert_cn"
    echo -e "         颁发者: $issuer"
    echo -e "         过期: $expiry_date"
    echo -e "         剩余: ${valid_days} 天"
    echo

    if [[ $valid_days -le WARNING_DAYS ]]; then
        local st
        [[ $valid_days -le CRITICAL_DAYS ]] && st="CRITICAL" || st="WARNING"
        send_slack_notification "$host" "$port" "$valid_days" "$expiry_date" "$st" "$cert_cn"
        send_telegram_notification "$host" "$port" "$valid_days" "$expiry_date" "$st" "$cert_cn"
    fi

    if [[ $valid_days -le CRITICAL_DAYS ]]; then
        log "WARN" "证书即将过期: $host:$port (剩余 ${valid_days} 天)"
    elif [[ $valid_days -le WARNING_DAYS ]]; then
        log "WARN" "证书即将过期: $host:$port (剩余 ${valid_days} 天)"
    fi
}

# ============================================================
# 生成报告
# ============================================================
generate_report() {
    local output_file="${1:-}"

    echo "========================================"
    echo "      SSL 证书过期监控报告"
    echo "      生成时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "========================================"
    echo

    local total=0 critical=0 warning=0 ok=0

    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        total=$((total + 1))

        host="${item%:*}"
        port="${item#*:}"

        local cert_info
        cert_info=$(get_cert_info "$host" "$port") || {
            echo -e "${RED}✗${NC}  $host:$port - 无法获取证书"
            continue
        }

        local expiry_epoch issuer valid_days
        IFS='|' read -r expiry_epoch issuer valid_days <<< "$cert_info"

        local cert_cn
        cert_cn=$(get_cert_cn "$host" "$port") || cert_cn="$host"

        local expiry_date
        expiry_date=$(format_epoch "$expiry_epoch")

        local status_label status_color
        status_label=$(get_status_label "$valid_days")
        status_color=$(get_status_color "$valid_days")

        case "$status_label" in
            *CRITICAL*) critical=$((critical + 1)) ;;
            *WARNING*)  warning=$((warning + 1)) ;;
            *OK*)       ok=$((ok + 1)) ;;
        esac

        echo -e "${status_color}${status_label}${NC}  $host:$port"
        echo -e "         $cert_cn"
        echo -e "         剩余: ${valid_days} 天 | 过期: $expiry_date"
        echo
    done < <(parse_config)

    echo "========================================"
    echo -e "${BOLD}统计摘要${NC}"
    echo "========================================"
    echo -e "总计: $total  | ${RED}严重: $critical${NC} | ${YELLOW}警告: $warning${NC} | ${GREEN}正常: $ok${NC}"
    echo

    if [[ -n "$output_file" ]]; then
        {
            echo "SSL Certificate Expiry Report"
            echo "Generated: $(date)"
            echo "Total: $total | Critical: $critical | Warning: $warning | OK: $ok"
        } > "$output_file"
        log "INFO" "报告已保存: $output_file"
    fi
}

# ============================================================
# 主函数
# ============================================================
main() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)    CONFIG_FILE="$2"; shift 2 ;;
            -i|--interval)  INTERVAL="$2"; shift 2 ;;
            -d|--days)       WARNING_DAYS="$2"; shift 2 ;;
            -D|--critical)   CRITICAL_DAYS="$2"; shift 2 ;;
            -w|--webhook)    NOTIFY_WEBHOOK="$2"; shift 2 ;;
            -r|--report)    MODE="report"; shift ;;
            -h|--help)      show_help; exit 0 ;;
            -v|--version)   show_version; exit 0 ;;
            *)              echo -e "${RED}未知选项: $1${NC}"; show_help; exit 1 ;;
        esac
    done

    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    mkdir -p "$(dirname "$CONFIG_FILE")" 2>/dev/null || true

    print_banner

    if [[ "$MODE" == "report" ]]; then
        generate_report
    else
        log "INFO" "========== cert-watcher 启动 =========="
        log "INFO" "配置文件: $CONFIG_FILE"
        log "INFO" "检测间隔: ${INTERVAL}秒"
        log "INFO" "告警阈值: ${WARNING_DAYS}天"
        log "INFO" "严重阈值: ${CRITICAL_DAYS}天"

        while true; do
            echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} 开始检测证书..."
            echo

            while IFS= read -r item; do
                [[ -z "$item" ]] && continue
                host="${item%:*}"
                port="${item#*:}"
                check_cert "$host" "$port"
            done < <(parse_config)

            echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} 本轮检测完成"
            log "INFO" "本轮检测完成，下次检测于 ${INTERVAL} 秒后"

            sleep "$INTERVAL"
        done
    fi
}

main "$@"
