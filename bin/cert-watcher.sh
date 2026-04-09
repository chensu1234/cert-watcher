#!/bin/bash
#
# cert-watcher - SSL/TLS 证书过期监控工具
# 作者: Chen Su
# 许可证: MIT
#
# 用法:
#   ./bin/cert-watcher.sh -c config/hosts.conf
#   ./bin/cert-watcher.sh -i 3600 -w https://hooks.slack.com/xxx
#   ./bin/cert-watcher.sh --check-once example.com:443
#

set -euo pipefail

# ============================================================
# 颜色输出
# ============================================================
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# 默认配置
# ============================================================
CONFIG_FILE="${CONFIG_FILE:-./config/hosts.conf}"
LOG_FILE="${LOG_FILE:-./log/cert-watcher.log}"
INTERVAL="${INTERVAL:-86400}"       # 默认检测间隔: 24小时
TIMEOUT="${TIMEOUT:-10}"            # 连接超时(秒)
WARN_DAYS="${WARN_DAYS:-30}"        # 首次警告天数
CRIT_DAYS="${CRIT_DAYS:-7}"         # 严重警告天数
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
MODE="${MODE:-daemon}"              # daemon | once
VERBOSE="${VERBOSE:-0}"

# ============================================================
# 帮助信息
# ============================================================
show_help() {
    cat << EOF
cert-watcher - SSL/TLS 证书过期监控工具

用法: $(basename "$0") [选项]

选项:
    -c, --config FILE      配置文件路径 (默认: ./config/hosts.conf)
    -i, --interval SEC     检测间隔秒数 (默认: 86400)
    -t, --timeout SEC      连接超时秒数 (默认: 10)
    -w, --warn DAYS        首次警告天数 (默认: 30)
    -k, --critical DAYS    严重警告天数 (默认: 7)
    -W, --webhook URL      告警 Webhook URL (支持 Slack/钉钉 等)
    -m, --mode MODE        运行模式: daemon|once (默认: daemon)
    -v, --verbose          详细输出
    -h, --help             显示帮助

示例:
    $(basename "$0") -c /etc/cert-watcher/hosts.conf -i 3600
    $(basename "$0") --check-once github.com:443
    $(basename "$0") -W https://hooks.slack.com/services/xxx

配置文件格式 (config/hosts.conf):
    # host:port  # 注释
    example.com:443
    api.example.com:443

EOF
}

# ============================================================
# 日志函数
# ============================================================
log() {
    local level="$1"
    shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

log_debug() {
    [[ "$VERBOSE" == "1" ]] || [[ "$VERBOSE" == "true" ]] && log "DEBUG" "$*"
}

# ============================================================
# 获取证书信息
# 返回: 过期日期 (格式: MMM DD HH:MM:SS YYYY GMT)
# ============================================================
get_cert_expiry() {
    local host="$1"
    local port="$2"

    # openssl s_client 需要 stdin 有数据才能完成握手
    # 注意: openssl -timeout 仅适用于 DTLS，TCP 超时由外部 timeout 命令控制
    # $0 = "_" (填充 bash -c 的 $0)，$1 = host, $2 = port
    local expiry
    expiry=$(timeout "$TIMEOUT" bash -c 'echo "" | openssl s_client -servername "$1" \
        -connect "$1:$2" 2>/dev/null' _ "$host" "$port" \
        | openssl x509 -noout -enddate 2>/dev/null \
        | cut -d= -f2)

    if [[ -z "$expiry" ]]; then
        # 备选: 不带 SNI (某些代理环境会拦截 SNI)
        expiry=$(timeout "$TIMEOUT" bash -c 'echo "" | openssl s_client \
            -connect "$1:$2" 2>/dev/null' _ "$host" "$port" \
            | openssl x509 -noout -enddate 2>/dev/null \
            | cut -d= -f2)
    fi

    echo "$expiry"
}

# ============================================================
# 计算证书剩余天数
# ============================================================
get_days_until_expiry() {
    local expiry_str="$1"
    # 解析日期: Feb 14 23:59:59 2026 GMT
    local expiry_epoch
    expiry_epoch=$(date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_str" +%s 2>/dev/null) || return 1
    local now_epoch
    now_epoch=$(date +%s)
    echo $(( (expiry_epoch - now_epoch) / 86400 ))
}

# ============================================================
# 发送告警通知
# ============================================================
send_notification() {
    local host="$1"
    local port="$2"
    local days_left="$3"
    local level="$4"   # WARN | CRIT | INFO

    local color_hex="36A64F"  # 默认绿色
    case "$level" in
        CRIT)  color_hex="FF0000" ;;
        WARN)  color_hex="FFCC00" ;;
        INFO)  color_hex="36A64F" ;;
    esac

    local message=""
    case "$level" in
        CRIT)  message="🚨 证书即将过期 (严重)！" ;;
        WARN)  message="⚠️  证书即将过期" ;;
        INFO)  message="✅ 证书状态正常" ;;
    esac
    message="${message} ${host}:${port} 剩余 ${days_left} 天"

    log "$level" "$message"

    if [[ -n "$NOTIFY_WEBHOOK" ]]; then
        # Slack 格式
        local payload
        payload=$(cat << EOF
{
  "attachments": [{
    "color": "#${color_hex}",
    "title": "证书监控告警",
    "text": "${message}",
    "footer": "cert-watcher",
    "ts": $(date +%s)
  }]
}
EOF
)
        curl -s -X POST "$NOTIFY_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d "$payload" > /dev/null 2>&1 || true
    fi
}

# ============================================================
# 检测单个主机
# ============================================================
check_host() {
    local host="$1"
    local port="$2"

    log_debug "检测 ${host}:${port} ..."

    local expiry_date
    expiry_date=$(get_cert_expiry "$host" "$port")

    if [[ -z "$expiry_date" ]]; then
        log "ERROR" "无法获取 ${host}:${port} 证书信息"
        return 1
    fi

    log_debug "  过期时间: $expiry_date"

    local days_left
    days_left=$(get_days_until_expiry "$expiry_date")

    if [[ $days_left -le 0 ]]; then
        send_notification "$host" "$port" "$days_left" "CRIT"
    elif [[ $days_left -le "$CRIT_DAYS" ]]; then
        send_notification "$host" "$port" "$days_left" "CRIT"
    elif [[ $days_left -le "$WARN_DAYS" ]]; then
        send_notification "$host" "$port" "$days_left" "WARN"
    else
        log_debug "  ${host}:${port} 剩余 ${days_left} 天 (状态正常)"
    fi

    return 0
}

# ============================================================
# 解析配置文件，返回 host:port 数组
# ============================================================
parse_config() {
    local config="$1"
    if [[ ! -f "$config" ]]; then
        log "ERROR" "配置文件不存在: $config"
        exit 1
    fi

    local hosts=()
    while IFS= read -r line; do
        # 跳过注释和空行
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        # 解析 host:port 格式 (支持 host:port 和 host:port:warning_days)
        if [[ "$line" =~ ^([^:#]+):([0-9]+)(:#.*)?$ ]]; then
            hosts+=("${BASH_REMATCH[1]}:${BASH_REMATCH[2]}")
        fi
    done < "$config"

    printf '%s\n' "${hosts[@]}"
}

# ============================================================
# 单次检测模式
# ============================================================
run_once() {
    log "INFO" "========== 证书检测开始 =========="

    local hosts=()
    if [[ -n "${SINGLE_HOST:-}" ]]; then
        hosts=("$SINGLE_HOST")
    elif [[ -f "$CONFIG_FILE" ]]; then
        while IFS= read -r line; do
            hosts+=("$line")
        done < <(parse_config "$CONFIG_FILE")
    else
        log "ERROR" "未指定检测目标，且配置文件不存在"
        exit 1
    fi

    local total=0 ok=0 warn=0 crit=0 fail=0
    for item in "${hosts[@]}"; do
        [[ -z "$item" ]] && continue
        ((total++))

        local host="${item%:*}"
        local port="${item#*:}"

        if check_host "$host" "$port"; then
            ((ok++))
        else
            ((fail++))
        fi
    done

    log "INFO" "========== 检测完成: $total 主机 | 正常 $ok | 警告 $warn | 严重 $crit | 失败 $fail =========="
}

# ============================================================
# 守护进程模式
# ============================================================
run_daemon() {
    log "INFO" "========== cert-watcher 守护进程启动 =========="
    log "INFO" "配置文件: $CONFIG_FILE"
    log "INFO" "检测间隔: ${INTERVAL}秒"
    log "INFO" "警告阈值: ${WARN_DAYS}天 / ${CRIT_DAYS}天"

    while true; do
        run_once
        sleep "$INTERVAL"
    done
}

# ============================================================
# 解析命令行参数
# ============================================================
main() {
    # 解析参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -i|--interval)
                INTERVAL="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -w|--warn)
                WARN_DAYS="$2"
                shift 2
                ;;
            -k|--critical)
                CRIT_DAYS="$2"
                shift 2
                ;;
            -W|--webhook)
                NOTIFY_WEBHOOK="$2"
                shift 2
                ;;
            -m|--mode)
                MODE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            --check-once)
                MODE="once"
                SINGLE_HOST="$2"
                shift 2
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "未知选项: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # 确保目录存在
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    mkdir -p "$(dirname "$CONFIG_FILE")" 2>/dev/null || true

    case "$MODE" in
        daemon) run_daemon ;;
        once)   run_once ;;
        *)
            echo "未知模式: $MODE"
            exit 1
            ;;
    esac
}

main "$@"
