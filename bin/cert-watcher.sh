#!/usr/local/bin/bash
#
# cert-watcher - SSL/TLS 证书过期监控工具
# 作者: Chen Su
# 许可证: MIT
#
# 用法:
#   ./bin/cert-watcher.sh                    # 使用默认配置
#   ./bin/cert-watcher.sh -c config/domains.conf
#   ./bin/cert-watcher.sh -i 3600            # 检测间隔 1 小时
#   ./bin/cert-watcher.sh -w "https://hooks.slack.com/..."
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
DIM='\033[2m'
NC='\033[0m' # No Color

# ============================================================
# 默认配置（可通过环境变量覆盖）
# ============================================================
CONFIG_FILE="${CONFIG_FILE:-./config/domains.conf}"
STATE_DIR="${STATE_DIR:-./state}"
LOG_DIR="${LOG_DIR:-./log}"
LOG_FILE="${LOG_FILE:-${LOG_DIR}/cert-watcher.log}"
INTERVAL="${INTERVAL:-3600}"      # 默认检测间隔: 1小时
TIMEOUT="${TIMEOUT:-10}"          # OpenSSL 连接超时(秒)
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
WARN_DAYS="${WARN_DAYS:-30}"       # 提前多少天开始警告
CRIT_DAYS="${CRIT_DAYS:-7}"        # 提前多少天开始严重警告

# ============================================================
# 全局变量
# ============================================================
declare -A previous_status    # 存储上一次检查状态 (域名 -> 状态)

# ============================================================
# 辅助函数
# ============================================================

# 打印带颜色的消息到终端和日志
log() {
    local level="$1"
    shift
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local msg="[${ts}] [${level}] $*"
    echo -e "$msg" >> "$LOG_FILE"
    case "$level" in
        ERROR)   echo -e "${RED}[$ts] [ERROR]   $*${NC}" ;;
        WARN)    echo -e "${YELLOW}[$ts] [WARN]    $*${NC}" ;;
        INFO)    echo -e "${GREEN}[$ts] [INFO]    $*${NC}" ;;
        CRIT)    echo -e "${RED}${BOLD}[$ts] [CRITICAL] $*${NC}" ;;
        OK)      echo -e "${GREEN}[$ts] [OK]      $*${NC}" ;;
        *)       echo -e "[$ts] [$level] $*" ;;
    esac
}

# 显示帮助信息
show_help() {
    cat << 'EOF'
cert-watcher - SSL/TLS 证书过期监控工具

用法: cert-watcher [选项]

选项:
  -c, --config FILE    域名配置文件路径 (默认: ./config/domains.conf)
  -i, --interval SEC   检测间隔秒数 (默认: 3600 = 1小时)
  -t, --timeout SEC    连接超时秒数 (默认: 10)
  -w, --webhook URL    告警 Webhook URL (支持 Slack)
  -d, --warn-days N    提前警告天数 (默认: 30)
  -D, --crit-days N    严重警告天数 (默认: 7)
  -s, --state-dir DIR  状态存储目录 (默认: ./state)
  -l, --log-dir DIR    日志目录 (默认: ./log)
  -h, --help           显示帮助信息
  -v, --version        显示版本信息

示例:
  cert-watcher -c /etc/cert-watcher/domains.conf -i 1800
  cert-watcher -w "https://hooks.slack.com/services/xxx" -d 14
  WARN_DAYS=14 INTERVAL=1800 ./bin/cert-watcher.sh

配置文件格式 (每行一个域名，# 开头为注释):
  example.com
  api.example.com:8443    # 注释说明
  sub.domain.org

EOF
}

# 显示版本
show_version() {
    echo "cert-watcher v1.0.0"
    echo "SSL/TLS 证书过期监控工具"
}

# 确保必要目录存在
ensure_dirs() {
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$STATE_DIR"
    mkdir -p "$(dirname "$CONFIG_FILE")" 2>/dev/null || true
}

# 读取域名列表
# 返回格式: 空格分隔的 "host:port" 列表
parse_domains() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log ERROR "配置文件不存在: $CONFIG_FILE"
        return 1
    fi

    local result=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        # 去除首尾空白
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        # 跳过注释和空行
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        result+=("$line")
    done < "$CONFIG_FILE"

    printf '%s\n' "${result[@]}"
}

# 获取证书过期时间
# 返回: 距离过期的天数 (负数表示已过期)
get_expiry_days() {
    local host="$1"
    local port="${2:-443}"

    # 使用 OpenSSL 获取证书信息
    # -servername 启用 SNI 支持
    # LibreSSL (macOS) 不支持 -timeout，使用外部 timeout 命令替代
    local expiry_str
    expiry_str=$(
        echo | timeout "$TIMEOUT" openssl s_client -servername "$host" \
            -connect "${host}:${port}" 2>/dev/null | \
            openssl x509 -noout -dates 2>/dev/null | \
            grep notAfter | \
            cut -d= -f2
    ) || return 1

    # 解析日期并计算剩余天数
    # 支持多种日期格式
    local expiry_epoch
    expiry_epoch=$(date -j -f "%b %d %T %Y %Z" "$expiry_str" +%s 2>/dev/null) || \
    expiry_epoch=$(date --date="$expiry_str" +%s 2>/dev/null) || \
    expiry_epoch=$(date -d "$expiry_str" +%s 2>/dev/null) || return 1

    local now_epoch
    now_epoch=$(date +%s)
    local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
    echo "$days_left"
}

# 获取证书主体信息
get_cert_info() {
    local host="$1"
    local port="${2:-443}"

    # 获取 Subject 和Issuer（使用外部 timeout 避免 LibreSSL 无 -timeout 的问题）
    timeout "$TIMEOUT" openssl s_client -servername "$host" \
        -connect "${host}:${port}" 2>/dev/null | \
        openssl x509 -noout -subject -issuer 2>/dev/null | \
        tr '\n' ';' | sed 's/;/\n  /g'
}

# 读取上一次的状态
# 状态文件格式: domain:port -> status,days,check_time
load_state() {
    local state_file="${STATE_DIR}/cert-status"
    if [[ -f "$state_file" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            IFS=':' read -r domain port status days <<< "$line"
            if [[ -n "$domain" ]]; then
                previous_status["${domain}:${port}"]="${status}:${days}"
            fi
        done < "$state_file"
    fi
}

# 保存当前状态
save_state() {
    local state_file="${STATE_DIR}/cert-status"
    {
        echo "# cert-watcher status file - DO NOT EDIT"
        echo "# 格式: domain:port:status:days_remaining"
        echo "# 更新时间: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        for key in "${!cert_status[@]}"; do
            echo "${key}:${cert_status[$key]}"
        done
    } > "${state_file}.tmp"
    mv "${state_file}.tmp" "$state_file"
}

# 发送 Webhook 通知
send_webhook() {
    local color="$1"      # good / warning / danger
    local title="$2"
    local body="$3"
    local footer="${4:-}"

    [[ -z "$NOTIFY_WEBHOOK" ]] && return 0

    local payload
    payload=$(cat << EOF
{
  "attachments": [{
    "color": "${color}",
    "title": "${title}",
    "text": "${body}",
    "footer": "${footer}",
    "ts": $(date +%s)
  }]
}
EOF
)

    curl -s -X POST "$NOTIFY_WEBHOOK" \
        -H 'Content-Type: application/json' \
        -d "$payload" > /dev/null 2>&1 || true
}

# 发送告警通知
send_alert() {
    local domain="$1"
    local port="$2"
    local days="$3"
    local severity="$4"   # info / warn / critical / expired

    local message="🔐 ${domain}:${port} 证书${severity_text[$severity]}"

    case "$severity" in
        expired)  message+=" (已过期 $((- days)) 天) ⚠️" ;;
        critical) message+=" (仅剩 ${days} 天) 🚨" ;;
        warn)     message+=" (还剩 ${days} 天)" ;;
        ok)       message+=" (还有 ${days} 天) ✅" ;;
    esac

    log "${severity_text_log[$severity]}" "$message"

    local color webhook_level
    case "$severity" in
        expired)  color="danger"; webhook_level="🚨 证书已过期" ;;
        critical) color="danger"; webhook_level="🚨 严重警告" ;;
        warn)     color="warning"; webhook_level="⚠️ 即将过期" ;;
        ok)       color="good"; webhook_level="✅ 证书正常" ;;
    esac

    [[ -n "$NOTIFY_WEBHOOK" ]] && send_webhook \
        "$color" \
        "证书监控 - ${domain}:${port}" \
        "$message" \
        "cert-watcher · $(date '+%Y-%m-%d %H:%M')"
}

# 关联数组存放当前检查状态
declare -A cert_status
declare -A cert_info

# 告警级别对应的文字和日志级别
declare -A severity_text=(
    [expired]="已过期"
    [critical]="严重告警"
    [warn]="即将过期"
    [ok]="正常"
)
declare -A severity_text_log=(
    [expired]="CRIT"
    [critical]="CRIT"
    [warn]="WARN"
    [ok]="OK"
)

# ============================================================
# 主检查逻辑
# ============================================================
check_domain() {
    local domain_port="$1"
    local host="${domain_port%%:*}"
    local port="${domain_port#*:}"
    [[ "$port" == "$host" ]] && port="443"

    local days_left cert_subject severity

    # 获取过期天数
    days_left=$(get_expiry_days "$host" "$port") || {
        log ERROR "无法获取 ${host}:${port} 的证书信息"
        cert_status["${host}:${port}"]="ERROR:0"
        return 1
    }

    # 判断告警级别
    if [[ $days_left -lt 0 ]]; then
        severity="expired"
    elif [[ $days_left -le $CRIT_DAYS ]]; then
        severity="critical"
    elif [[ $days_left -le $WARN_DAYS ]]; then
        severity="warn"
    else
        severity="ok"
    fi

    # 存储状态
    cert_status["${host}:${port}"]="${severity}:${days_left}"

    # 获取证书信息
    cert_info["${host}:${port}"]=$(get_cert_info "$host" "$port")

    # 检查状态变化，只在状态变化时告警
    local prev="${previous_status[${host}:${port}]:-}"
    local prev_severity="${prev%%:*}"
    local prev_days="${prev#*:}"

    if [[ -z "$prev" || "$prev_severity" != "$severity" || \
          "$severity" == "critical" || "$severity" == "expired" ]]; then
        send_alert "$host" "$port" "$days_left" "$severity"
    fi
}

# 打印概览表格
print_summary() {
    local total=${#cert_status[@]}
    local expired=0 critical=0 warn=0 ok=0 error=0

    for key in "${!cert_status[@]}"; do
        case "${cert_status[$key]%%:*}" in
            expired) ((expired++)) ;;
            critical) ((critical++)) ;;
            warn) ((warn++)) ;;
            ok) ((ok++)) ;;
            ERROR) ((error++)) ;;
        esac
    done

    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${BOLD}  cert-watcher 证书监控概览${NC}"
    echo -e "${BOLD}========================================${NC}"
    printf "  总计: %s | ${GREEN}正常: %s${NC} | ${YELLOW}警告: %s${NC} | ${RED}严重: %s | 已过期: %s | 错误: %s${NC}\n" \
        "$total" "$ok" "$warn" "$critical" "$expired" "$error"
    echo ""

    # 详细列表
    printf "  %-35s %-10s %s\n" "域名" "剩余天数" "状态"
    printf "  %-35s %-10s %s\n" "------" "--------" "------"
    for key in "${!cert_status[@]}"; do
        local severity="${cert_status[$key]%%:*}"
        local days="${cert_status[$key]#*:}"
        local label
        case "$severity" in
            expired)  label="${RED}已过期${NC}" ;;
            critical) label="${RED}严重${NC}" ;;
            warn)     label="${YELLOW}警告${NC}" ;;
            ok)       label="${GREEN}正常${NC}" ;;
            ERROR)    label="${RED}错误${NC}" ;;
        esac
        printf "  %-35s %-10s %b\n" "$key" "$days" "$label"
    done
    echo ""
}

# ============================================================
# 主入口
# ============================================================
main() {
    # 解析命令行参数
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)       CONFIG_FILE="$2"; shift 2 ;;
            -i|--interval)      INTERVAL="$2"; shift 2 ;;
            -t|--timeout)       TIMEOUT="$2"; shift 2 ;;
            -w|--webhook)       NOTIFY_WEBHOOK="$2"; shift 2 ;;
            -d|--warn-days)     WARN_DAYS="$2"; shift 2 ;;
            -D|--crit-days)     CRIT_DAYS="$2"; shift 2 ;;
            -s|--state-dir)     STATE_DIR="$2"; shift 2 ;;
            -l|--log-dir)       LOG_DIR="$2"; LOG_FILE="${2}/cert-watcher.log"; shift 2 ;;
            -h|--help)          show_help; exit 0 ;;
            -v|--version)       show_version; exit 0 ;;
            *)                  echo "未知选项: $1"; show_help; exit 1 ;;
        esac
    done

    # 确保目录存在
    ensure_dirs

    log INFO "=========================================="
    log INFO "cert-watcher 证书监控启动"
    log INFO "版本: 1.0.0"
    log INFO "配置文件: $CONFIG_FILE"
    log INFO "检测间隔: ${INTERVAL}秒"
    log INFO "超时时间: ${TIMEOUT}秒"
    log INFO "警告阈值: ${WARN_DAYS}天"
    log INFO "严重阈值: ${CRIT_DAYS}天"
    log INFO "=========================================="

    # 加载历史状态
    load_state

    # 主监控循环
    while true; do
        local run_ts
        run_ts=$(date '+%Y-%m-%d %H:%M:%S')
        log INFO "开始检测... ($run_ts)"

        # 解析域名列表
        local domains
        domains=$(parse_domains) || {
            log ERROR "配置解析失败，${INTERVAL}秒后重试"
            sleep "$INTERVAL"
            continue
        }

        local checked=0 failed=0
        while IFS= read -r domain_port; do
            [[ -z "$domain_port" ]] && continue
            if check_domain "$domain_port"; then
                ((checked++))
            else
                ((failed++))
            fi
        done <<< "$domains"

        # 保存状态
        save_state

        # 打印概览
        print_summary

        log INFO "本轮检测完成: 检查 $checked 个域名, 失败 $failed 个"
        log INFO "下次检测: ${INTERVAL}秒后"
        sleep "$INTERVAL"
    done
}

main "$@"
