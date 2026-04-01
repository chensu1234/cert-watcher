#!/bin/bash
#
# cert-watcher - TLS/SSL 证书到期监控工具
# 作者: Chen Su
# 许可证: MIT
#
# 用法: ./bin/cert-watcher.sh [选项]
#   -c, --config FILE    配置文件路径 (默认: ./config/domains.conf)
#   -i, --interval SEC   检测间隔秒数 (默认: 86400，即24小时)
#   -w, --webhook URL    告警 Webhook URL (支持 Slack/钉钉 格式)
#   -d, --days DAYS      提前告警天数 (默认: 30)
#   -p, --port PORT      HTTPS 端口 (默认: 443)
#   -o, --once           单次检测后退出 (不循环)
#   -h, --help           显示帮助信息
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
ALERT_DAYS="${ALERT_DAYS:-30}"
HTTPS_PORT="${HTTPS_PORT:-443}"
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
ONCE_MODE=false

# 程序信息
PROGRAM_NAME="cert-watcher"
PROGRAM_VERSION="1.0.0"

# ============================================================
# 帮助信息
# ============================================================
show_help() {
    cat << EOF
${BOLD}${CYAN}cert-watcher${NC} - TLS/SSL 证书到期监控工具 v${PROGRAM_VERSION}

${BOLD}用法:${NC} $(basename "$0") [选项]

${BOLD}选项:${NC}
    -c, --config FILE    配置文件路径 (默认: ./config/domains.conf)
    -i, --interval SEC   检测间隔秒数 (默认: 86400，即24小时)
    -w, --webhook URL    告警 Webhook URL (支持 Slack 格式)
    -d, --days DAYS      提前告警天数 (默认: 30)
    -p, --port PORT      HTTPS 端口 (默认: 443)
    -o, --once           单次检测后退出 (不循环)
    -v, --version        显示版本信息
    -h, --help           显示帮助信息

${BOLD}示例:${NC}
    $(basename "$0") -c /etc/cert-watcher.conf -d 14
    $(basename "$0") -w "https://hooks.slack.com/services/xxx"
    $(basename "$0") -o  # 单次检测

${BOLD}环境变量:${NC}
    CONFIG_FILE     配置文件路径
    LOG_FILE        日志文件路径
    NOTIFY_WEBHOOK  Webhook URL

EOF
}

# 显示版本
show_version() {
    echo "${PROGRAM_NAME} v${PROGRAM_VERSION}"
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

# 带颜色的日志（仅输出到终端）
log_color() {
    local color="$1"
    shift
    echo -e "${color}$*${NC}"
}

# ============================================================
# 获取证书信息
# ============================================================
get_cert_info() {
    local host="$1"
    local port="$2"
    local timeout="${3:-10}"
    
    # 方法1: 使用 curl 获取证书信息 (支持代理环境)
    local curl_output
    curl_output=$(timeout "$timeout" curl -sI --connect-timeout "$timeout" -k "https://${host}:${port}" 2>/dev/null)
    
    if [[ -n "$curl_output" ]]; then
        # 提取 expire date 字段
        local expiry_date
        expiry_date=$(echo "$curl_output" | grep -i "expire date:" | head -1 | sed 's/.*expire date: *//i' | tr -d '\r')
        
        if [[ -n "$expiry_date" ]]; then
            # 转换为标准格式 "Jun  1 08:36:14 2026 GMT"
            # curl 返回格式: "Fri, 01 May 2026 10:06:31 GMT" 或 "May  1 10:06:31 2026 GMT"
            # 使用 date 命令转换为标准格式
            local formatted_date
            formatted_date=$(date -j -f "%a, %d %b %Y %T %Z" "$expiry_date" "+%b %d %T %Y %Z" 2>/dev/null || \
                             date -d "$expiry_date" "+%b %d %T %Y %Z" 2>/dev/null || \
                             echo "$expiry_date")
            echo "$formatted_date"
            return 0
        fi
    fi
    
    # 方法2: 直接使用 openssl (用于无代理环境)
    local cert_output
    cert_output=$(timeout "$timeout" bash -c "echo 'Q' | openssl s_client -servername '$host' -connect '$host:$port' 2>/dev/null" || echo "")
    
    if [[ -n "$cert_output" ]]; then
        local expiry_date
        expiry_date=$(echo "$cert_output" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        if [[ -n "$expiry_date" ]]; then
            echo "$expiry_date"
            return 0
        fi
    fi
    
    return 1
}

# ============================================================
# 计算证书剩余天数
# ============================================================
days_until_expiry() {
    local expiry_date="$1"
    
    # 解析日期 (格式: "Mar 15 23:59:59 2026 GMT")
    local expiry_epoch
    expiry_epoch=$(date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null || \
                   date -d "$expiry_date" +%s 2>/dev/null || \
                   echo "0")
    
    local now_epoch
    now_epoch=$(date +%s)
    
    local days=$(( (expiry_epoch - now_epoch) / 86400 ))
    echo "$days"
}

# ============================================================
# 格式化剩余时间
# ============================================================
format_remaining() {
    local days="$1"
    
    if [[ "$days" -lt 0 ]]; then
        echo "${RED}已过期 $(printf '%d' $(( -days ))) 天${NC}"
    elif [[ "$days" -eq 0 ]]; then
        echo "${RED}今天过期！${NC}"
    elif [[ "$days" -le 7 ]]; then
        echo "${RED}${days} 天${NC}"
    elif [[ "$days" -le 30 ]]; then
        echo "${YELLOW}${days} 天${NC}"
    else
        echo "${GREEN}${days} 天${NC}"
    fi
}

# ============================================================
# 解析配置文件
# ============================================================
parse_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "配置文件不存在: $CONFIG_FILE"
        return 1
    fi
    
    local domains=()
    while IFS= read -r line; do
        # 跳过注释和空行
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        
        # 去除首尾空白
        line=$(echo "$line" | xargs)
        
        # 解析格式: host[:port][:alert_days]
        if [[ "$line" =~ ^([^:#]+)(:([0-9]+))?(:([0-9]+))?$ ]]; then
            local domain="${BASH_REMATCH[1]}"
            local port="${BASH_REMATCH[3]:-$HTTPS_PORT}"
            local custom_days="${BASH_REMATCH[5]:-$ALERT_DAYS}"
            domains+=("${domain}:${port}:${custom_days}")
        fi
    done < "$CONFIG_FILE"
    
    printf '%s\n' "${domains[@]}"
}

# ============================================================
# 发送告警通知
# ============================================================
send_alert() {
    local domain="$1"
    local port="$2"
    local days="$3"
    local expiry_date="$4"
    
    local emoji alarm_level
    if [[ "$days" -lt 0 ]]; then
        emoji="🚨"
        alarm_level="CRITICAL"
    elif [[ "$days" -eq 0 ]]; then
        emoji="🚨"
        alarm_level="CRITICAL"
    elif [[ "$days" -le 7 ]]; then
        emoji="⚠️"
        alarm_level="WARNING"
    else
        emoji="🔔"
        alarm_level="NOTICE"
    fi
    
    local message="${emoji} *证书告警* [${alarm_level}]
� domain: \`${domain}:${port}\`
⏰ 剩余: *${days} 天*
📅 到期: ${expiry_date}"
    
    log "WARN" "证书告警: ${domain}:${port} 剩余 ${days} 天 (到期: ${expiry_date})"
    
    # 发送到 Webhook
    if [[ -n "$NOTIFY_WEBHOOK" ]]; then
        # 自动检测 Slack 格式
        if [[ "$NOTIFY_WEBHOOK" == *"hooks.slack.com"* ]]; then
            curl -s -X POST "$NOTIFY_WEBHOOK" \
                -H 'Content-Type: application/json' \
                -d "{\"text\": \"$(echo "$message" | tr '\n' ' ')\"}" \
                > /dev/null 2>&1 || log "ERROR" "Webhook 发送失败"
        else
            # 通用格式 (钉钉等)
            curl -s -X POST "$NOTIFY_WEBHOOK" \
                -H 'Content-Type: application/json' \
                -d "{\"msgtype\": \"text\", \"text\": {\"content\": \"$message\"}}" \
                > /dev/null 2>&1 || log "ERROR" "Webhook 发送失败"
        fi
    fi
}

# ============================================================
# 检测单个域名
# ============================================================
check_domain() {
    local domain="$1"
    local port="$2"
    local alert_threshold="$3"
    
    log "INFO" "检测证书: ${domain}:${port}"
    
    local cert_info
    cert_info=$(get_cert_info "$domain" "$port")
    
    if [[ $? -ne 0 ]] || [[ -z "$cert_info" ]]; then
        log "ERROR" "无法获取证书: ${domain}:${port}"
        return 1
    fi
    
    local days
    days=$(days_until_expiry "$cert_info")
    
    # 格式化输出
    local remaining_str
    remaining_str=$(format_remaining "$days")
    
    # 打印结果
    printf "  %-40s %s\n" "${domain}:${port}" "$remaining_str"
    
    # 检查是否需要告警
    if [[ "$days" -le "$alert_threshold" ]]; then
        send_alert "$domain" "$port" "$days" "$cert_info"
        return 1
    fi
    
    return 0
}

# ============================================================
# 主监控循环
# ============================================================
main() {
    # 解析命令行参数
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
            -w|--webhook)
                NOTIFY_WEBHOOK="$2"
                shift 2
                ;;
            -d|--days)
                ALERT_DAYS="$2"
                shift 2
                ;;
            -p|--port)
                HTTPS_PORT="$2"
                shift 2
                ;;
            -o|--once)
                ONCE_MODE=true
                shift
                ;;
            -v|--version)
                show_version
                exit 0
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
    
    log "INFO" "=========================================="
    log "INFO" "cert-watcher v${PROGRAM_VERSION} 启动"
    log "INFO" "配置文件: $CONFIG_FILE"
    log "INFO" "告警阈值: ${ALERT_DAYS} 天"
    log "INFO" "检测间隔: ${INTERVAL} 秒"
    
    # 主循环
    while true; do
        echo ""
        log_color "$BLUE" "=========================================="
        log_color "$BLUE" "证书检测 - $(date '+%Y-%m-%d %H:%M:%S')"
        log_color "$BLUE" "=========================================="
        echo ""
        printf "  %-40s %s\n" "Domain" "剩余时间"
        printf "  %-40s %s\n" "------" "--------"
        
        # 解析域名列表
        local domains
        domains=$(parse_config) || {
            log "ERROR" "配置解析失败"
            sleep "$INTERVAL"
            continue
        }
        
        local has_alert=false
        
        while IFS= read -r item; do
            [[ -z "$item" ]] && continue
            
            IFS=':' read -r domain port alert_days <<< "$item"
            
            if check_domain "$domain" "$port" "$alert_days"; then
                : # 证书正常
            else
                has_alert=true
            fi
        done <<< "$domains"
        
        echo ""
        if [[ "$has_alert" == "true" ]]; then
            log_color "$RED" "⚠️  检测到异常证书，请检查日志"
        else
            log_color "$GREEN" "✓ 所有证书状态正常"
        fi
        
        # 单次模式
        if [[ "$ONCE_MODE" == "true" ]]; then
            log "INFO" "单次检测完成，退出"
            exit 0
        fi
        
        log "INFO" "下次检测: $(date -v+${INTERVAL}S '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
                       date -d "+${INTERVAL} seconds" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "${INTERVAL} 秒后")"
        sleep "$INTERVAL"
    done
}

# 入口
main "$@"
