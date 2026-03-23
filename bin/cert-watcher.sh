#!/bin/bash
#
# cert-watcher - SSL/TLS 证书过期监控工具
# 作者: Chen Su
# 许可证: MIT
#

set -euo pipefail

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 默认配置
CONFIG_FILE="${CONFIG_FILE:-./config/certs.conf}"
LOG_FILE="${LOG_FILE:-./log/cert-watcher.log}"
INTERVAL="${INTERVAL:-86400}"  # 默认每天检查一次
TIMEOUT="${TIMEOUT:-10}"
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
WARNING_DAYS="${WARNING_DAYS:-30}"  # 提前多少天告警
CRITICAL_DAYS="${CRITICAL_DAYS:-7}"  # 紧急告警天数

# 帮助信息
show_help() {
    cat << EOF
cert-watcher - SSL/TLS 证书过期监控工具

用法: $(basename "$0") [选项]

选项:
    -c, --config FILE       配置文件路径 (默认: ./config/certs.conf)
    -i, --interval SEC      检测间隔秒数 (默认: 86400 = 24小时)
    -t, --timeout SEC       连接超时秒数 (默认: 10)
    -w, --webhook URL       告警Webhook URL
    --warning DAYS          警告阈值天数 (默认: 30)
    --critical DAYS         紧急阈值天数 (默认: 7)
    -h, --help              显示帮助信息

示例:
    $(basename "$0") -c /etc/cert-watcher.conf -i 3600
    $(basename "$0") -w https://hooks.slack.com/xxx --warning 14

环境变量:
    CONFIG_FILE      配置文件路径
    LOG_FILE         日志文件路径
    NOTIFY_WEBHOOK   Slack Webhook URL

EOF
}

# 日志函数
log() {
    local level="$1"
    shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo -e "$msg" | tee -a "$LOG_FILE"
}

# 打印带颜色的状态
print_status() {
    local days_left="$1"
    if [[ $days_left -le $CRITICAL_DAYS ]]; then
        echo -e "${RED}CRITICAL${NC} (${days_left}天)"
    elif [[ $days_left -le $WARNING_DAYS ]]; then
        echo -e "${YELLOW}WARNING${NC} (${days_left}天)"
    else
        echo -e "${GREEN}OK${NC} (${days_left}天)"
    fi
}

# 解析配置文件
parse_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "配置文件不存在: $CONFIG_FILE"
        exit 1
    fi
    
    local certs=()
    while IFS= read -r line; do
        # 跳过注释和空行
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue
        
        # 解析 host:port 格式
        if [[ "$line" =~ ^([^:]+):([0-9]+) ]]; then
            certs+=("${BASH_REMATCH[1]}:${BASH_REMATCH[2]}")
        fi
    done < "$CONFIG_FILE"
    
    echo "${certs[@]}"
}

# 获取证书信息并计算剩余天数
get_cert_info() {
    local host="$1"
    local port="$2"
    
    # 使用 openssl 获取证书
    local cert_info
    cert_info=$(echo | openssl s_client -servername "$host" -connect "$host:$port" 2>/dev/null | \
        openssl x509 -noout -dates 2>/dev/null) || return 1
    
    # 提取过期日期
    local not_after
    not_after=$(echo "$cert_info" | grep "notAfter=" | cut -d= -f2)
    
    if [[ -z "$not_after" ]]; then
        return 1
    fi
    
    # 转换日期为时间戳
    local expire_timestamp
    expire_timestamp=$(date -j -f "%b %d %H:%M:%S %Y" "$not_after" "+%s" 2>/dev/null) || return 1
    
    # 计算剩余天数
    local now_timestamp
    now_timestamp=$(date "+%s")
    
    local days_left=$(( (expire_timestamp - now_timestamp) / 86400 ))
    echo "$days_left"
}

# 发送通知
send_notification() {
    local host="$1"
    local port="$2"
    local days_left="$3"
    local status="$4"
    
    local color
    if [[ "$status" == "CRITICAL" ]]; then
        color="danger"
    elif [[ "$status" == "WARNING" ]]; then
        color="warning"
    else
        color="good"
    fi
    
    local message="证书告警: ${host}:${port} 剩余 ${days_left} 天，状态: ${status}"
    
    log "WARN" "$message"
    
    # Slack Webhook 通知
    if [[ -n "$NOTIFY_WEBHOOK" ]]; then
        curl -s -X POST "$NOTIFY_WEBHOOK" \
            -H 'Content-Type: application/json' \
            -d "{
                \"attachments\": [{
                    \"color\": \"$color\",
                    \"title\": \"证书告警\",
                    \"text\": \"$message\",
                    \"fields\": [
                        {\"title\": \"主机\", \"value\": \"$host\", \"short\": true},
                        {\"title\": \"端口\", \"value\": \"$port\", \"short\": true},
                        {\"title\": \"剩余天数\", \"value\": \"$days_left\", \"short\": true},
                        {\"title\": \"状态\", \"value\": \"$status\", \"short\": true}
                    ]
                }]
            }" \
            > /dev/null 2>&1 || true
    fi
}

# 检查单个证书
check_cert() {
    local host="$1"
    local port="$2"
    
    log "INFO" "检查证书: ${host}:${port}"
    
    local days_left
    days_left=$(get_cert_info "$host" "$port") || {
        log "ERROR" "获取证书失败: ${host}:${port}"
        return 1
    }
    
    local status
    if [[ $days_left -le $CRITICAL_DAYS ]]; then
        status="CRITICAL"
    elif [[ $days_left -le $WARNING_DAYS ]]; then
        status="WARNING"
    else
        status="OK"
    fi
    
    # 打印状态
    printf "  %-30s " "${host}:${port}"
    print_status "$days_left"
    
    # 状态变化通知
    local cache_key="${host}:${port}"
    local prev_status="${cert_status[$cache_key]:-UNKNOWN}"
    
    if [[ "$status" != "$prev_status" ]]; then
        if [[ "$prev_status" != "UNKNOWN" ]]; then
            send_notification "$host" "$port" "$days_left" "$status"
        fi
        cert_status[$cache_key]="$status"
    fi
    
    return 0
}

# 主监控循环
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
            -w|--webhook)
                NOTIFY_WEBHOOK="$2"
                shift 2
                ;;
            --warning)
                WARNING_DAYS="$2"
                shift 2
                ;;
            --critical)
                CRITICAL_DAYS="$2"
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
    mkdir -p "$(dirname "$LOG_FILE")"
    mkdir -p "$(dirname "$CONFIG_FILE")"
    
    log "INFO" "========== SSL证书监控启动 =========="
    log "INFO" "配置文件: $CONFIG_FILE"
    log "INFO" "检测间隔: ${INTERVAL}秒 ($(($INTERVAL / 3600))小时)"
    log "INFO" "超时时间: ${TIMEOUT}秒"
    log "INFO" "警告阈值: ${WARNING_DAYS}天"
    log "INFO" "紧急阈值: ${CRITICAL_DAYS}天"
    
    # 证书状态缓存
    declare -A cert_status
    
    while true; do
        # 解析证书列表
        IFS=' ' read -ra CERTS <<< "$(parse_config)"
        
        echo ""
        log "INFO" "========== 开始检查 =========="
        
        for item in "${CERTS[@]}"; do
            [[ -z "$item" ]] && continue
            
            host="${item%:*}"
            port="${item#*:}"
            
            check_cert "$host" "$port"
        done
        
        log "INFO" "========== 检查完成 =========="
        
        sleep "$INTERVAL"
    done
}

main "$@"
