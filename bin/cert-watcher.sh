#!/usr/bin/env bash
#
# cert-watcher - SSL/TLS 证书过期监控工具
# 作者: Chen Su
# 许可证: MIT
#
# 用法:
#   ./bin/cert-watcher.sh [选项]
#   ./bin/cert-watcher.sh -c config/certs.conf -w 7,3,1
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
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# ============================================================
# 默认配置
# ============================================================
CONFIG_FILE="${CONFIG_FILE:-./config/certs.conf}"
LOG_FILE="${LOG_FILE:-./log/cert-watcher.log}"
INTERVAL="${INTERVAL:-86400}"          # 默认 24 小时
WARN_DAYS="${WARN_DAYS:-7,3,1}"        # 默认提前 7/3/1 天告警
NOTIFY_WEBHOOK="${NOTIFY_WEBHOOK:-}"
JSON_OUTPUT=false
CHECK_ONCE=false
QUIET_MODE=false

# ============================================================
# 全局变量
# ============================================================
declare -A cert_status       # 缓存证书状态: key=host:port, value=剩余天数
declare -A last_alert_days   # 避免重复告警: key=host:port, value=上次告警天数

# ============================================================
# 帮助信息
# ============================================================
show_help() {
    cat << EOF
${BOLD}cert-watcher${NC} - SSL/TLS 证书过期监控工具

${BOLD}用法:${NC}
    $(basename "$0") [选项]

${BOLD}选项:${NC}
    -c, --config FILE    配置文件路径 (默认: ./config/certs.conf)
    -i, --interval SEC   检测间隔秒数 (默认: 86400，即 24 小时)
    -w, --warn DAYS      告警阈值天数，逗号分隔 (默认: 7,3,1)
    -W, --webhook URL    Slack Webhook URL
    -j, --json           输出 JSON 格式报告
    -o, --once           单次检查（不守护运行）
    -q, --quiet          静默模式（仅告警）
    -h, --help           显示帮助信息

${BOLD}示例:${NC}
    $(basename "$0") -c /etc/cert-watcher.conf -i 3600
    $(basename "$0") -w 30,14,7,3 -W https://hooks.slack.com/xxx
    $(basename "$0") --check-once --json

${BOLD}配置文件格式:${NC}
    # host:port [warning_days...]
    google.com:443
    github.com:443
    localhost:8443 30,14,7,3

EOF
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

# 静默日志（不输出到终端）
log_quiet() {
    local level="$1"
    shift
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*"
    echo -e "$msg" >> "$LOG_FILE" 2>/dev/null || echo "$msg"
}

# ============================================================
# 解析告警阈值天数数组
# ============================================================
parse_warn_days() {
    local input="$1"
    # 将 "7,3,1" 转换为数组并排序（从大到小）
    local IFS=','
    read -ra DAYS <<< "$input"
    # 冒泡排序：从大到小
    for ((i=0; i<${#DAYS[@]}-1; i++)); do
        for ((j=0; j<${#DAYS[@]}-i-1; j++)); do
            if (( DAYS[j] < DAYS[j+1] )); then
                tmp="${DAYS[j]}"
                DAYS[j]="${DAYS[j+1]}"
                DAYS[j+1]="$tmp"
            fi
        done
    done
    echo "${DAYS[@]}"
}

# ============================================================
# 获取证书信息 (使用 OpenSSL s_client)
# ============================================================
get_cert_info() {
    local host="$1"
    local port="$2"
    local timeout="${3:-5}"

    # 使用 OpenSSL 获取证书信息
    # -servername 用于 SNI (Server Name Indication)
    # -partial_chain 允许部分证书链验证
    local cert_info
    cert_info=$(echo | timeout "$timeout" openssl s_client -servername "$host" -connect "${host}:${port}" 2>/dev/null | \
                 openssl x509 -noout -text -issuer -subject -dates -fingerprint -serial 2>/dev/null) || return 1

    echo "$cert_info"
}

# ============================================================
# 解析证书日期
# ============================================================
parse_cert_date() {
    local cert_info="$1"
    local date_str

    # 提取 notAfter 日期
    date_str=$(echo "$cert_info" | grep "Not After:" | sed 's/.*Not After: *//')

    # 尝试多种日期格式解析
    # 格式: "Mar 15 23:59:59 2026 GMT"
    if [[ -n "$date_str" ]]; then
        # 转换为时间戳
        date -j -f "%b %d %H:%M:%S %Y %Z" "$date_str" +%s 2>/dev/null || \
        date --date="$date_str" +%s 2>/dev/null || return 1
    else
        return 1
    fi
}

# ============================================================
# 计算剩余天数
# ============================================================
get_days_remaining() {
    local expiry_ts="$1"
    local now_ts
    now_ts=$(date +%s)
    echo $(( (expiry_ts - now_ts) / 86400 ))
}

# ============================================================
# 提取证书各字段信息
# ============================================================
extract_cert_field() {
    local cert_info="$1"
    local field="$2"

    case "$field" in
        subject)
            echo "$cert_info" | grep "Subject:" | sed 's/.*Subject: *//'
            ;;
        issuer)
            echo "$cert_info" | grep "Issuer:" | sed 's/.*Issuer: *//'
            ;;
        not_before)
            echo "$cert_info" | grep "Not Before:" | sed 's/.*Not Before: *//'
            ;;
        not_after)
            echo "$cert_info" | grep "Not After:" | sed 's/.*Not After: *//'
            ;;
        fingerprint)
            echo "$cert_info" | grep "SHA256 Fingerprint" | sed 's/.*SHA256 Fingerprint= *//'
            ;;
        serial)
            echo "$cert_info" | grep "Serial Number:" | sed 's/.*Serial Number: *//'
            ;;
        *)
            echo "Unknown field: $field"
            ;;
    esac
}

# ============================================================
# 发送 Slack 通知
# ============================================================
send_slack_notification() {
    local host="$1"
    local port="$2"
    local days="$3"
    local expiry_date="$4"
    local subject="$5"
    local alert_level="$6"  # CRITICAL, WARNING, INFO

    if [[ -z "$NOTIFY_WEBHOOK" ]]; then
        return 0
    fi

    # 根据告警级别选择颜色和 emoji
    local color emoji
    case "$alert_level" in
        CRITICAL)
            color="#FF0000"
            emoji="🚨"
            ;;
        WARNING)
            color="#FFA500"
            emoji="⚠️"
            ;;
        *)
            color="#36A64F"
            emoji="✅"
            ;;
    esac

    # 构建 Slack 消息
    local payload
    payload=$(cat << EOF
{
    "attachments": [
        {
            "color": "$color",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "${emoji} *[\${alert_level}] 证书告警 - cert-watcher*"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": "*🌐 主机:*\n\`${host}:${port}\`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*📅 剩余天数:*\n\`${days} 天\`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*📆 到期时间:*\n\`${expiry_date}\`"
                        },
                        {
                            "type": "mrkdwn",
                            "text": "*👤 证书主题:*\n\`${subject}\`"
                        }
                    ]
                }
            ]
        }
    ]
}
EOF
)

    # 发送请求（静默失败）
    curl -s -X POST "$NOTIFY_WEBHOOK" \
        -H 'Content-Type: application/json' \
        -d "$payload" > /dev/null 2>&1 || true
}

# ============================================================
# 检查单个证书
# ============================================================
check_cert() {
    local host="$1"
    local port="$2"
    local warn_days_arr=("$@")
    local warn_days_str="${*: -1}"  # 最后一个参数是 warn_days 字符串

    # 获取证书信息
    local cert_info
    cert_info=$(get_cert_info "$host" "$port" 5) || {
        log_quiet "ERROR" "无法获取 ${host}:${port} 的证书信息"
        if [[ "$JSON_OUTPUT" == "true" ]]; then
            jq -n \
                --arg h "$host" --arg p "$port" \
                --arg e "无法获取证书信息" \
                '{host: $h, port: $p, error: $e, ok: false}'
        fi
        return 1
    }

    # 解析到期时间
    local expiry_ts
    expiry_ts=$(parse_cert_date "$cert_info") || {
        log_quiet "ERROR" "无法解析 ${host}:${port} 的证书日期"
        return 1
    }

    # 计算剩余天数
    local days_remaining
    days_remaining=$(get_days_remaining "$expiry_ts")

    # 提取证书详情
    local subject issuer not_before not_after fingerprint serial
    subject=$(extract_cert_field "$cert_info" "subject")
    issuer=$(extract_cert_field "$cert_info" "issuer")
    not_before=$(extract_cert_field "$cert_info" "not_before")
    not_after=$(extract_cert_field "$cert_info" "not_after")
    fingerprint=$(extract_cert_field "$cert_info" "fingerprint")
    serial=$(extract_cert_field "$cert_info" "serial")

    # 格式化输出
    local status_color status_text
    if (( days_remaining < 0 )); then
        status_color="$RED"
        status_text="已过期 $(( -days_remaining )) 天"
    elif (( days_remaining <= warn_days_arr[0] )); then
        status_color="$RED"
        status_text="紧急 (${days_remaining} 天)"
    elif (( days_remaining <= warn_days_arr[1] )); then
        status_color="$YELLOW"
        status_text="警告 (${days_remaining} 天)"
    elif (( days_remaining <= warn_days_arr[2] )); then
        status_color="$CYAN"
        status_text="注意 (${days_remaining} 天)"
    else
        status_color="$GREEN"
        status_text="正常 (${days_remaining} 天)"
    fi

    # 根据告警级别发送通知
    local alert_level=""
    if (( days_remaining <= 0 )); then
        alert_level="CRITICAL"
    elif (( days_remaining <= warn_days_arr[2] )); then
        alert_level="WARNING"
    fi

    # 避免重复告警（同一天不重复发送）
    local cache_key="${host}:${port}"
    local last_alert="${last_alert_days[$cache_key]:-999}"
    if [[ -n "$alert_level" ]] && (( last_alert != days_remaining )); then
        send_slack_notification "$host" "$port" "$days_remaining" "$not_after" "$subject" "$alert_level"
        last_alert_days[$cache_key]="$days_remaining"
        log "WARN" "告警: ${host}:${port} 剩余 ${days_remaining} 天 (${alert_level})"
    fi

    # 更新状态缓存
    cert_status[$cache_key]="$days_remaining"

    # 输出
    if [[ "$JSON_OUTPUT" == "true" ]]; then
        jq -n \
            --arg h "$host" \
            --arg p "$port" \
            --arg s "$subject" \
            --arg i "$issuer" \
            --arg nb "$not_before" \
            --arg na "$not_after" \
            --arg fp "$fingerprint" \
            --arg sn "$serial" \
            --argjson d "$days_remaining" \
            --argjson ok true \
            '{
                host: $h,
                port: ($p | tonumber),
                subject: $s,
                issuer: $i,
                notBefore: $nb,
                notAfter: $na,
                fingerprint: $fp,
                serialNumber: $sn,
                daysRemaining: $d,
                ok: $ok
            }'
    else
        if [[ "$QUIET_MODE" != "true" ]]; then
            echo -e "${status_color}[${status_text}]${NC} ${BOLD}${host}:${port}${NC}"
            echo -e "  ${DIM}Subject:${NC}   $subject"
            echo -e "  ${DIM}Issuer:${NC}    $issuer"
            echo -e "  ${DIM}Valid:${NC}     $not_before ~ $not_after"
            echo -e "  ${DIM}Fingerprint:${NC} $fingerprint"
        fi
    fi

    return 0
}

# ============================================================
# 解析配置文件
# ============================================================
parse_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "配置文件不存在: $CONFIG_FILE"
        exit 1
    fi

    local entries=()
    while IFS= read -r line; do
        # 跳过注释和空行
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$line" ]] && continue

        entries+=("$line")
    done < "$CONFIG_FILE"

    echo "${entries[@]}"
}

# ============================================================
# 打印汇总报告
# ============================================================
print_summary() {
    local total=${#cert_status[@]}
    local expired=0
    local critical=0
    local warning=0
    local ok=0

    for key in "${!cert_status[@]}"; do
        local days=${cert_status[$key]}
        if (( days < 0 )); then
            (( expired++ ))
        elif (( days <= 7 )); then
            (( critical++ ))
        elif (( days <= 30 )); then
            (( warning++ ))
        else
            (( ok++ ))
        fi
    done

    echo ""
    echo -e "${BOLD}========== 汇总报告 ==========${NC}"
    echo -e "总计: $total  |  ${GREEN}正常: $ok${NC}  |  ${CYAN}注意: $warning${NC}  |  ${RED}紧急: $critical${NC}  |  ${RED}过期: $expired${NC}"
    echo ""
}

# ============================================================
# 主程序
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
            -w|--warn)
                WARN_DAYS="$2"
                shift 2
                ;;
            -W|--webhook)
                NOTIFY_WEBHOOK="$2"
                shift 2
                ;;
            -j|--json)
                JSON_OUTPUT=true
                shift
                ;;
            -o|--once|--check-once)
                CHECK_ONCE=true
                shift
                ;;
            -q|--quiet)
                QUIET_MODE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}未知选项: $1${NC}"
                show_help
                exit 1
                ;;
        esac
    done

    # 确保目录存在
    mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
    mkdir -p "$(dirname "$CONFIG_FILE")" 2>/dev/null || true

    # 解析告警阈值
    local -a WARN_DAYS_ARR
    read -ra WARN_DAYS_ARR <<< "$(parse_warn_days "$WARN_DAYS")"

    # 日志启动
    log "INFO" "========== cert-watcher 启动 =========="
    log "INFO" "配置文件: $CONFIG_FILE"
    log "INFO" "检测间隔: ${INTERVAL}秒 ($(($INTERVAL / 3600)) 小时)"
    log "INFO" "告警阈值: ${WARN_DAYS_ARR[*]} 天"

    # 主循环
    while true; do
        # 解析配置
        local config_entries
        config_entries=$(parse_config)

        if [[ -z "$config_entries" ]]; then
            log "WARN" "配置为空或无效: $CONFIG_FILE"
        else
            # 转换为数组（处理多行配置）
            local IFS=' '
            read -ra ENTRIES <<< "$config_entries"

            local -a cert_tasks=()

            for entry in "${ENTRIES[@]}"; do
                [[ -z "$entry" ]] && continue

                # 解析 host:port [warn_days...]
                local host port custom_warn
                if [[ "$entry" =~ ^([^:]+):([0-9]+)[\ ]*(.*) ]]; then
                    host="${BASH_REMATCH[1]}"
                    port="${BASH_REMATCH[2]}"
                    custom_warn="${BASH_REMATCH[3]}"
                else
                    log "WARN" "无效配置行: $entry"
                    continue
                fi

                # 如果有自定义告警阈值，使用它；否则使用默认
                if [[ -n "$custom_warn" ]]; then
                    local -a custom_arr
                    read -ra custom_arr <<< "$(parse_warn_days "$custom_warn")"
                    check_cert "$host" "$port" "${custom_arr[@]}"
                else
                    check_cert "$host" "$port" "${WARN_DAYS_ARR[@]}"
                fi
            done

            # 输出汇总（非 JSON 模式）
            if [[ "$JSON_OUTPUT" != "true" ]]; then
                print_summary
            fi
        fi

        # 单次模式则退出
        if [[ "$CHECK_ONCE" == "true" ]]; then
            log "INFO" "单次检查完成，退出"
            exit 0
        fi

        log "INFO" "等待 ${INTERVAL} 秒后进行下次检查..."
        sleep "$INTERVAL"
    done
}

# ============================================================
# 入口
# ============================================================
main "$@"
