#!/usr/bin/env python3
"""
cert-watcher - SSL/TLS 证书过期监控工具
作者: Chen Su
许可证: MIT
"""

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import time
import socket
import ssl
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ============================================================
# 颜色定义 (ANSI Escape Codes)
# ============================================================
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
MAGENTA = '\033[0;35m'
BOLD = '\033[1m'
DIM = '\033[2m'
NC = '\033[0m'  # No Color

# ============================================================
# 全局配置
# ============================================================
CONFIG_FILE = './config/certs.conf'
LOG_FILE = './log/cert-watcher.log'
STATE_FILE = './log/cert-watcher.state'
INTERVAL = 86400  # 24 hours
WARN_DAYS = [7, 3, 1]
NOTIFY_WEBHOOK = ''
JSON_OUTPUT = False
CHECK_ONCE = False
QUIET_MODE = False

# 状态缓存
cert_status: Dict[str, int] = {}
last_alert_days: Dict[str, int] = {}

# ============================================================
# 工具函数
# ============================================================

def log(level: str, msg: str, to_file: bool = True, to_stdout: bool = True):
    """写入日志"""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] [{level}] {msg}"
    if to_stdout and not QUIET_MODE:
        print(line)
    if to_file:
        try:
            Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
            with open(LOG_FILE, 'a') as f:
                f.write(line + '\n')
        except Exception:
            pass


def load_state():
    """从文件加载状态缓存"""
    global cert_status, last_alert_days
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, 'r') as f:
                data = json.load(f)
                cert_status = data.get('cert_status', {})
                last_alert_days = data.get('last_alert_days', {})
    except Exception:
        pass


def save_state():
    """保存状态缓存到文件"""
    try:
        Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(STATE_FILE, 'w') as f:
            json.dump({
                'cert_status': cert_status,
                'last_alert_days': last_alert_days
            }, f, indent=2)
    except Exception:
        pass


def parse_warn_days(warn_str: str) -> List[int]:
    """解析告警阈值字符串，返回排序后的天数列表（从大到小）"""
    days = [int(d.strip()) for d in warn_str.split(',') if d.strip()]
    return sorted(set(days), reverse=True)


def get_cert_info(host: str, port: int, timeout: int = 10) -> Optional[Dict]:
    """
    获取目标主机的证书信息。
    优先使用 Python ssl 模块（直接连接），失败时降级到 curl（支持代理）。
    """
    # 方法 1: 使用 Python ssl 模块直接连接
    result = _get_cert_via_ssl(host, port, timeout)
    if result:
        return result

    # 方法 2: 降级到 curl（会自动使用系统代理/HTTP_PROXY 环境变量）
    result = _get_cert_via_curl(host, port, timeout)
    if result:
        return result

    return None


def _get_cert_via_ssl(host: str, port: int, timeout: int) -> Optional[Dict]:
    """使用 Python ssl 模块获取证书信息"""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                if not cert:
                    return None

                # 解析证书
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend

                cert_obj = x509.load_der_x509_certificate(cert, default_backend())

                # 提取信息
                subject = cert_obj.subject.rfc4514_string()
                issuer = cert_obj.issuer.rfc4514_string()
                not_before = cert_obj.not_valid_before_utc.strftime('%b %d %H:%M:%S %Y %Z')
                not_after = cert_obj.not_valid_after_utc.strftime('%b %d %H:%M:%S %Y %Z')

                # 序列号
                serial = format(cert_obj.serial_number, 'x').upper()
                serial = ':'.join(serial[i:i+2] for i in range(0, len(serial), 2))

                # SHA256 指纹
                fingerprint = cert_obj.fingerprint()
                fp_str = ':'.join(format(b, '02X') for b in fingerprint)

                return {
                    'subject': subject,
                    'issuer': issuer,
                    'not_before': not_before,
                    'not_after': not_after,
                    'serial': serial,
                    'fingerprint': fp_str,
                }
    except Exception:
        return None


def _get_cert_via_curl(host: str, port: int, timeout: int) -> Optional[Dict]:
    """使用 curl 获取证书信息（支持 HTTP 代理）"""
    try:
        # curl 自动使用 HTTP_PROXY/https_proxy 环境变量
        result = subprocess.run(
            ['curl', '-s', '--connect-timeout', str(timeout),
             '-v', '-k', f'https://{host}:{port}'],
            capture_output=True, text=True, timeout=timeout + 2
        )

        # 解析 curl -v 输出中的证书信息
        stderr = result.stderr
        info = {}

        # subject: CN=*.google.com
        m = re.search(r'^\*\s+subject: (.+)', stderr, re.MULTILINE)
        if m:
            info['subject'] = m.group(1).strip()

        # issuer: C=US; O=Google Trust Services; CN=WR2
        m = re.search(r'^\*\s+issuer:\s*(.+)', stderr, re.MULTILINE)
        if m:
            info['issuer'] = m.group(1).strip()

        # start date
        m = re.search(r'^\*\s+start date: (.+)', stderr, re.MULTILINE)
        if m:
            info['not_before'] = m.group(1).strip()

        # expire date
        m = re.search(r'^\*\s+expire date: (.+)', stderr, re.MULTILINE)
        if m:
            info['not_after'] = m.group(1).strip()

        if 'not_after' in info and 'subject' in info:
            info['fingerprint'] = '(via curl)'
            info['serial'] = '(via curl)'
            return info

        return None
    except Exception:
        return None


def parse_expiry_timestamp(date_str: str) -> Optional[int]:
    """解析证书日期字符串，返回 Unix 时间戳"""
    if not date_str:
        return None

    date_str = date_str.strip()

    # 常见格式列表
    formats = [
        '%b %d %H:%M:%S %Y %Z',       # Jun  8 08:36:31 2026 GMT
        '%b %d %H:%M:%S %Y GMT',       # Jun  8 08:36:31 2026 GMT
        '%d %b %Y %H:%M:%S %Z',       # 08 Jun 2026 08:36:31 GMT
        '%Y-%m-%d %H:%M:%S %Z',       # 2026-06-08 08:36:31 GMT
        '%Y-%m-%d %H:%M:%S',          # 2026-06-08 08:36:31
        '%d %b %Y %H:%M:%S',          # 08 Jun 2026 08:36:31
    ]

    for fmt in formats:
        try:
            # 移除多余空格
            dt = datetime.datetime.strptime(date_str, fmt)
            return int(dt.timestamp())
        except ValueError:
            continue

    # 尝试 email.utils 解析
    try:
        from email.utils import parsedate_to_datetime
        parsed = parsedate_to_datetime(date_str)
        return int(parsed.timestamp())
    except Exception:
        pass

    return None


def get_days_remaining(expiry_ts: int) -> int:
    """计算剩余天数"""
    now = int(time.time())
    return (expiry_ts - now) // 86400


def send_slack_notification(host: str, port: int, days: int,
                              expiry_date: str, subject: str, alert_level: str):
    """发送 Slack 通知"""
    if not NOTIFY_WEBHOOK:
        return

    if alert_level == 'CRITICAL':
        color = '#FF0000'
        emoji = '🚨'
    elif alert_level == 'WARNING':
        color = '#FFA500'
        emoji = '⚠️'
    else:
        color = '#36A64F'
        emoji = '✅'

    payload = {
        'attachments': [{
            'color': color,
            'blocks': [
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': f'{emoji} *[{alert_level}] 证书告警 - cert-watcher*'
                    }
                },
                {
                    'type': 'section',
                    'fields': [
                        {'type': 'mrkdwn', 'text': f'*🌐 主机:*\n`{host}:{port}`'},
                        {'type': 'mrkdwn', 'text': f'*📅 剩余天数:*\n`{days} 天`'},
                        {'type': 'mrkdwn', 'text': f'*📆 到期时间:*\n`{expiry_date}`'},
                        {'type': 'mrkdwn', 'text': f'*👤 证书主题:*\n`{subject}`'},
                    ]
                }
            ]
        }]
    }

    try:
        import urllib.request
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            NOTIFY_WEBHOOK,
            data=data,
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def check_cert(host: str, port: int, warn_days: List[int]) -> bool:
    """检查单个证书，返回是否成功"""
    key = f'{host}:{port}'

    # 获取证书信息
    info = get_cert_info(host, port, timeout=10)
    if not info:
        log('ERROR', f'无法获取 {host}:{port} 的证书信息')
        if JSON_OUTPUT:
            print(json.dumps({
                'host': host, 'port': port,
                'error': '无法获取证书信息', 'ok': False
            }))
        return False

    # 计算剩余天数
    expiry_ts = parse_expiry_timestamp(info.get('not_after', ''))
    if not expiry_ts:
        log('ERROR', f'无法解析 {host}:{port} 的证书日期')
        return False

    days_remaining = get_days_remaining(expiry_ts)

    # 确定告警级别
    alert_level = ''
    if days_remaining <= 0:
        alert_level = 'CRITICAL'
    elif days_remaining <= warn_days[-1] if warn_days else False:
        alert_level = 'WARNING'

    # 避免重复告警
    last_alert = last_alert_days.get(key, 999)
    if alert_level and last_alert != days_remaining:
        send_slack_notification(
            host, port, days_remaining,
            info.get('not_after', ''),
            info.get('subject', ''),
            alert_level
        )
        last_alert_days[key] = days_remaining
        log('WARN', f'告警: {host}:{port} 剩余 {days_remaining} 天 ({alert_level})')

    # 更新状态缓存
    cert_status[key] = days_remaining

    # 输出
    if JSON_OUTPUT:
        print(json.dumps({
            'host': host,
            'port': port,
            'subject': info.get('subject', ''),
            'issuer': info.get('issuer', ''),
            'notBefore': info.get('not_before', ''),
            'notAfter': info.get('not_after', ''),
            'fingerprint': info.get('fingerprint', ''),
            'serialNumber': info.get('serial', ''),
            'daysRemaining': days_remaining,
            'ok': True
        }, indent=2))
    else:
        # 确定显示颜色
        if days_remaining < 0:
            color = RED
            status_text = f'已过期 {abs(days_remaining)} 天'
        elif days_remaining <= (warn_days[0] if warn_days else 7):
            color = RED
            status_text = f'紧急 ({days_remaining} 天)'
        elif days_remaining <= (warn_days[1] if len(warn_days) > 1 else 30):
            color = YELLOW
            status_text = f'警告 ({days_remaining} 天)'
        elif days_remaining <= (warn_days[2] if len(warn_days) > 2 else 7):
            color = CYAN
            status_text = f'注意 ({days_remaining} 天)'
        else:
            color = GREEN
            status_text = f'正常 ({days_remaining} 天)'

        if not QUIET_MODE:
            print(f'{color}[{status_text}]{NC} {BOLD}{host}:{port}{NC}')
            print(f'  {DIM}Subject:{NC}   {info.get("subject", "N/A")}')
            print(f'  {DIM}Issuer:{NC}    {info.get("issuer", "N/A")}')
            print(f'  {DIM}Valid:{NC}     {info.get("not_before", "N/A")} ~ {info.get("not_after", "N/A")}')
            if info.get('fingerprint') != '(via curl)':
                print(f'  {DIM}Fingerprint:{NC} {info.get("fingerprint", "N/A")}')

    return True


def parse_config(config_path: str) -> List[Tuple[str, int, List[int]]]:
    """解析配置文件，返回 [(host, port, warn_days), ...]"""
    entries = []
    if not os.path.exists(config_path):
        log('ERROR', f'配置文件不存在: {config_path}')
        sys.exit(1)

    with open(config_path, 'r') as f:
        for line_no, line in enumerate(f, 1):
            raw = line.strip()
            # 跳过空行和注释
            if not raw or raw.startswith('#'):
                continue

            # 解析 host:port [warn_days...]
            match = re.match(r'^([^:]+):(\d+)(?:\s+(.*))?$', raw)
            if not match:
                log('WARN', f'配置行 {line_no} 格式无效: {raw}')
                continue

            host = match.group(1).strip()
            port = int(match.group(2))
            custom_warn_str = match.group(3) or ''

            # 解析自定义告警天数
            if custom_warn_str:
                custom_warn = parse_warn_days(custom_warn_str)
            else:
                custom_warn = WARN_DAYS

            entries.append((host, port, custom_warn))

    return entries


def print_summary():
    """打印汇总报告"""
    total = len(cert_status)
    if total == 0:
        return

    expired = sum(1 for d in cert_status.values() if d < 0)
    critical = sum(1 for d in cert_status.values() if 0 <= d <= 7)
    warning = sum(1 for d in cert_status.values() if 7 < d <= 30)
    ok = sum(1 for d in cert_status.values() if d > 30)

    print('')
    print(f'{BOLD}========== 汇总报告 =========={NC}')
    print(f'总计: {total}  |  {GREEN}正常: {ok}{NC}  |  {CYAN}注意: {warning}{NC}  |  {RED}紧急: {critical}{NC}  |  {RED}过期: {expired}{NC}')
    print('')


def main():
    global CONFIG_FILE, LOG_FILE, STATE_FILE, INTERVAL, WARN_DAYS, NOTIFY_WEBHOOK
    global JSON_OUTPUT, CHECK_ONCE, QUIET_MODE

    parser = argparse.ArgumentParser(
        description='cert-watcher - SSL/TLS 证书过期监控工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  %(prog)s -c /etc/cert-watcher.conf -i 3600
  %(prog)s -w 30,14,7,3 -W https://hooks.slack.com/xxx
  %(prog)s --check-once --json

配置文件格式:
  # host:port [warning_days...]
  google.com:443
  github.com:443
  localhost:8443 30,14,7,3
'''
    )
    parser.add_argument('-c', '--config', default=CONFIG_FILE,
                        help='配置文件路径 (默认: ./config/certs.conf)')
    parser.add_argument('-i', '--interval', type=int, default=INTERVAL,
                        help='检测间隔秒数 (默认: 86400，即 24 小时)')
    parser.add_argument('-w', '--warn', default='7,3,1',
                        help='告警阈值天数，逗号分隔 (默认: 7,3,1)')
    parser.add_argument('-W', '--webhook', default='',
                        help='Slack Webhook URL')
    parser.add_argument('-j', '--json', action='store_true',
                        help='输出 JSON 格式报告')
    parser.add_argument('-o', '--once', '--check-once', action='store_true',
                        help='单次检查（不守护运行）')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='静默模式（仅告警）')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0.0')

    args = parser.parse_args()

    # 应用参数
    CONFIG_FILE = args.config
    INTERVAL = args.interval
    WARN_DAYS = parse_warn_days(args.warn)
    NOTIFY_WEBHOOK = args.webhook
    JSON_OUTPUT = args.json
    CHECK_ONCE = args.once
    QUIET_MODE = args.quiet

    # 展开路径
    CONFIG_FILE = os.path.expanduser(CONFIG_FILE)
    LOG_FILE = os.path.expanduser(LOG_FILE)
    STATE_FILE = os.path.expanduser(STATE_FILE)

    # 确保目录存在
    Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(CONFIG_FILE).parent.mkdir(parents=True, exist_ok=True)

    # 加载状态
    load_state()

    # 日志启动
    log('INFO', '========== cert-watcher 启动 ==========')
    log('INFO', f'配置文件: {CONFIG_FILE}')
    log('INFO', f'检测间隔: {INTERVAL} 秒 ({INTERVAL // 3600} 小时)')
    log('INFO', f'告警阈值: {WARN_DAYS} 天')

    # 主循环
    while True:
        # 解析配置
        entries = parse_config(CONFIG_FILE)

        if not entries:
            log('WARN', f'配置为空或无效: {CONFIG_FILE}')
        else:
            for host, port, warn_days in entries:
                check_cert(host, port, warn_days)

            # 汇总报告（非 JSON 模式）
            if not JSON_OUTPUT:
                print_summary()

            # 保存状态
            save_state()

        # 单次模式则退出
        if CHECK_ONCE:
            log('INFO', '单次检查完成，退出')
            break

        log('INFO', f'等待 {INTERVAL} 秒后进行下次检查...')
        time.sleep(INTERVAL)


if __name__ == '__main__':
    main()
