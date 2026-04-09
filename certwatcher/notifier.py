"""
通知模块 - 支持多种通知渠道
"""

import json
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import List
from certwatcher.checker import CertificateInfo


class NotificationStrategy(ABC):
    """通知策略抽象基类"""

    @abstractmethod
    def send(self, certs: List[CertificateInfo], config: dict) -> bool:
        """
        发送通知

        Args:
            certs: 需要通知的证书列表
            config: 通知配置

        Returns:
            发送是否成功
        """
        pass

    @abstractmethod
    def format_message(self, certs: List[CertificateInfo]) -> str:
        """格式化通知消息"""
        pass


class SlackNotifier(NotificationStrategy):
    """Slack Webhook 通知"""

    def format_message(self, certs: List[CertificateInfo]) -> str:
        """格式化 Slack 消息（使用 Block Kit）"""
        blocks = []

        # 标题
        warning_count = sum(1 for c in certs if c.days_until_expiry <= 30 and c.days_until_expiry >= 0)
        expired_count = sum(1 for c in certs if c.days_until_expiry < 0)
        error_count = sum(1 for c in certs if c.error)

        emoji = "🔴" if expired_count > 0 else ("⚠️" if warning_count > 0 else "✅")
        title = f"{emoji} Certificate Status Report"

        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": title,
                "emoji": True
            }
        })

        blocks.append({"type": "divider"})

        # 分类显示
        # 过期证书
        expired = [c for c in certs if c.days_until_expiry < 0]
        if expired:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*🔴 Expired Certificates*"}
            })
            for cert in expired:
                text = f"• `{cert.domain}:{cert.port}` - Expired {abs(cert.days_until_expiry)} days ago"
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": text}
                })

        # 严重警告（7天内）
        critical = [c for c in certs if 0 <= c.days_until_expiry <= 7]
        if critical:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*⚠️ Critical - Expiring within 7 days*"}
            })
            for cert in critical:
                text = f"• `{cert.domain}:{cert.port}` - Expires in {cert.days_until_expiry} days ({cert.not_after.strftime('%Y-%m-%d')})"
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": text}
                })

        # 警告（30天内）
        warning = [c for c in certs if 7 < c.days_until_expiry <= 30]
        if warning:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*🟡 Warning - Expiring within 30 days*"}
            })
            for cert in warning:
                text = f"• `{cert.domain}:{cert.port}` - Expires in {cert.days_until_expiry} days ({cert.not_after.strftime('%Y-%m-%d')})"
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": text}
                })

        # 错误
        errors = [c for c in certs if c.error]
        if errors:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*❌ Connection Errors*"}
            })
            for cert in errors:
                text = f"• `{cert.domain}:{cert.port}` - {cert.error}"
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": text}
                })

        # 正常证书
        ok = [c for c in certs if not c.error and c.days_until_expiry > 30]
        if ok:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*✅ Healthy ({len(ok)} certificates, >30 days)*"}
            })

        blocks.append({"type": "divider"})

        # 时间戳
        from datetime import datetime
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Generated at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                }
            ]
        })

        return json.dumps(blocks)

    def send(self, certs: List[CertificateInfo], config: dict) -> bool:
        """通过 Slack Webhook 发送通知"""
        webhook_url = config.get("webhook_url", "")
        if not webhook_url:
            print("[Slack] No webhook URL configured")
            return False

        payload = self.format_message(certs)
        payload_dict = json.loads(payload)

        data = json.dumps({"blocks": payload_dict}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print(f"[Slack] Notification sent successfully")
                    return True
                else:
                    print(f"[Slack] Failed to send: HTTP {response.status}")
                    return False
        except urllib.error.URLError as e:
            print(f"[Slack] Error sending notification: {e}")
            return False


class ConsoleNotifier(NotificationStrategy):
    """控制台输出通知（用于调试）"""

    def format_message(self, certs: List[CertificateInfo]) -> str:
        """格式化控制台消息"""
        lines = []
        for cert in certs:
            if cert.error:
                status = f"❌ ERROR: {cert.error}"
            elif cert.days_until_expiry < 0:
                status = f"🔴 EXPIRED ({abs(cert.days_until_expiry)} days ago)"
            elif cert.days_until_expiry <= 7:
                status = f"⚠️  CRITICAL - {cert.days_until_expiry} days"
            elif cert.days_until_expiry <= 30:
                status = f"🟡 WARNING - {cert.days_until_expiry} days"
            else:
                status = f"✅ OK - {cert.days_until_expiry} days"

            lines.append(f"{cert.domain}:{cert.port} - {status}")

        return '\n'.join(lines)

    def send(self, certs: List[CertificateInfo], config: dict) -> bool:
        """输出到控制台"""
        print(self.format_message(certs))
        return True


class BarkNotifier(NotificationStrategy):
    """Bark 推送通知（iOS）"""

    def format_message(self, certs: List[CertificateInfo]) -> tuple[str, str]:
        """格式化 Bark 消息"""
        warning_certs = [c for c in certs if c.days_until_expiry <= 30 or c.error]
        if not warning_certs:
            title = "✅ Certificate Check - All OK"
            body = f"All {len(certs)} certificates are healthy."
        else:
            expired = [c for c in warning_certs if c.days_until_expiry < 0]
            critical = [c for c in warning_certs if 0 <= c.days_until_expiry <= 7]

            if expired:
                title = f"🔴 {len(expired)} Certificate(s) Expired!"
                body = ", ".join(f"{c.domain}" for c in expired[:3])
            elif critical:
                title = f"⚠️ {len(critical)} Certificate(s) Expiring Soon"
                body = ", ".join(f"{c.domain}({c.days_until_expiry}d)" for c in critical[:3])
            else:
                title = f"🟡 {len(warning_certs)} Certificate(s) Expiring Within 30 Days"
                body = ", ".join(f"{c.domain}({c.days_until_expiry}d)" for c in warning_certs[:3])

        return title, body

    def send(self, certs: List[CertificateInfo], config: dict) -> bool:
        """通过 Bark 发送推送"""
        bark_url = config.get("bark_url", "")
        if not bark_url:
            print("[Bark] No bark URL configured")
            return False

        title, body = self.format_message(certs)

        # Bark URL 格式: https://api.day.app/{device_key}/{title}/{body}
        url = f"{bark_url.rstrip('/')}/{title}/{body}"

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "cert-watcher"})
            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status == 200:
                    print("[Bark] Notification sent successfully")
                    return True
                else:
                    print(f"[Bark] Failed to send: HTTP {response.status}")
                    return False
        except urllib.error.URLError as e:
            print(f"[Bark] Error sending notification: {e}")
            return False


class NotifierManager:
    """通知管理器 - 协调多个通知渠道"""

    def __init__(self):
        self.channels: list[NotificationStrategy] = []

    def add_channel(self, channel: NotificationStrategy):
        """添加通知渠道"""
        self.channels.append(channel)

    def notify(self, certs: List[CertificateInfo], config: dict):
        """
        通过所有渠道发送通知

        Args:
            certs: 证书列表
            config: 通知配置
        """
        for channel in self.channels:
            try:
                channel.send(certs, config)
            except Exception as e:
                print(f"[Notifier] Channel {channel.__class__.__name__} failed: {e}")

    @classmethod
    def from_config(cls, config: dict) -> "NotifierManager":
        """
        从配置创建通知管理器

        Args:
            config: 通知配置字典

        Returns:
            NotifierManager 实例
        """
        manager = cls()

        # 总是添加控制台通知（仅在 verbose 模式真正输出）
        # 这里添加以便在批处理时也能看到摘要
        if config.get("console", True):
            manager.add_channel(ConsoleNotifier())

        if config.get("slack_webhook"):
            manager.add_channel(SlackNotifier())

        if config.get("bark_url"):
            manager.add_channel(BarkNotifier())

        return manager
