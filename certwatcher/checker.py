#!/usr/bin/env python3
"""
cert-watcher - SSL Certificate Expiration Monitor
Author: Chen Su
License: MIT
"""

import ssl
import socket
import datetime
import json
import re
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class CertificateInfo:
    """SSL 证书信息"""
    domain: str
    port: int
    issuer: str
    subject: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    serial_number: str
    signature_algorithm: str
    is_valid: bool
    days_until_expiry: int
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """转换为字典格式"""
        d = asdict(self)
        d["not_before"] = self.not_before.isoformat() if self.not_before else None
        d["not_after"] = self.not_after.isoformat() if self.not_after else None
        return d


class CertificateChecker:
    """SSL 证书检查器"""

    # 默认检查端口
    DEFAULT_PORTS = [443, 8443]

    def __init__(self, timeout: int = 10):
        """
        初始化检查器

        Args:
            timeout: 连接超时时间（秒）
        """
        self.timeout = timeout

    def get_certificate(self, host: str, port: int = 443) -> CertificateInfo:
        """
        获取域名的 SSL 证书信息

        Args:
            host: 主机名
            port: 端口号

        Returns:
            CertificateInfo 对象
        """
        try:
            # 创建 SSL 上下文
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # 建立连接
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # 获取证书
                    cert = ssock.getpeercert(binary_form=True)

                    if cert is None:
                        return CertificateInfo(
                            domain=host,
                            port=port,
                            issuer="",
                            subject="",
                            not_before=datetime.datetime.min,
                            not_after=datetime.datetime.min,
                            serial_number="",
                            signature_algorithm="",
                            is_valid=False,
                            days_until_expiry=0,
                            error="Failed to retrieve certificate"
                        )

                    # 解析证书
                    return self._parse_certificate(host, port, cert)

        except socket.timeout:
            return CertificateInfo(
                domain=host,
                port=port,
                issuer="",
                subject="",
                not_before=datetime.datetime.min,
                not_after=datetime.datetime.min,
                serial_number="",
                signature_algorithm="",
                is_valid=False,
                days_until_expiry=0,
                error=f"Connection timeout ({self.timeout}s)"
            )
        except socket.gaierror as e:
            return CertificateInfo(
                domain=host,
                port=port,
                issuer="",
                subject="",
                not_before=datetime.datetime.min,
                not_after=datetime.datetime.min,
                serial_number="",
                signature_algorithm="",
                is_valid=False,
                days_until_expiry=0,
                error=f"DNS resolution failed: {e}"
            )
        except ConnectionRefusedError:
            return CertificateInfo(
                domain=host,
                port=port,
                issuer="",
                subject="",
                not_before=datetime.datetime.min,
                not_after=datetime.datetime.min,
                serial_number="",
                signature_algorithm="",
                is_valid=False,
                days_until_expiry=0,
                error="Connection refused"
            )
        except Exception as e:
            return CertificateInfo(
                domain=host,
                port=port,
                issuer="",
                subject="",
                not_before=datetime.datetime.min,
                not_after=datetime.datetime.min,
                serial_number="",
                signature_algorithm="",
                is_valid=False,
                days_until_expiry=0,
                error=f"Error: {e}"
            )

    def _parse_certificate(self, host: str, port: int, der_cert: bytes) -> CertificateInfo:
        """
        解析 DER 格式证书

        Args:
            host: 主机名
            port: 端口号
            der_cert: DER 格式证书数据

        Returns:
            CertificateInfo 对象
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
        except ImportError:
            # Fallback: 使用 socket.ssl 对象的不完整信息
            return self._parse_from_socket_info(host, port)

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # 提取颁发者
        issuer = self._get_issuer_name(cert)

        # 提取主题
        subject = self._get_subject_name(cert)

        # 提取有效期
        not_before = cert.not_valid_before_utc.replace(tzinfo=None) if hasattr(cert.not_valid_before_utc, 'replace') else cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc.replace(tzinfo=None) if hasattr(cert.not_valid_after_utc, 'replace') else cert.not_valid_after_utc

        # 计算剩余天数
        now = datetime.datetime.utcnow()
        days_until_expiry = (not_after - now).days

        # 检查证书是否有效
        is_valid = not_before <= now <= not_after

        # 提取序列号
        serial_number = format(cert.serial_number, '016x')

        # 提取签名算法
        signature_algorithm = cert.signature_algorithm_oid._name

        return CertificateInfo(
            domain=host,
            port=port,
            issuer=issuer,
            subject=subject,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial_number,
            signature_algorithm=signature_algorithm,
            is_valid=is_valid,
            days_until_expiry=days_until_expiry
        )

    def _parse_from_socket_info(self, host: str, port: int) -> CertificateInfo:
        """当 cryptography 库不可用时的降级方案"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_dict = ssock.getpeercert()
                if not cert_dict:
                    raise ValueError("Cannot parse certificate")

                # 简单的字典解析
                subject = dict(x[0] for x in cert_dict.get('subject', []))
                issuer = dict(x[0] for x in cert_dict.get('issuer', []))

                not_before_str = cert_dict.get('notBefore', '')
                not_after_str = cert_dict.get('notAfter', '')

                not_before = self._parse_asn1_date(not_before_str) if not_before_str else datetime.datetime.min
                not_after = self._parse_asn1_date(not_after_str) if not_after_str else datetime.datetime.min

                now = datetime.datetime.utcnow()
                days_until_expiry = (not_after - now).days if not_after != datetime.datetime.min else 0

                return CertificateInfo(
                    domain=host,
                    port=port,
                    issuer=', '.join(f"{k}={v}" for k, v in issuer.items()),
                    subject=', '.join(f"{k}={v}" for k, v in subject.items()),
                    not_before=not_before,
                    not_after=not_after,
                    serial_number=cert_dict.get('serialNumber', ''),
                    signature_algorithm=cert_dict.get('signatureAlgorithm', ''),
                    is_valid=days_until_expiry > 0,
                    days_until_expiry=days_until_expiry
                )

    def _parse_asn1_date(self, date_str: str) -> datetime.datetime:
        """解析 ASN.1 日期格式 (如 'Apr  8 12:00:00 2026 GMT')"""
        try:
            # 尝试标准格式
            dt = datetime.datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z')
            return dt
        except ValueError:
            try:
                dt = datetime.datetime.strptime(date_str, '%b %d %H:%M:%S %Y GMT')
                return dt
            except ValueError:
                return datetime.datetime.min

    def _get_issuer_name(self, cert) -> str:
        """提取颁发者名称"""
        parts = []
        for attr in cert.issuer:
            parts.append(f"{attr.oid._name}={attr.value}")
        return ', '.join(parts)

    def _get_subject_name(self, cert) -> str:
        """提取主题名称"""
        parts = []
        for attr in cert.subject:
            parts.append(f"{attr.oid._name}={attr.value}")
        return ', '.join(parts)

    def check_domains(self, domains: list[tuple[str, int]]) -> list[CertificateInfo]:
        """
        批量检查域名证书

        Args:
            domains: [(domain, port), ...] 列表

        Returns:
            CertificateInfo 列表
        """
        results = []
        for domain, port in domains:
            result = self.get_certificate(domain, port)
            results.append(result)
        return results


def format_cert_table(certs: list[CertificateInfo], verbose: bool = False) -> str:
    """
    格式化证书信息为表格

    Args:
        certs: CertificateInfo 列表
        verbose: 是否显示详细信息

    Returns:
        格式化的表格字符串
    """
    if not certs:
        return "No certificates to display."

    if verbose:
        # 详细模式
        lines = []
        for cert in certs:
            lines.append(f"Domain: {cert.domain}:{cert.port}")
            lines.append(f"  Subject: {cert.subject}")
            lines.append(f"  Issuer: {cert.issuer}")
            lines.append(f"  Valid From: {cert.not_before}")
            lines.append(f"  Valid Until: {cert.not_after}")
            lines.append(f"  Days Until Expiry: {cert.days_until_expiry}")
            lines.append(f"  Serial: {cert.serial_number}")
            lines.append(f"  Signature: {cert.signature_algorithm}")
            if cert.error:
                lines.append(f"  Error: {cert.error}")
            lines.append("")
        return '\n'.join(lines)

    # 简洁模式
    header = f"{'Domain':<35} {'Port':<6} {'Expiry':<12} {'Days':<6} {'Status':<10} {'Issuer (CN)'}"
    separator = "-" * len(header)
    lines = [header, separator]

    for cert in certs:
        # 提取颁发者 CN
        issuer_cn = ""
        if "CN=" in cert.issuer:
            match = re.search(r'CN=([^,]+)', cert.issuer)
            if match:
                issuer_cn = match.group(1)

        # 状态
        if cert.error:
            status = f"ERROR"
            days = "N/A"
            expiry = "N/A"
        else:
            days = str(cert.days_until_expiry)
            expiry = cert.not_after.strftime('%Y-%m-%d') if cert.not_after else "N/A"
            if cert.days_until_expiry < 0:
                status = "EXPIRED"
            elif cert.days_until_expiry <= 7:
                status = "CRITICAL"
            elif cert.days_until_expiry <= 30:
                status = "WARNING"
            else:
                status = "OK"

        domain_display = f"{cert.domain}:{cert.port}"
        lines.append(f"{domain_display:<35} {cert.port:<6} {expiry:<12} {days:<6} {status:<10} {issuer_cn}")

    return '\n'.join(lines)
