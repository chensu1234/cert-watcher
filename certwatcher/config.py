"""
配置解析模块
"""

import re
import os
from pathlib import Path
from typing import List, Tuple, Optional


class ConfigParser:
    """配置文件解析器"""

    COMMENT_PATTERN = re.compile(r'^\s*#')
    DOMAIN_PATTERN = re.compile(r'^\s*([^:#\s]+):(\d+)(?:\s+#.*)?$')
    KEY_VALUE_PATTERN = re.compile(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[=:]\s*(.+)$')

    def __init__(self, config_file: str):
        """
        初始化配置解析器

        Args:
            config_file: 配置文件路径
        """
        self.config_file = Path(config_file)

    def parse(self) -> Tuple[List[Tuple[str, int]], dict]:
        """
        解析配置文件

        Returns:
            (domains, settings) 元组
            - domains: [(domain, port), ...] 列表
            - settings: 配置字典
        """
        domains = []
        settings = {
            "interval": 86400,          # 默认每天检查一次
            "timeout": 10,              # 连接超时
            "warning_days": 30,         # 警告阈值（天）
            "critical_days": 7,         # 严重阈值（天）
            "webhook_url": "",          # Slack webhook
            "bark_url": "",             # Bark URL
            "log_file": "",             # 日志文件
            "console": True,
        }

        if not self.config_file.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_file}")

        with open(self.config_file, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip("\n\r")

                # 跳过注释和空行
                if self._is_comment_or_empty(line):
                    continue

                # 尝试解析域名配置
                if self._try_parse_domain(line, domains):
                    continue

                # 尝试解析键值配置
                if self._try_parse_kv(line, settings):
                    continue

        return domains, settings

    def _is_comment_or_empty(self, line: str) -> bool:
        """检查是否为注释或空行"""
        return not line or self.COMMENT_PATTERN.match(line)

    def _try_parse_domain(self, line: str, domains: list) -> bool:
        """
        尝试解析域名配置行

        Args:
            line: 行内容
            domains: 域名列表（会被修改）

        Returns:
            是否成功解析
        """
        # 去除行内注释
        line_content = line.split("#")[0].strip()
        if not line_content:
            return False

        match = self.DOMAIN_PATTERN.match(line)
        if match:
            domain = match.group(1)
            port = int(match.group(2))
            domains.append((domain, port))
            return True

        return False

    def _try_parse_kv(self, line: str, settings: dict) -> bool:
        """
        尝试解析键值配置行

        Args:
            line: 行内容
            settings: 设置字典（会被修改）

        Returns:
            是否成功解析
        """
        match = self.KEY_VALUE_PATTERN.match(line)
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()

            # 去除引号
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

            # 类型转换
            if key in ("interval", "timeout", "warning_days", "critical_days"):
                value = int(value)
            elif key in ("console",):
                value = value.lower() in ("true", "yes", "1", "on")

            settings[key] = value
            return True

        return False


def parse_env_file(env_path: str) -> dict:
    """
    解析 .env 格式文件

    Args:
        env_path: .env 文件路径

    Returns:
        环境变量字典
    """
    env_vars = {}
    env_file = Path(env_path)

    if not env_file.exists():
        return env_vars

    with open(env_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                env_vars[key.strip()] = value.strip().strip('"\'')

    return env_vars


def merge_config_with_env(config: dict, prefix: str = "CERTWATCHER_") -> dict:
    """
    将环境变量合并到配置

    环境变量格式: CERTWATCHER_INTERVAL=3600

    Args:
        config: 基础配置
        prefix: 环境变量前缀

    Returns:
        合并后的配置
    """
    result = config.copy()

    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue

        config_key = key[len(prefix):].lower()

        # 类型推断
        if value.lower() in ("true", "yes", "1"):
            value = True
        elif value.lower() in ("false", "no", "0"):
            value = False
        elif value.isdigit():
            value = int(value)

        result[config_key] = value

    return result
