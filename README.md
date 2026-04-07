# cert-watcher 🔐

> SSL/TLS 证书过期监控与告警工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)](https://www.python.org/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-Required-blue.svg)](https://www.openssl.org/)

实时监测 SSL/TLS 证书过期时间，支持多主机监控、阈值告警、Slack 通知。

## ✨ 特性

- 🔍 支持检测任意 HTTPS 服务的证书信息
- ⏰ 自定义提前告警天数（默认 7/3/1 天）
- 🔔 支持 Slack Webhook 通知
- 📝 详细的日志记录（支持 JSON 格式导出）
- ⚙️ 灵活的配置文件格式
- 📊 支持输出证书详细信息（颁发者、域名、指纹等）
- 🖥️ 支持标准输出报告模式（无需守护运行）

## 🏃 快速开始

### 前置要求

- Python 3.6+
- OpenSSL (系统自带或通过 `brew install openssl` / `apt install openssl` 安装)

### 安装

```bash
# 克隆项目
git clone https://github.com/chensu1234/cert-watcher.git
cd cert-watcher

# 添加执行权限
chmod +x bin/cert-watcher.py
```

### 使用

```bash
# 使用默认配置 (config/certs.conf)
./bin/cert-watcher.py

# 指定配置文件
./bin/cert-watcher.py -c /path/to/certs.conf

# 设置告警阈值（提前 14/7/3 天告警）
./bin/cert-watcher.py -w 14,7,3

# 单次检查并输出 JSON
./bin/cert-watcher.py --check-once --json

# 指定 Slack Webhook
./bin/cert-watcher.py -W "https://hooks.slack.com/services/xxx"
```

## ⚙️ 配置

编辑 `config/certs.conf` 文件：

```bash
# 格式: host:port [warning_days]
# warning_days 可选，逗号分隔，默认使用命令行指定的阈值

# 监控常见服务
google.com:443
github.com:443
api.example.com:443
localhost:8443 30,14,7,3  # 自定义阈值
```

## 📋 命令行选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| -c, --config FILE | 配置文件路径 | ./config/certs.conf |
| -i, --interval SEC | 检测间隔（秒） | 86400 (24小时) |
| -w, --warn DAYS | 告警阈值天数（逗号分隔） | 7,3,1 |
| -W, --webhook URL | Slack Webhook URL | - |
| -j, --json | 输出 JSON 格式报告 | false |
| -o, --once | 单次检查（不守护运行） | false |
| -q, --quiet | 静默模式（仅告警） | false |
| -h, --help | 显示帮助信息 | - |

## 📁 项目结构

```
cert-watcher/
├── bin/
│   └── cert-watcher.py        # 主脚本
├── config/
│   └── certs.conf             # 证书监控配置
├── log/
│   └── .gitkeep               # 日志目录占位
├── README.md
└── LICENSE
```

## 📊 证书信息

每行配置可指定自定义告警阈值：

```bash
# host:port  threshold_days...
example.com:443      30,14,7,3
```

脚本会自动检测并输出以下证书信息：
- **Subject**: 证书主题
- **Issuer**: 颁发机构
- **Valid From/To**: 有效期
- **Days Remaining**: 剩余天数
- **Fingerprint**: SHA-256 指纹
- **Serial Number**: 序列号

## 🔔 告警通知

### Slack Webhook

```bash
./bin/cert-watcher.py -W "https://hooks.slack.com/services/xxx"
```

告警格式：
```
🚨 [cert-watcher] 证书即将过期
🌐 google.com:443
📅 剩余: 5 天 (到期: 2026-04-12)
👤 CN=*.google.com
```

## 📝 日志

日志默认保存在 `./log/cert-watcher.log`，包含：
- 检查时间
- 证书状态变化
- 错误信息
- 告警发送记录

## 🔧 扩展

- [ ] 添加邮件告警支持
- [ ] 添加钉钉/企业微信通知
- [ ] 添加 Prometheus 指标导出
- [ ] 添加到期排行榜（最紧急的证书列表）
- [ ] 添加证书链验证

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 👤 作者

Chen Su

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
