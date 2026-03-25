# cert-watcher 🖥️

> SSL/TLS 证书过期监控工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-Required-blue.svg)](https://www.openssl.org/)

一个简单实用的 SSL/TLS 证书过期监控工具，实时监测证书状态，异常时发送告警通知。

## ✨ 特性

- 🚀 **轻量级** — 纯 Shell 脚本，仅依赖 OpenSSL
- ⚡ **多域名监控** — 支持同时监控多个域名的证书
- 🔔 **多种通知** — 支持 Slack、Telegram Webhook 告警
- 📊 **状态可视化** — 颜色输出，快速识别证书状态
- 📝 **详细日志** — 记录所有检测结果和状态变化
- 🔧 **灵活配置** — 支持配置文件和命令行参数
- 📋 **报告模式** — 一键生成证书健康报告
- ⏰ **守护进程** — 支持后台持续监控

## 🏃 快速开始

### 前置要求

- Bash 4.0+
- OpenSSL
- curl (用于通知)

### 安装

```bash
# 克隆项目
git clone https://github.com/chensu1234/cert-watcher.git
cd cert-watcher

# 添加执行权限
chmod +x bin/cert-watcher.sh
```

### 使用

```bash
# 使用默认配置 (config/domains.conf)
./bin/cert-watcher.sh

# 生成证书健康报告 (单次)
./bin/cert-watcher.sh --report

# 指定配置文件
./bin/cert-watcher.sh -c /path/to/domains.conf

# 设置检测间隔 (1小时)
./bin/cert-watcher.sh -i 3600

# 设置告警阈值 (提前14天告警)
./bin/cert-watcher.sh -d 14

# 启用 Slack 通知
./bin/cert-watcher.sh -w "https://hooks.slack.com/services/xxx"

# 启用 Telegram 通知
export TELEGRAM_BOT_TOKEN="your-bot-token"
export TELEGRAM_CHAT_ID="your-chat-id"
./bin/cert-watcher.sh
```

## ⚙️ 配置

编辑 `config/domains.conf` 文件：

```bash
# 格式: host:port
# # 开头的行为注释

# 常用网站
github.com:443
google.com:443

# 国内服务
baidu.com:443
alipay.com:443

# 自定义域名
example.com:443
api.example.com:8443
```

## 📋 命令行选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config` FILE | 配置文件路径 | ./config/domains.conf |
| `-i, --interval` SEC | 检测间隔秒数 | 86400 (24小时) |
| `-d, --days` N | 警告阈值(提前N天) | 30 |
| `-D, --critical` N | 严重告警阈值(天) | 7 |
| `-w, --webhook` URL | Slack Webhook URL | - |
| `-r, --report` | 生成报告模式(单次) | - |
| `-h, --help` | 显示帮助 | - |
| `-v, --version` | 显示版本 | - |

## 🔔 通知配置

### Slack Webhook

```bash
./bin/cert-watcher.sh -w "https://hooks.slack.com/services/xxx"
```

### Telegram Bot

```bash
export TELEGRAM_BOT_TOKEN="your-bot-token"
export TELEGRAM_CHAT_ID="your-chat-id"
./bin/cert-watcher.sh
```

## 📊 证书状态说明

| 状态 | 剩余天数 | 颜色 | 说明 |
|------|---------|------|------|
| 🟢 OK | > 30 天 | 绿色 | 证书正常 |
| 🟡 WARNING | 8-30 天 | 黄色 | 即将过期，注意续期 |
| 🔴 CRITICAL | ≤ 7 天 | 红色 | 紧急! 立即续期 |

## 📁 项目结构

```
cert-watcher/
├── bin/
│   └── cert-watcher.sh      # 主脚本
├── config/
│   └── domains.conf          # 域名配置
├── log/                      # 日志目录
│   └── .gitkeep
├── README.md
├── LICENSE
└── CHANGELOG.md
```

## 📝 日志

日志默认保存在 `./log/cert-watcher.log`，包含：
- 启动/停止信息
- 证书检测结果
- 状态变化记录
- 错误信息

## 🔧 高级用法

### 定时任务 (crontab)

```bash
# 每天早上9点生成报告
0 9 * * * /path/to/cert-watcher.sh --report

# 每6小时检测一次 (生产环境推荐)
0 */6 * * * /path/to/cert-watcher.sh -i 21600 -w "https://hooks.slack.com/..."
```

### 监控内网服务

```bash
# 监控自签名证书 (使用 -d 0 忽略过期警告)
internal.example.com:8443
```

## 🔄 CHANGELOG

### v1.0.0 (2026-03-25)

- ✨ 初始版本发布
- ⚡ 支持多域名证书监控
- 🔔 支持 Slack Webhook 通知
- 📱 支持 Telegram Bot 通知
- 📊 支持单次报告模式
- 🔧 支持自定义告警阈值

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 👤 作者

Chen Su
