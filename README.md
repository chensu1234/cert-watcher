# cert-watcher 🔐

> SSL/TLS 证书过期监控工具 — 轻量、可靠、自动化

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux-blue.svg)]()

**cert-watcher** 是一款纯 Shell 编写的 SSL/TLS 证书过期监控工具，支持多主机监控、分级告警、Webhook 通知，适用于服务器运维和 DevOps 场景。

## ✨ 特性

- 🛡️ **纯 Shell 实现** — 无需额外依赖，仅需 OpenSSL
- 🌐 **多主机监控** — 支持批量检测配置文件中的所有主机
- 📡 **SNI 支持** — 自动发送 ServerName，正确处理虚拟主机证书
- 🚨 **分级告警** — 警告 (WARN) / 严重 (CRIT) 两级阈值
- 📢 **Webhook 通知** — 原生支持 Slack 格式，可扩展至钉钉、企业微信等
- 🔄 **守护进程模式** — 后台持续监控，灵活设置间隔
- 🎯 **单次检测模式** — 适合 CI/CD 和一次性检查
- 📝 **详细日志** — 所有检测结果记录到日志文件

## 🏃 快速开始

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
# 守护进程模式 (监控 config/hosts.conf 中的所有主机)
./bin/cert-watcher.sh

# 单次检测 (指定单个主机)
./bin/cert-watcher.sh --check-once github.com:443

# 指定配置文件
./bin/cert-watcher.sh -c /path/to/hosts.conf

# 设置检测间隔为 1 小时，30天开始警告，7天严重告警
./bin/cert-watcher.sh -i 3600 -w 30 -k 7

# 启用 Slack Webhook 通知
./bin/cert-watcher.sh -W "https://hooks.slack.com/services/xxx"
```

## ⚙️ 配置

### 主机配置

编辑 `config/hosts.conf`：

```bash
# 格式: host:port
# # 开头的行为注释

# 常用网站
github.com:443
google.com:443

# 自定义服务
example.com:443
api.example.com:443
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `CONFIG_FILE` | 配置文件路径 | `./config/hosts.conf` |
| `LOG_FILE` | 日志文件路径 | `./log/cert-watcher.log` |
| `INTERVAL` | 检测间隔(秒) | `86400` (24小时) |
| `TIMEOUT` | 连接超时(秒) | `10` |
| `WARN_DAYS` | 警告阈值(天) | `30` |
| `CRIT_DAYS` | 严重阈值(天) | `7` |
| `NOTIFY_WEBHOOK` | Webhook URL | 空 |

### Webhook 通知

支持 Slack Webhook，将 URL 通过 `-W` 参数传入即可：

```bash
./bin/cert-watcher.sh -W "https://hooks.slack.com/services/xxx"
```

告警效果：

- 🟡 **警告 (WARN)** — 证书剩余天数 ≤ 30 天
- 🔴 **严重 (CRIT)** — 证书剩余天数 ≤ 7 天，或已过期

## 📋 命令行选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config FILE` | 配置文件路径 | `./config/hosts.conf` |
| `-i, --interval SEC` | 检测间隔秒数 | `86400` |
| `-t, --timeout SEC` | 连接超时秒数 | `10` |
| `-w, --warn DAYS` | 首次警告天数 | `30` |
| `-k, --critical DAYS` | 严重警告天数 | `7` |
| `-W, --webhook URL` | 告警 Webhook URL | - |
| `-m, --mode MODE` | 运行模式: `daemon` 或 `once` | `daemon` |
| `-v, --verbose` | 详细输出 | - |
| `--check-once HOST:PORT` | 单次检测指定主机 | - |
| `-h, --help` | 显示帮助 | - |

## 📁 项目结构

```
cert-watcher/
├── bin/
│   └── cert-watcher.sh      # 主脚本
├── config/
│   └── hosts.conf           # 主机配置
├── log/                      # 日志目录
│   └── .gitkeep
├── lib/                      # 扩展库目录 (预留)
│   └── .gitkeep
├── README.md
├── LICENSE
└── .gitignore
```

## 📝 日志

日志默认保存在 `./log/cert-watcher.log`，包含：

- 启动和关闭信息
- 每台主机的证书过期检测结果
- 告警触发记录
- 错误信息 (连接失败、超时等)

```bash
# 查看实时日志
tail -f log/cert-watcher.log
```

## 🔧 扩展

计划中的功能：

- [ ] 钉钉 Webhook 通知支持
- [ ] 企业微信通知支持
- [ ] Prometheus 指标导出
- [ ] 支持 PEM 证书文件直接读取 (无需网络)
- [ ] 健康检查端点 (HTTP API)

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 👤 作者

Chen Su

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
