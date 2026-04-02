# cert-watcher 🔐

> SSL/TLS 证书过期监控与告警工具

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/Shell-Bash-blue.svg)](https://www.gnu.org/software/bash/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-Required-orange.svg)](https://www.openssl.org/)

自动监控多个域名的 SSL/TLS 证书过期时间，异常时通过 Slack Webhook 发送告警。

## ✨ 特性

- 🔐 **自动检测** — 定期检查域名证书过期时间，支持 SNI
- ⚡ **轻量高效** — 纯 Bash + OpenSSL，无需额外依赖
- 🔔 **智能告警** — 支持 Slack Webhook，状态变化时才告警（避免轰炸）
- 📊 **多级阈值** — 警告（默认30天）/ 严重（默认7天）/ 已过期
- 📝 **状态持久化** — 本地存储上次检查状态，仅在状态变化时告警
- 📁 **灵活配置** — 命令行参数或环境变量均可配置
- 🖥️ **彩色输出** — 终端实时显示彩色状态概览

## 🏃 快速开始

### 前提

- Bash 4.0+（macOS 需安装新版 Bash: `brew install bash`）
- OpenSSL / LibreSSL
- GNU coreutils `timeout` 命令（macOS: `brew install coreutils`）
- curl（仅 Slack 通知功能需要）

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
# 使用默认配置（监控 config/domains.conf 中的域名，间隔1小时）
./bin/cert-watcher.sh

# 指定配置文件
./bin/cert-watcher.sh -c /path/to/domains.conf

# 设置检测间隔（1800秒 = 30分钟）
./bin/cert-watcher.sh -i 1800

# 启用 Slack 告警
./bin/cert-watcher.sh -w "https://hooks.slack.com/services/xxx"

# 自定义警告阈值（提前14天开始警告，提前3天严重告警）
./bin/cert-watcher.sh -d 14 -D 3
```

### 环境变量

```bash
# 也可以通过环境变量配置
CONFIG_FILE=./config/domains.conf \
INTERVAL=3600 \
TIMEOUT=10 \
WARN_DAYS=30 \
CRIT_DAYS=7 \
NOTIFY_WEBHOOK="https://hooks.slack.com/services/xxx" \
./bin/cert-watcher.sh
```

## ⚙️ 配置

编辑 `config/domains.conf` 文件，每行一个域名：

```bash
# 格式: domain 或 domain:port
# # 开头为注释

# 标准 HTTPS
google.com
github.com

# 自定义端口
api.example.com:8443

# 带注释说明
secure.example.com:443   # 生产环境主站
```

## 📋 命令行选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| `-c, --config FILE` | 域名配置文件路径 | `./config/domains.conf` |
| `-i, --interval SEC` | 检测间隔（秒） | `3600` (1小时) |
| `-t, --timeout SEC` | 连接超时（秒） | `10` |
| `-w, --webhook URL` | 告警 Webhook URL | `-` |
| `-d, --warn-days N` | 警告阈值（天） | `30` |
| `-D, --crit-days N` | 严重警告阈值（天） | `7` |
| `-s, --state-dir DIR` | 状态存储目录 | `./state` |
| `-l, --log-dir DIR` | 日志目录 | `./log` |
| `-h, --help` | 显示帮助 | `-` |
| `-v, --version` | 显示版本 | `-` |

## 📁 项目结构

```
cert-watcher/
├── bin/
│   └── cert-watcher.sh      # 🎯 主脚本（核心逻辑）
├── config/
│   └── domains.conf         # 📋 域名列表配置
├── log/                      # 📝 日志目录
│   └── .gitkeep
├── state/                    # 💾 状态存储目录
│   └── .gitkeep
├── README.md                 # 📖 说明文档
└── LICENSE                   # 📄 MIT 许可证
```

## 🔔 告警示例

### Slack 告警消息

证书状态变化时，自动发送彩色 Slack 消息：

| 状态 | 颜色 | 说明 |
|------|------|------|
| ✅ 正常 | 绿色 | 证书在阈值之外 |
| ⚠️ 警告 | 黄色 | 即将过期（≤警告天数） |
| 🚨 严重 | 红色 | 即将过期（≤严重天数） |
| 🚨 已过期 | 红色 | 证书已过期 |

### 终端输出示例

```
[2026-04-02 12:00:00] [INFO]    cert-watcher 证书监控启动
==========================================
  cert-watcher 证书监控概览
==========================================
  总计: 3 | 正常: 2 | 警告: 1 | 严重: 0 | 已过期: 0 | 错误: 0

  域名                                  剩余天数   状态
  ------                                --------   ------
  github.com                           365        正常
  google.com                           22         警告
  expired.badssl.com                   -5         已过期
```

## 📝 日志

日志保存在 `./log/cert-watcher.log`，包含：

- 启动和配置信息
- 每轮检测结果
- 告警触发记录
- 错误详情

```bash
# 实时查看日志
tail -f log/cert-watcher.log
```

## 🔧 工作原理

1. **读取配置** — 从 `config/domains.conf` 加载域名列表
2. **连接检测** — 使用 `openssl s_client` 获取每个域名的证书信息
3. **计算过期** — 解析证书 `notAfter` 字段，计算剩余天数
4. **状态对比** — 与本地状态文件对比，只在状态变化时触发告警
5. **发送通知** — 通过 Slack Webhook 发送彩色告警消息
6. **持久化** — 保存当前状态到 `state/cert-status` 文件

## 🚀 生产环境建议

```bash
# 使用 systemd 服务运行（Linux）
# 创建 /etc/systemd/system/cert-watcher.service
[Unit]
Description=cert-watcher SSL Certificate Monitor
After=network.target

[Service]
Type=simple
User=your-user
WorkingDirectory=/path/to/cert-watcher
ExecStart=/path/to/cert-watcher/bin/cert-watcher.sh \
    -c /path/to/cert-watcher/config/domains.conf \
    -i 1800 \
    -w "https://hooks.slack.com/services/xxx"
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

## 🛠️ 扩展方向

- [ ] 支持邮件通知
- [ ] 支持企业微信 / 钉钉 Webhook
- [ ] Prometheus 指标导出
- [ ] 支持 Docker 运行
- [ ] 支持配置文件内的自定义阈值

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 👤 作者

Chen Su

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
