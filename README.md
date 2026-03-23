# cert-watcher 🔒

> SSL/TLS 证书过期监控工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0-blue.svg)](https://www.openssl.org/)

一个简单实用的 SSL/TLS 证书监控工具，实时监测证书过期时间，临近过期时自动发送告警通知。

## ✨ 特性

- 🚀 轻量级，纯 Shell 脚本
- ⚡ 支持多主机多端口监控
- 🔔 智能告警（WARNING/CRITICAL）
- 📢 支持 Slack Webhook 通知
- 📝 详细的日志记录
- 🔧 灵活的配置
- ⏰ 可配置检测间隔和阈值

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
# 使用默认配置 (config/certs.conf)
./bin/cert-watcher.sh

# 指定配置文件
./bin/cert-watcher.sh -c /path/to/certs.conf

# 设置检测间隔 (每小时)
./bin/cert-watcher.sh -i 3600

# 启用 Slack 通知
./bin/cert-watcher.sh -w "https://hooks.slack.com/services/xxx"

# 自定义告警阈值
./bin/cert-watcher.sh --warning 14 --critical 7
```

## ⚙️ 配置

编辑 `config/certs.conf` 文件：

```bash
# 格式: host:port

# 常用 HTTPS 服务
google.com:443
github.com:443
cloudflare.com:443

# 本地服务
localhost:8443
localhost:443
```

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| CONFIG_FILE | 配置文件路径 | ./config/certs.conf |
| LOG_FILE | 日志文件路径 | ./log/cert-watcher.log |
| NOTIFY_WEBHOOK | Slack Webhook URL | - |

## 📋 命令行选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| -c, --config FILE | 配置文件路径 | ./config/certs.conf |
| -i, --interval SEC | 检测间隔秒数 | 86400 (24小时) |
| -t, --timeout SEC | 连接超时秒数 | 10 |
| -w, --webhook URL | 告警Webhook URL | - |
| --warning DAYS | 警告阈值天数 | 30 |
| --critical DAYS | 紧急阈值天数 | 7 |
| -h, --help | 显示帮助 | - |

## 📁 项目结构

```
cert-watcher/
├── bin/
│   └── cert-watcher.sh      # 主脚本
├── config/
│   └── certs.conf           # 证书配置
├── log/                     # 日志目录
│   └── .gitkeep
├── README.md
└── LICENSE
```

## 📝 日志

日志默认保存在 `./log/cert-watcher.log`，包含：
- 启动信息
- 证书检查结果
- 告警信息
- 错误信息

## 🔔 告警通知

支持 Slack Webhook：

```bash
./bin/cert-watcher.sh -w "https://hooks.slack.com/services/xxx"
```

告警消息会显示：
- 主机和端口
- 剩余天数
- 状态（OK/WARNING/CRITICAL）

## 📊 状态说明

| 状态 | 颜色 | 含义 |
|------|------|------|
| OK | 🟢 绿色 | 证书正常，剩余天数 > 警告阈值 |
| WARNING | 🟡 黄色 | 证书即将过期，剩余天数 ≤ 警告阈值 |
| CRITICAL | 🔴 红色 | 证书紧急过期，剩余天数 ≤ 紧急阈值 |

## 🔧 扩展

- [ ] 添加邮件通知支持
- [ ] 添加企业微信通知
- [ ] 添加 Prometheus 指标导出
- [ ] 添加证书详情展示（颁发者、域名等）

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 👤 作者

Chen Su

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！
