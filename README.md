# cert-watcher 🛡️

> TLS/SSL 证书到期监控工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-Required-blue.svg)](https://www.openssl.org/)
[![Platform](https://img.shields.io/badge/Platform-macOS%20|%20Linux-lightgrey.svg)](https://www.apple.com/macos/)

一个简单实用的 TLS/SSL 证书到期监控工具，自动检测证书过期时间，异常时发送告警通知。

## ✨ 特性

- 🔔 **智能告警** - 支持 Slack/钉钉 Webhook 通知
- ⏰ **灵活配置** - 支持按域名自定义告警阈值
- 🔄 **循环监控** - 支持定期自动检测
- 📊 **彩色输出** - 清晰的终端彩色状态展示
- 🔒 **安全可靠** - 使用 OpenSSL 获取证书信息
- 🛠️ **轻量简洁** - 纯 Bash 脚本，无依赖
- 📝 **详细日志** - 完整的运行日志记录

## 🏃 快速开始

### 环境要求

- Bash 4.0+
- OpenSSL
- curl (用于 Webhook 通知)

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
# 使用默认配置检测 (config/domains.conf)
./bin/cert-watcher.sh

# 单次检测后退出
./bin/cert-watcher.sh --once

# 指定配置文件
./bin/cert-watcher.sh -c /path/to/domains.conf

# 设置提前 14 天告警
./bin/cert-watcher.sh -d 14

# 启用 Slack 通知
./bin/cert-watcher.sh -w "https://hooks.slack.com/services/xxx"

# 设置检测间隔 (1 小时)
./bin/cert-watcher.sh -i 3600
```

## ⚙️ 配置

编辑 `config/domains.conf` 文件：

```bash
# 格式: domain[:port[:alert_days]]

# 基本用法 - 使用默认端口(443)和告警天数
example.com

# 自定义端口
example.com:8443

# 自定义告警天数 (提前 14 天告警)
example.com:443:14

# IP 地址
192.168.1.1:443
```

### 配置示例

```bash
# ============================================================
# 常用网站
# ============================================================
google.com
github.com

# ============================================================
# 国内网站
# ============================================================
baidu.com
aliyun.com

# ============================================================
# 自定义告警阈值
# ============================================================
# 重要站点 - 提前 30 天告警
payment.example.com:443:30

# 内部服务 - 提前 7 天告警
internal.example.com:8443:7
```

## 📋 命令行选项

| 选项 | 说明 | 默认值 |
|------|------|--------|
| -c, --config FILE | 配置文件路径 | ./config/domains.conf |
| -i, --interval SEC | 检测间隔秒数 | 86400 (24小时) |
| -w, --webhook URL | 告警 Webhook URL | - |
| -d, --days DAYS | 提前告警天数 | 30 |
| -p, --port PORT | 默认 HTTPS 端口 | 443 |
| -o, --once | 单次检测后退出 | false |
| -v, --version | 显示版本信息 | - |
| -h, --help | 显示帮助信息 | - |

## 📁 项目结构

```
cert-watcher/
├── bin/
│   └── cert-watcher.sh      # 主脚本
├── config/
│   └── domains.conf         # 域名配置
├── log/                      # 日志目录
│   └── .gitkeep
├── README.md                 # 说明文档
├── LICENSE                  # MIT 许可证
├── CHANGELOG.md             # 变更日志
└── .gitignore               # Git 忽略规则
```

## 🔔 告警通知

### Slack Webhook

```bash
./bin/cert-watcher.sh -w "https://hooks.slack.com/services/xxx"
```

### 钉钉 Webhook

```bash
./bin/cert-watcher.sh -w "https://oapi.dingtalk.com/robot/send?access_token=xxx"
```

## 📝 日志

日志默认保存在 `./log/cert-watcher.log`，包含：

- 启动/停止信息
- 证书检测结果
- 告警通知记录
- 错误信息

## 🔧 高级用法

### 定时任务 (crontab)

```bash
# 每天早上 9 点检测一次
0 9 * * * /path/to/cert-watcher/bin/cert-watcher.sh -c /path/to/cert-watcher/config/domains.conf -w "https://hooks.slack.com/services/xxx" -d 14 >> /var/log/cert-watcher.log 2>&1
```

### Docker 部署

```bash
docker run -d \
  --name cert-watcher \
  -v /path/to/domains.conf:/app/config/domains.conf \
  -e NOTIFY_WEBHOOK="https://hooks.slack.com/services/xxx" \
  -e ALERT_DAYS=14 \
  chen su/cert-watcher
```

### macOS LaunchAgent

创建 `~/Library/LaunchAgents/com.cert-watcher.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.cert-watcher</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/cert-watcher.sh</string>
        <string>-c</string>
        <string>/path/to/domains.conf</string>
        <string>-w</string>
        <string>https://hooks.slack.com/services/xxx</string>
    </array>
    <key>StartInterval</key>
    <integer>86400</integer>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
```

## 🎯 使用场景

- **DevOps** - 监控生产环境证书过期
- **安全审计** - 定期检查证书有效期
- **CI/CD** - 集成到发布流程
- **个人站点** - 管理多个域名证书

## 🤝 扩展计划

- [ ] 支持邮件通知
- [ ] 支持企业微信通知
- [ ] 支持 Prometheus 指标导出
- [ ] 支持多配置文件
- [ ] 添加 Web 界面
- [ ] 支持配置文件热重载

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件

## 👤 作者

Chen Su

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

如果您觉得这个项目有用，请给我一个 ⭐️
