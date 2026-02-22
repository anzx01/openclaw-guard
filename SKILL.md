---
name: openclaw-guard
description: Universal security control for OpenClaw agents. Prevents overspending (token/money budgets), unauthorized posting, file deletion, and protects itself from tampering. Zero telemetry, 100% local.
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - node
    install:
      - kind: node
        package: openclaw-guard
        bins: [openclaw-guard]
    emoji: "🛡️"
    homepage: https://github.com/myaist/openclaw-guard
    os:
      - macos
      - linux
      - windows
---

# OpenClaw Guard 🛡️

四大核心保护，开箱即用：

| 保护 | 说明 |
|------|------|
| 💰 不乱花钱 | 设定 token/调用次数/金额上限，限额内随便用，超出自动阻断 |
| 📢 不乱发帖 | 发帖/发邮件默认拒绝，需在策略中显式授权 |
| 🗑️ 不乱删文件 | 所有删除操作全局拦截 |
| 🔒 插件防篡改 | 插件自身文件完全锁定，不可被代理修改 |

## 安装

```bash
npm install -g openclaw-guard
```

## 注册为 OpenClaw 钩子

编辑 `~/.openclaw/settings.json`：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "openclaw-guard-hook",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

## 最小配置

创建 `security-config.yaml`：

```yaml
redis:
  url: "redis://localhost:6379"

storage:
  auditLog:
    backend: file
    path: "./logs/audit"

policy:
  path: "./policies"
  defaultEffect: deny

alerting:
  channels:
    - type: stdout

failsafe:
  mode: fail-closed
```

## 控制 LLM 花费示例

```yaml
# policies/agents/llm-agent-policy.yaml
version: "1"
scope: agent
target: "llm-agent"
defaultEffect: allow

budget:
  daily:
    tokens: 1000000    # 每日 100 万 token 上限
    calls: 500
  singleOp:
    tokens: 100000     # 单次最多 10 万 token

rateLimits:
  - action: "call:llm"
    window: 1m
    maxCount: 30
```

## 查看审计日志

```bash
openclaw-guard audit --limit 50
openclaw-guard audit --decision deny
```

## Links

- **Repository:** https://github.com/myaist/openclaw-guard
- **License:** MIT
- **Zero telemetry** — 无追踪，无网络请求，100% 本地运行
