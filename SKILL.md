---
name: openclaw-guard
description: Universal security control for OpenClaw agents. Prevents overspending (token/money budgets), unauthorized posting, file deletion, and protects itself from tampering. No telemetry by default; webhook alerts only if configured.
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

Four core protections, ready out of the box:

| Protection | Description |
|------------|-------------|
| 💰 No overspending | Set token/call/money limits. Free use within limits; auto-block when exceeded. |
| 📢 No unauthorized posting | POST/email denied by default; must be explicitly allowed in policy. |
| 🗑️ No file deletion | All delete operations blocked globally. |
| 🔒 Tamper-proof | Plugin files are completely locked; agents cannot modify them. |

## Install

```bash
npm install -g openclaw-guard
```

## Register as an OpenClaw hook

Edit `~/.openclaw/settings.json`:

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

## Minimal config

Create `security-config.yaml`:

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

## Control LLM spending

```yaml
# policies/agents/llm-agent-policy.yaml
version: "1"
scope: agent
target: "llm-agent"
defaultEffect: allow

budget:
  daily:
    tokens: 1000000    # 1M tokens/day limit
    calls: 500
  singleOp:
    tokens: 100000     # max 100K tokens per call

rateLimits:
  - action: "call:llm"
    window: 1m
    maxCount: 30
```

## View audit log

```bash
openclaw-guard audit --limit 50
openclaw-guard audit --decision deny
```

## Links

- **Repository:** https://github.com/myaist/openclaw-guard
- **License:** MIT
- **Privacy:** no telemetry or tracking; outbound requests only occur for user-configured alert webhooks
