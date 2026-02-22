# OpenClaw Guard 🛡️

Universal security control plugin for OpenClaw agents.

**Four core protections:**
- 💰 **No overspending** — Set token/call/money limits. Free use within limits; auto-block when exceeded.
- 📢 **No unauthorized posting** — POST/email actions denied by default; must be explicitly allowed in policy.
- 🗑️ **No file deletion** — All delete operations blocked globally.
- 🔒 **Tamper-proof** — Plugin files are completely locked; agents cannot modify them.

Zero telemetry. 100% local. MIT licensed.

---

## Install in OpenClaw (recommended)

### Option 1: One-click via clawhub.ai

In the OpenClaw chat, say:

```
install openclaw-guard from clawhub
```

Or search `openclaw-guard` in the OpenClaw settings. Hooks are registered automatically — no manual config needed.

---

### Option 2: Manual install (npm)

**Step 1: Install the package**

```bash
npm install -g openclaw-guard
```

**Step 2: Create a config file**

Create `security-config.yaml` in your project root:

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
    - type: stdout        # use webhook in production

failsafe:
  mode: fail-closed
```

**Step 3: Create the policy directory**

```bash
mkdir -p policies/agents
```

Copy the built-in policy examples from the npm package:

```bash
cp node_modules/openclaw-guard/policies/global-policy.yaml ./policies/
cp node_modules/openclaw-guard/policies/agents/llm-agent-policy.yaml ./policies/agents/
```

**Step 4: Register as an OpenClaw hook**

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

> If `openclaw-guard-hook` is not in PATH, use the full path:
> ```json
> "command": "node /path/to/node_modules/openclaw-guard/src/cli/hook.js"
> ```

**Step 5: Verify installation**

```bash
# Validate a policy file
openclaw-guard validate ./policies/global-policy.yaml

# Test the hook
echo '{"tool_name":"Delete","tool_input":{"file_path":"/tmp/test.txt"},"agent_id":"test"}' \
  | node node_modules/openclaw-guard/src/cli/hook.js
# Expected: {"hookSpecificOutput":{"permissionDecision":"deny",...}}
```

---

## Quick config: three scenarios

### Scenario 1: Control LLM spending

`policies/agents/llm-agent-policy.yaml`:

```yaml
version: "1"
scope: agent
target: "llm-agent"
defaultEffect: allow

budget:
  daily:
    tokens: 1000000    # 1M tokens/day — free use within limit
    calls: 500
  monthly:
    tokens: 20000000
  singleOp:
    tokens: 100000     # max 100K tokens per call

rateLimits:
  - action: "call:llm"
    window: 1m
    maxCount: 30       # max 30 calls/min
```

### Scenario 2: Prevent unauthorized posting

`policies/agents/social-agent-policy.yaml`:

```yaml
version: "1"
scope: agent
target: "social-agent"
defaultEffect: allow

rules:
  - id: deny-post
    priority: 1
    match:
      action: "call:*-api"
      params:
        method: "POST"
    effect: deny
    reason: "Auto-posting disabled; requires human approval"
```

### Scenario 3: Prevent file deletion

`policies/global-policy.yaml` — built-in, works out of the box:

```yaml
rules:
  - id: deny-delete-all
    priority: 1
    match:
      action: "delete:*"
    effect: deny
    reason: "All delete operations are blocked"
```

---

## Audit log

```bash
# View last 50 operations
openclaw-guard audit --limit 50

# View denied operations only
openclaw-guard audit --decision deny

# View operations for a specific agent
openclaw-guard audit --agent payment-agent --limit 100
```

---

## Alert configuration

Alerts fire automatically when budget is exceeded or a deny rule triggers. Supports webhook (Feishu / Slack / DingTalk):

```yaml
alerting:
  suppressWindowMs: 300000   # same alert fires at most once per 5 minutes
  channels:
    # Feishu
    - type: webhook
      url: "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
    # Slack
    - type: webhook
      url: "https://hooks.slack.com/services/xxx"
    # DingTalk
    - type: webhook
      url: "https://oapi.dingtalk.com/robot/send?access_token=xxx"
```

---

## Plugin tamper protection

This plugin protects its own files from agent modification. Any Write/Edit/Delete targeting files under `src/` is automatically blocked:

```
[SecurityGuard self-protection] Modification of plugin file denied: src/cli/hook.js.
Plugin files are immutable. To upgrade, reinstall via the official channel.
```

To upgrade:

```bash
npm install -g openclaw-guard@latest
# or update via clawhub
```

---

## How it works

Each request passes through the following pipeline:

```
Incoming request
  │
  ▼
[0] Plugin self-protection   ← Hardcoded, highest priority, cannot be bypassed
  │
  ▼
[1] Rule engine              ← allow/deny rules + domain filter
  │
  ▼
[2] Budget / rate limit      ← token/call/money limits
  │
  ▼
[3] Time window              ← block during off-hours or holidays
  │
  ▼
Execute request
  │
  ▼
[4] Audit log (async) + Alerts (async)
```

---

## Failsafe

| Mode | When Redis is unavailable | Use case |
|------|--------------------------|----------|
| `fail-closed` (default) | Deny all requests | Production — security first |
| `fail-open` | Allow and log error | Development / testing |

---

## Requirements

- Node.js ≥ 22.0.0
- Redis ≥ 6.0 (required for budget/rate features; omit with `fail-open` if not needed)

## License

MIT
