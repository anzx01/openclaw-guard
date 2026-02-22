# OpenClaw Guard 🛡️

Universal security control plugin for OpenClaw agents.

**四大核心保护：**
- 💰 **不乱花钱** — 设定 token/调用次数/金额上限，限额内随便用，超出自动阻断
- 📢 **不乱发帖** — 发帖/发邮件默认拒绝，需在策略中显式授权
- 🗑️ **不乱删文件** — 所有删除操作全局拦截
- 🔒 **插件防篡改** — 插件自身文件完全锁定，不可被代理修改

Zero telemetry. 100% local. MIT licensed.

---

## 在 OpenClaw 中安装（推荐）

### 方式一：通过 clawhub.ai 一键安装

在 OpenClaw 对话框中直接说：

```
install openclaw-guard from clawhub
```

或在 OpenClaw 设置界面搜索 `openclaw-guard` 安装。

安装完成后 OpenClaw 会自动注册钩子，**无需手动配置**。

---

### 方式二：手动安装（npm）

**第 1 步：安装包**

```bash
npm install -g openclaw-guard
```

**第 2 步：创建配置文件**

在你的项目根目录创建 `security-config.yaml`：

```yaml
redis:
  url: "redis://localhost:6379"   # 必须有 Redis

storage:
  auditLog:
    backend: file
    path: "./logs/audit"

policy:
  path: "./policies"
  defaultEffect: deny

alerting:
  channels:
    - type: stdout                # 开发环境用 stdout，生产环境改为 webhook

failsafe:
  mode: fail-closed
```

**第 3 步：创建策略目录**

```bash
mkdir -p policies/agents
```

复制内置策略示例（包含在 npm 包的 `policies/` 目录中）：

```bash
cp node_modules/openclaw-guard/policies/global-policy.yaml ./policies/
cp node_modules/openclaw-guard/policies/agents/llm-agent-policy.yaml ./policies/agents/
```

**第 4 步：注册为 OpenClaw 钩子**

编辑 `~/.openclaw/settings.json`，添加以下内容：

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

> 如果 `openclaw-guard-hook` 命令不在 PATH 中，使用完整路径：
> ```json
> "command": "node /path/to/node_modules/openclaw-guard/src/cli/hook.js"
> ```

**第 5 步：验证安装**

```bash
# 验证策略文件语法
openclaw-guard validate ./policies/global-policy.yaml

# 测试钩子是否正常工作
echo '{"tool_name":"Delete","tool_input":{"file_path":"/tmp/test.txt"},"agent_id":"test"}' \
  | node node_modules/openclaw-guard/src/cli/hook.js
# 预期输出：{"hookSpecificOutput":{"permissionDecision":"deny",...}}
```

---

## 快速配置：三个场景

### 场景 1：控制 LLM 花费

在 `policies/agents/llm-agent-policy.yaml` 中设置：

```yaml
version: "1"
scope: agent
target: "llm-agent"
defaultEffect: allow

budget:
  daily:
    tokens: 1000000    # 每日 100 万 token，超出自动阻断
    calls: 500
  monthly:
    tokens: 20000000   # 每月 2000 万 token
  singleOp:
    tokens: 100000     # 单次最多 10 万 token

rateLimits:
  - action: "call:llm"
    window: 1m
    maxCount: 30       # 每分钟最多 30 次，限额内随便调
```

### 场景 2：防止乱发帖

在 `policies/agents/social-agent-policy.yaml` 中设置：

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
    reason: "禁止自动发帖，需人工确认"
```

### 场景 3：防止乱删文件

`policies/global-policy.yaml` 已内置，开箱即用：

```yaml
rules:
  - id: deny-delete-all
    priority: 1
    match:
      action: "delete:*"
    effect: deny
    reason: "禁止任何删除操作"
```

---

## 查看审计日志

```bash
# 查看最近 50 条操作记录
openclaw-guard audit --limit 50

# 只看被拒绝的操作
openclaw-guard audit --decision deny

# 查看特定代理的操作
openclaw-guard audit --agent payment-agent --limit 100
```

---

## 告警配置

超出预算或触发拒绝规则时，自动发送告警。支持 Webhook（飞书/Slack/钉钉）：

```yaml
# security-config.yaml
alerting:
  suppressWindowMs: 300000   # 5 分钟内相同告警只发一次
  channels:
    # 飞书
    - type: webhook
      url: "https://open.feishu.cn/open-apis/bot/v2/hook/xxx"
    # Slack
    - type: webhook
      url: "https://hooks.slack.com/services/xxx"
    # 钉钉
    - type: webhook
      url: "https://oapi.dingtalk.com/robot/send?access_token=xxx"
```

---

## 插件防篡改说明

本插件会保护自身文件不被代理修改。任何对 `src/` 目录下文件的 Write/Edit/Delete 操作都会被自动拦截：

```
[SecurityGuard 自我保护] 禁止修改或删除插件文件: src/cli/hook.js。
插件文件不可修改，如需升级请通过官方渠道重新安装。
```

如需升级插件：

```bash
npm install -g openclaw-guard@latest
# 或通过 clawhub 更新
```

---

## How it works

每个请求依次经过：

```
请求进入
  │
  ▼
[0] 插件自身防篡改   ← 最高优先级，硬编码，不可绕过
  │
  ▼
[1] 规则引擎         ← allow/deny 规则 + 域名过滤
  │
  ▼
[2] 预算/频率控制    ← token/调用次数/金额上限
  │
  ▼
[3] 时间窗口         ← 凌晨/节假日封锁
  │
  ▼
执行请求
  │
  ▼
[4] 审计日志（异步） + 告警（异步）
```

---

## Failsafe

| 模式 | Redis 不可用时 | 适用场景 |
|------|--------------|----------|
| `fail-closed`（默认） | 拒绝所有请求 | 生产环境，安全优先 |
| `fail-open` | 放行并记录错误 | 开发/测试环境 |

---

## Requirements

- Node.js ≥ 22.0.0
- Redis ≥ 6.0（预算/频率功能必须；不需要预算控制时可省略，配合 `fail-open` 使用）

## License

MIT
