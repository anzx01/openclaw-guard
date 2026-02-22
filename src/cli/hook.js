#!/usr/bin/env node
// src/cli/hook.js
// OpenClaw PreToolUse / before_tool_use 钩子入口
// 通过 stdin 接收 JSON，通过 stdout 输出决策

import { createGuard } from '../index.js';
import * as path from 'path';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

// ─── 插件自身防篡改 ───────────────────────────────────────────
// 获取本插件的根目录（绝对路径）
const PLUGIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// 插件核心文件列表（相对于 PLUGIN_ROOT）
const PROTECTED_PLUGIN_FILES = [
  'src/cli/hook.js',
  'src/cli/index.js',
  'src/index.js',
  'src/security-guard.js',
  'src/engine/policy-loader.js',
  'src/engine/rule-engine.js',
  'src/budget/budget-controller.js',
  'src/timewindow/time-checker.js',
  'src/audit/audit-logger.js',
  'src/alerting/alert-manager.js',
  'src/utils/pii-scrubber.js',
  'openclaw.plugin.json',
  'SKILL.md',
];

/**
 * 检查目标文件是否是插件自身的受保护文件
 * @param {string} filePath
 * @returns {string|null} 匹配的相对路径，或 null
 */
function isPluginFile(filePath) {
  if (!filePath) return null;
  const abs = path.resolve(filePath);
  for (const rel of PROTECTED_PLUGIN_FILES) {
    if (abs === path.join(PLUGIN_ROOT, rel)) return rel;
  }
  // 保护整个 src/ 目录
  const srcDir = path.join(PLUGIN_ROOT, 'src');
  if (abs.startsWith(srcDir + path.sep)) {
    return path.relative(PLUGIN_ROOT, abs);
  }
  return null;
}

function deny(reason) {
  const output = {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  };
  process.stdout.write(JSON.stringify(output));
}

function allow() {
  process.exit(0);
}

async function main() {
  // 读取 stdin
  let raw = '';
  for await (const chunk of process.stdin) raw += chunk;

  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    // JSON 解析失败：无法判断意图，fail-closed 拒绝
    deny('[SecurityGuard] 无法解析请求，已拒绝');
    return;
  }

  const toolName = input.tool_name ?? '';
  const toolInput = input.tool_input ?? {};
  const filePath = toolInput.file_path ?? toolInput.filePath ?? '';

  // ── 插件自身防篡改检查（最高优先级，在所有其他检查之前）──────
  const matchedFile = isPluginFile(filePath);
  if (matchedFile) {
    const tool = toolName.toLowerCase();
    if (tool === 'write' || tool === 'edit' || tool === 'delete') {
      deny(`[SecurityGuard 自我保护] 禁止修改或删除插件文件: ${matchedFile}。插件文件不可修改，如需升级请通过官方渠道重新安装。`);
      return;
    }
  }

  // 查找配置文件（从当前目录向上查找）
  const configPath = findConfig();
  if (!configPath) {
    allow(); // 无配置时放行
    return;
  }

  let guard;
  try {
    guard = await createGuard(configPath);
  } catch (err) {
    console.error('[SecurityGuard] 初始化失败:', err.message);
    allow();
    return;
  }

  // 将 OpenClaw hook 输入转换为 RequestContext
  const agentId = input.agent_id ?? input.agentId ?? 'unknown';

  const ctx = {
    agentId,
    userId: input.user_id ?? input.userId,
    action: mapToolToAction(toolName, toolInput),
    target: toolInput.url ?? filePath ?? toolInput.command,
    params: toolInput,
    timestamp: Date.now(),
  };

  const result = await guard.beforeRequest(ctx);
  await guard.close();

  if (result.decision === 'deny') {
    deny(result.reason ?? '请求被安全策略拒绝');
  } else {
    allow();
  }
}

/** 将 OpenClaw 工具名映射为 action 格式 */
function mapToolToAction(toolName, toolInput) {
  const tool = toolName.toLowerCase();
  if (tool === 'write' || tool === 'edit') return `write:file`;
  if (tool === 'read') return `read:file`;
  if (tool === 'bash' || tool === 'execute') return `execute:shell`;
  if (tool === 'webrequest' || tool === 'fetch' || tool === 'httprequest') return `call:http`;
  if (tool === 'delete') return `delete:file`;
  if (toolInput?.url) return `call:http`;
  return `tool:${tool}`;
}

/** 从当前目录向上查找 security-config.yaml */
function findConfig() {
  const names = ['security-config.yaml', 'security-config.yml', '.security-guard.yaml'];
  let dir = process.cwd();
  for (let i = 0; i < 5; i++) {
    for (const name of names) {
      const p = path.join(dir, name);
      if (fs.existsSync(p)) return p;
    }
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

main().catch((err) => {
  console.error('[SecurityGuard] 钩子异常:', err.message);
  process.exit(0); // 异常时放行，避免阻断所有操作
});
