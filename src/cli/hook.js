#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2026 OpenClaw Guard contributors
// src/cli/hook.js
// OpenClaw PreToolUse / before_tool_use hook entry point
// Receives JSON via stdin, outputs decision via stdout

import { createGuard } from '../index.js';
import * as path from 'path';
import * as fs from 'fs';
import { fileURLToPath } from 'url';

// ─── Plugin self-protection ─────────────────────────────────────
// Absolute path to this plugin root
const PLUGIN_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// Protected plugin files (relative to PLUGIN_ROOT)
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
 * Check if the target file is a protected plugin file.
 * @param {string} filePath
 * @returns {string|null} matched relative path, or null
 */
function isPluginFile(filePath) {
  if (!filePath) return null;
  const abs = path.resolve(filePath);
  for (const rel of PROTECTED_PLUGIN_FILES) {
    if (abs === path.join(PLUGIN_ROOT, rel)) return rel;
  }
  // Protect the entire src/ directory
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
  // Read stdin
  let raw = '';
  for await (const chunk of process.stdin) raw += chunk;

  let input;
  try {
    input = JSON.parse(raw);
  } catch {
    // Cannot parse input — intent unknown, deny (fail-closed)
    deny('[SecurityGuard] Cannot parse request, denied');
    return;
  }

  const toolName = input.tool_name ?? '';
  const toolInput = input.tool_input ?? {};
  const filePath = toolInput.file_path ?? toolInput.filePath ?? '';

  // ── Plugin self-protection (highest priority, before all other checks) ──────
  const matchedFile = isPluginFile(filePath);
  if (matchedFile) {
    const tool = toolName.toLowerCase();
    if (tool === 'write' || tool === 'edit' || tool === 'delete') {
      deny(`[SecurityGuard self-protection] Modification of plugin file denied: ${matchedFile}. Plugin files are immutable; reinstall via the official channel to upgrade.`);
      return;
    }
  }

  // Find config file (walk up from cwd)
  const configPath = findConfig();
  if (!configPath) {
    allow(); // No config found — allow
    return;
  }

  let guard;
  try {
    guard = await createGuard(configPath);
  } catch (err) {
    console.error('[SecurityGuard] Initialization failed:', err.message);
    allow();
    return;
  }

  // Map OpenClaw hook input to RequestContext
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
    deny(result.reason ?? 'Request denied by security policy');
  } else {
    allow();
  }
}

/** Map OpenClaw tool name to action string */
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

/** Walk up from cwd to find security-config.yaml */
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
  console.error('[SecurityGuard] Hook error:', err.message);
  process.exit(0); // On error, allow to avoid blocking all operations
});
