#!/usr/bin/env node
// src/cli/index.js
// CLI 工具入口

import { createGuard, VERSION } from '../index.js';
import * as fs from 'fs';
import * as path from 'path';

const HELP = `
openclaw-guard v${VERSION}

Usage:
  openclaw-guard audit [--config <path>]     查询审计日志
  openclaw-guard status [--config <path>]    查看预算状态
  openclaw-guard validate <policy-file>      验证策略文件语法
  openclaw-guard --help                      显示帮助
  openclaw-guard --version                   显示版本

Options:
  --config <path>    配置文件路径（默认: ./security-config.yaml）
  --agent <id>       过滤指定代理
  --limit <n>        返回最近 N 条记录（默认: 50）
  --decision <v>     过滤决策结果: allow | deny
`;

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    console.log(HELP);
    return;
  }

  if (args.includes('--version') || args.includes('-v')) {
    console.log(VERSION);
    return;
  }

  const cmd = args[0];
  const configPath = getArg(args, '--config') ?? findConfig();

  if (cmd === 'validate') {
    await cmdValidate(args[1]);
    return;
  }

  if (!configPath) {
    console.error('错误: 未找到配置文件。请使用 --config 指定路径，或在当前目录创建 security-config.yaml');
    process.exit(1);
  }

  if (cmd === 'audit') {
    await cmdAudit(configPath, args);
  } else if (cmd === 'status') {
    await cmdStatus(configPath, args);
  } else {
    console.error(`未知命令: ${cmd}`);
    console.log(HELP);
    process.exit(1);
  }
}

async function cmdAudit(configPath, args) {
  const guard = await createGuard(configPath);
  const filter = {
    agentId: getArg(args, '--agent'),
    decision: getArg(args, '--decision'),
    limit: parseInt(getArg(args, '--limit') ?? '50'),
  };

  try {
    const entries = guard.auditLogger.query(filter);
    if (entries.length === 0) {
      console.log('暂无审计日志记录');
    } else {
      console.log(`\n审计日志（最近 ${entries.length} 条）:\n`);
      for (const e of entries) {
        const time = new Date(e.timestamp).toISOString();
        const icon = e.decision === 'allow' ? '✓' : '✗';
        console.log(`${icon} [${time}] agent=${e.agentId} action=${e.action} decision=${e.decision}${e.ruleId ? ` rule=${e.ruleId}` : ''}${e.reason ? ` reason="${e.reason}"` : ''}`);
      }
    }
  } finally {
    await guard.close();
  }
}

async function cmdStatus(configPath, args) {
  const guard = await createGuard(configPath);
  const agentId = getArg(args, '--agent');

  try {
    if (!agentId) {
      console.log('请使用 --agent <id> 指定代理 ID');
      return;
    }

    // 从审计日志中统计该代理最近的决策分布
    const entries = guard.auditLogger.query({ agentId, limit: 1000 });
    const total = entries.length;
    const denied = entries.filter((e) => e.decision === 'deny').length;
    const allowed = total - denied;

    console.log(`\n代理 ${agentId} 状态:\n`);
    console.log(`  审计记录总数: ${total}`);
    console.log(`  放行: ${allowed}  拒绝: ${denied}`);

    if (total > 0) {
      const last = entries[entries.length - 1];
      console.log(`  最近操作: ${new Date(last.timestamp).toISOString()} action=${last.action} decision=${last.decision}`);
    }

    console.log(`\n  队列深度: ${guard.auditLogger.queueDepth}  溢出次数: ${guard.auditLogger.overflowCount}`);
  } finally {
    await guard.close();
  }
}

async function cmdValidate(policyFile) {
  if (!policyFile) {
    console.error('请指定策略文件路径: openclaw-guard validate <policy-file>');
    process.exit(1);
  }
  if (!fs.existsSync(policyFile)) {
    console.error(`文件不存在: ${policyFile}`);
    process.exit(1);
  }

  const { createRequire } = await import('module');
  const require = createRequire(import.meta.url);
  const yaml = require('js-yaml');

  try {
    const raw = fs.readFileSync(policyFile, 'utf-8');
    const data = yaml.load(raw);

    const errors = [];
    if (!data?.version) errors.push('缺少 version 字段');
    if (!data?.scope) errors.push('缺少 scope 字段');
    if (data?.scope === 'agent' && !data?.target) errors.push('scope=agent 时 target 必填');
    for (const tr of data?.timeRestrictions ?? []) {
      if (!tr.schedule?.timezone) errors.push(`时间规则 ${tr.id} 缺少 timezone`);
    }

    if (errors.length > 0) {
      console.error('策略文件验证失败:');
      errors.forEach((e) => console.error(`  - ${e}`));
      process.exit(1);
    } else {
      console.log(`✓ 策略文件验证通过: ${policyFile}`);
    }
  } catch (err) {
    console.error(`策略文件解析失败: ${err.message}`);
    process.exit(1);
  }
}

function getArg(args, name) {
  const i = args.indexOf(name);
  return i !== -1 && i + 1 < args.length ? args[i + 1] : null;
}

function findConfig() {
  const names = ['security-config.yaml', 'security-config.yml'];
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
  console.error('错误:', err.message);
  process.exit(1);
});
