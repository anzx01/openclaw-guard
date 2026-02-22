#!/usr/bin/env node
// src/cli/index.js
// CLI entry point

import { createGuard, VERSION } from '../index.js';
import * as fs from 'fs';
import * as path from 'path';

const HELP = `
openclaw-guard v${VERSION}

Usage:
  openclaw-guard audit [--config <path>]     Query audit log
  openclaw-guard status [--config <path>]    Show budget status
  openclaw-guard validate <policy-file>      Validate policy file syntax
  openclaw-guard --help                      Show help
  openclaw-guard --version                   Show version

Options:
  --config <path>    Config file path (default: ./security-config.yaml)
  --agent <id>       Filter by agent ID
  --limit <n>        Return last N records (default: 50)
  --decision <v>     Filter by decision: allow | deny
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
    console.error('Error: config file not found. Use --config to specify a path, or create security-config.yaml in the current directory');
    process.exit(1);
  }

  if (cmd === 'audit') {
    await cmdAudit(configPath, args);
  } else if (cmd === 'status') {
    await cmdStatus(configPath, args);
  } else {
    console.error(`Unknown command: ${cmd}`);
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
      console.log('No audit log entries found');
    } else {
      console.log(`\nAudit log (last ${entries.length} entries):\n`);
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
      console.log('Please specify an agent ID with --agent <id>');
      return;
    }

    // Summarize recent decisions for this agent from audit log
    const entries = guard.auditLogger.query({ agentId, limit: 1000 });
    const total = entries.length;
    const denied = entries.filter((e) => e.decision === 'deny').length;
    const allowed = total - denied;

    console.log(`\nAgent ${agentId} status:\n`);
    console.log(`  Total audit records: ${total}`);
    console.log(`  Allowed: ${allowed}  Denied: ${denied}`);

    if (total > 0) {
      const last = entries[entries.length - 1];
      console.log(`  Latest: ${new Date(last.timestamp).toISOString()} action=${last.action} decision=${last.decision}`);
    }

    console.log(`\n  Queue depth: ${guard.auditLogger.queueDepth}  Overflow count: ${guard.auditLogger.overflowCount}`);
  } finally {
    await guard.close();
  }
}

async function cmdValidate(policyFile) {
  if (!policyFile) {
    console.error('Please specify a policy file: openclaw-guard validate <policy-file>');
    process.exit(1);
  }
  if (!fs.existsSync(policyFile)) {
    console.error(`File not found: ${policyFile}`);
    process.exit(1);
  }

  const { createRequire } = await import('module');
  const require = createRequire(import.meta.url);
  const yaml = require('js-yaml');

  try {
    const raw = fs.readFileSync(policyFile, 'utf-8');
    const data = yaml.load(raw);

    const errors = [];
    if (!data?.version) errors.push('Missing version field');
    if (!data?.scope) errors.push('Missing scope field');
    if (data?.scope === 'agent' && !data?.target) errors.push('target is required when scope=agent');
    for (const tr of data?.timeRestrictions ?? []) {
      if (!tr.schedule?.timezone) errors.push(`Time restriction ${tr.id} is missing timezone`);
    }

    if (errors.length > 0) {
      console.error('Policy validation failed:');
      errors.forEach((e) => console.error(`  - ${e}`));
      process.exit(1);
    } else {
      console.log(`✓ Policy file is valid: ${policyFile}`);
    }
  } catch (err) {
    console.error(`Policy file parse error: ${err.message}`);
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
  console.error('Error:', err.message);
  process.exit(1);
});
