// SPDX-License-Identifier: MIT
// Copyright (c) 2026 OpenClaw Guard contributors
// src/index.js
// Main entry — exports all modules

export { SecurityGuard } from './security-guard.js';
export { PolicyLoader } from './engine/policy-loader.js';
export { RuleEngine } from './engine/rule-engine.js';
export { BudgetController } from './budget/budget-controller.js';
export { TimeChecker } from './timewindow/time-checker.js';
export { AuditLogger } from './audit/audit-logger.js';
export { AlertManager } from './alerting/alert-manager.js';
export { PiiScrubber } from './utils/pii-scrubber.js';

export const VERSION = '1.0.0';
export const PRIVACY = {
  telemetry: false,
  tracking: false,
  dataCollection: false,
  externalRequestsByDefault: false,
  userConfiguredExternalRequests: ['alert-webhook'],
};

/**
 * Factory function: create and initialize a SecurityGuard from a config file
 * @param {string} configPath  path to security-config.yaml
 * @returns {Promise<SecurityGuard>}
 */
export async function createGuard(configPath = './security-config.yaml') {
  const { createRequire } = await import('module');
  const require = createRequire(import.meta.url);
  const yaml = require('js-yaml');
  const fs = await import('fs');

  let raw;
  try {
    raw = fs.readFileSync(configPath, 'utf-8');
  } catch (err) {
    throw new Error(`Cannot read config file ${configPath}: ${err.message}`);
  }

  let config;
  try {
    config = yaml.load(raw);
  } catch (err) {
    throw new Error(`Config file parse error: ${err.message}`);
  }

  // Global unhandled rejection handler to prevent process crash
  process.on('unhandledRejection', (reason) => {
    console.error('[SecurityGuard] Unhandled Promise rejection:', reason);
  });

  let redis = null;
  if (config.redis?.url) {
    const { default: Redis } = await import('ioredis');
    redis = new Redis(config.redis.url, {
      tls: config.redis.tls ? {} : undefined,
      password: config.redis.password,
      lazyConnect: true,
      maxRetriesPerRequest: 2,
      connectTimeout: 3000,
      enableOfflineQueue: false,  // Do not queue when disconnected; fail immediately to trigger failsafe
    });
    redis.on('error', (err) => {
      // Log only; do not expose internal details
      console.error('[SecurityGuard] Redis connection error');
    });
    // Attempt connection; on failure apply failsafe mode
    try {
      await redis.connect();
    } catch {
      const mode = config.failsafe?.mode ?? 'fail-closed';
      if (mode === 'fail-closed') {
        throw new Error('Redis connection failed; cannot start in fail-closed mode');
      }
      console.error('[SecurityGuard] Redis unavailable; running in fail-open mode (budget/rate control disabled)');
      redis = null;
    }
  }

  const guard = new SecurityGuard(config, redis);
  await guard.init();
  return guard;
}

export default { VERSION, PRIVACY, createGuard };
