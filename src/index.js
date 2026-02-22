// src/index.js
// 主入口 - 导出所有模块

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
  externalRequests: false,
  dataCollection: false,
};

/**
 * 工厂函数：从配置文件创建并初始化 SecurityGuard 实例
 * @param {string} configPath  security-config.yaml 路径
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
    throw new Error(`无法读取配置文件 ${configPath}: ${err.message}`);
  }

  let config;
  try {
    config = yaml.load(raw);
  } catch (err) {
    throw new Error(`配置文件格式错误: ${err.message}`);
  }

  // 全局未捕获异常处理，防止进程崩溃
  process.on('unhandledRejection', (reason) => {
    console.error('[SecurityGuard] 未处理的 Promise rejection:', reason);
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
      enableOfflineQueue: false,  // 连接断开时不排队，直接报错触发 failsafe
    });
    redis.on('error', (err) => {
      // 仅记录，不暴露内部细节给外部
      console.error('[SecurityGuard] Redis 连接错误');
    });
    // 尝试连接，失败时根据 failsafe 模式决定是否继续
    try {
      await redis.connect();
    } catch {
      const mode = config.failsafe?.mode ?? 'fail-closed';
      if (mode === 'fail-closed') {
        throw new Error('Redis 连接失败，fail-closed 模式下无法启动');
      }
      console.error('[SecurityGuard] Redis 连接失败，以 fail-open 模式运行（预算/频率控制不可用）');
      redis = null;
    }
  }

  const guard = new SecurityGuard(config, redis);
  await guard.init();
  return guard;
}

export default { VERSION, PRIVACY, createGuard };
