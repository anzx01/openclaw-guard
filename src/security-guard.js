// src/security-guard.js
// 主控制器：串联所有模块，实现 ProviderMiddleware 接口

import { randomUUID } from 'crypto';
import { PolicyLoader } from './engine/policy-loader.js';
import { RuleEngine } from './engine/rule-engine.js';
import { BudgetController } from './budget/budget-controller.js';
import { TimeChecker } from './timewindow/time-checker.js';
import { AuditLogger } from './audit/audit-logger.js';
import { AlertManager } from './alerting/alert-manager.js';

export class SecurityGuard {
  #loader;
  #ruleEngine;
  #budgetController;
  #timeChecker;
  #auditLogger;
  #alertManager;
  #failsafeMode;
  #ready = false;

  /**
   * @param {object} config  SecurityGuardConfig
   * @param {import('ioredis').Redis} [redis]
   */
  constructor(config, redis = null) {
    this.#failsafeMode = config.failsafe?.mode ?? 'fail-closed';

    // 策略加载器
    this.#loader = new PolicyLoader(
      config.policy?.path ?? './policies',
      config.policy?.defaultEffect ?? 'deny'
    );

    // 规则引擎
    this.#ruleEngine = new RuleEngine(this.#loader);

    // 预算控制器（需要 Redis）
    const agentConfigs = new Map(
      Object.entries(config.agents ?? {}).map(([id, cfg]) => [id, cfg])
    );
    this.#budgetController = new BudgetController(redis, agentConfigs);

    // 时间窗口检查
    this.#timeChecker = new TimeChecker(this.#loader);

    // 审计日志
    this.#auditLogger = new AuditLogger({
      backend: config.storage?.auditLog?.backend ?? 'stdout',
      path: config.storage?.auditLog?.path,
      customPiiPatterns: config.pii?.customPatterns,
      onOverflow: (count) => {
        this.#alertManager?.send('audit_queue_overflow', 'CRITICAL', {
          message: `审计日志队列溢出，已丢弃 ${count} 条日志`,
          suggestion: '请检查存储后端是否正常',
        });
      },
    });

    // 告警管理器
    this.#alertManager = new AlertManager(
      config.alerting?.channels ?? [],
      config.alerting?.suppressWindowMs ?? 300000
    );

    // 策略加载错误告警
    this.#loader.on('policy:error', (filePath, err) => {
      this.#alertManager.send('rule_denied', 'WARNING', {
        message: `策略文件加载失败: ${filePath} — ${err.message}`,
      });
    });
  }

  /** 初始化：加载策略、启动审计 worker */
  async init() {
    await this.#loader.load();
    this.#auditLogger.start();
    this.#ready = true;
  }

  /**
   * 请求前拦截（ProviderMiddleware.beforeRequest）
   * @param {object} ctx  RequestContext（requestId 可选，未提供时自动生成）
   * @returns {Promise<{decision: string, ruleId?: string, reason?: string}>}
   */
  async beforeRequest(ctx) {
    // 补全 requestId 和 timestamp
    ctx.requestId = ctx.requestId ?? randomUUID();
    ctx.timestamp = ctx.timestamp ?? Date.now();

    if (!this.#ready) {
      return this.#failsafe('插件未初始化');
    }

    try {
      // 1. 规则引擎
      const ruleResult = this.#ruleEngine.evaluate(ctx);
      if (ruleResult.decision === 'deny') {
        this.#auditLogger.enqueue(ctx, ruleResult);
        this.#sendDenyAlert(ctx, ruleResult, 'rule_denied');
        return ruleResult;
      }

      // 2. 域名过滤
      const domainResult = this.#ruleEngine.evaluateDomain(ctx);
      if (domainResult?.decision === 'deny') {
        this.#auditLogger.enqueue(ctx, domainResult);
        this.#sendDenyAlert(ctx, domainResult, 'domain_blocked');
        return domainResult;
      }

      // 3. 预算/频率控制
      let budgetResult = { decision: 'allow' };
      if (this.#budgetController) {
        try {
          budgetResult = await this.#budgetController.check(ctx);
        } catch (err) {
          console.error('[SecurityGuard] 预算检查失败:', err.message);
          budgetResult = this.#failsafe('预算服务不可用');
        }
      }
      if (budgetResult.decision === 'deny') {
        this.#auditLogger.enqueue(ctx, budgetResult);
        this.#sendDenyAlert(ctx, budgetResult, 'rate_limit_triggered');
        return budgetResult;
      }

      // 4. 时间窗口
      const timeResult = this.#timeChecker.check(ctx);
      if (timeResult?.decision === 'deny') {
        this.#auditLogger.enqueue(ctx, timeResult);
        this.#sendDenyAlert(ctx, timeResult, 'rule_denied');
        return timeResult;
      }

      // 全部通过
      this.#auditLogger.enqueue(ctx, { decision: 'allow' });
      return { decision: 'allow' };

    } catch (err) {
      console.error('[SecurityGuard] 检查异常:', err.message);
      return this.#failsafe('内部错误');
    }
  }

  /**
   * 请求后钩子（ProviderMiddleware.afterRequest）
   * @param {object} ctx
   * @param {object} result  RequestResult
   */
  async afterRequest(ctx, result) {
    // 更新审计日志中的响应状态
    this.#auditLogger.enqueue(ctx, { decision: 'allow' }, result);

    // 扣减预算
    if (this.#budgetController) {
      try {
        await this.#budgetController.deduct(ctx, result);
        // 检查预算告警
        const remaining = await this.#budgetController.getRemainingBudget(ctx.agentId);
        await this.#alertManager.checkBudgetAlert(ctx.agentId, remaining);
      } catch (err) {
        console.error('[SecurityGuard] 预算扣减失败:', err.message);
      }
    }
  }

  /** Graceful shutdown */
  async close() {
    await this.#auditLogger.close();
    await this.#loader.close();
  }

  #failsafe(reason) {
    if (this.#failsafeMode === 'fail-open') {
      console.error(`[SecurityGuard] fail-open: ${reason}`);
      return { decision: 'allow', reason: `[fail-open] ${reason}` };
    }
    return { decision: 'deny', reason: `[fail-closed] 安全检查不可用: ${reason}` };
  }

  #sendDenyAlert(ctx, result, event) {
    this.#alertManager.send(event, 'INFO', {
      agentId: ctx.agentId,
      requestId: ctx.requestId,
      message: `请求被拒绝: ${result.reason ?? event}`,
    }).catch(() => {});
  }

  // 暴露内部组件供测试和 CLI 使用
  get loader() { return this.#loader; }
  get auditLogger() { return this.#auditLogger; }
  get alertManager() { return this.#alertManager; }
}
