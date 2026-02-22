// src/security-guard.js
// Main controller: chains all modules, implements ProviderMiddleware interface

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

    // Policy loader
    this.#loader = new PolicyLoader(
      config.policy?.path ?? './policies',
      config.policy?.defaultEffect ?? 'deny'
    );

    // Rule engine
    this.#ruleEngine = new RuleEngine(this.#loader);

    // Budget controller (requires Redis)
    const agentConfigs = new Map(
      Object.entries(config.agents ?? {}).map(([id, cfg]) => [id, cfg])
    );
    this.#budgetController = new BudgetController(redis, agentConfigs);

    // Time window checker
    this.#timeChecker = new TimeChecker(this.#loader);

    // Audit logger
    this.#auditLogger = new AuditLogger({
      backend: config.storage?.auditLog?.backend ?? 'stdout',
      path: config.storage?.auditLog?.path,
      customPiiPatterns: config.pii?.customPatterns,
      onOverflow: (count) => {
        this.#alertManager?.send('audit_queue_overflow', 'CRITICAL', {
          message: `Audit queue overflow, dropped ${count} entries`,
          suggestion: 'Check if the storage backend is healthy',
        });
      },
    });

    // Alert manager
    this.#alertManager = new AlertManager(
      config.alerting?.channels ?? [],
      config.alerting?.suppressWindowMs ?? 300000
    );

    // Alert on policy load errors
    this.#loader.on('policy:error', (filePath, err) => {
      this.#alertManager.send('rule_denied', 'WARNING', {
        message: `Failed to load policy file: ${filePath} — ${err.message}`,
      });
    });
  }

  /** Initialize: load policies and start audit worker */
  async init() {
    await this.#loader.load();
    this.#auditLogger.start();
    this.#ready = true;
  }

  /**
   * Pre-request interceptor (ProviderMiddleware.beforeRequest)
   * @param {object} ctx  RequestContext (requestId is auto-generated if not provided)
   * @returns {Promise<{decision: string, ruleId?: string, reason?: string}>}
   */
  async beforeRequest(ctx) {
    // Fill in requestId and timestamp if not provided
    ctx.requestId = ctx.requestId ?? randomUUID();
    ctx.timestamp = ctx.timestamp ?? Date.now();

    if (!this.#ready) {
      return this.#failsafe('Plugin not initialized');
    }

    try {
      // 1. Rule engine
      const ruleResult = this.#ruleEngine.evaluate(ctx);
      if (ruleResult.decision === 'deny') {
        this.#auditLogger.enqueue(ctx, ruleResult);
        this.#sendDenyAlert(ctx, ruleResult, 'rule_denied');
        return ruleResult;
      }

      // 2. Domain filter
      const domainResult = this.#ruleEngine.evaluateDomain(ctx);
      if (domainResult?.decision === 'deny') {
        this.#auditLogger.enqueue(ctx, domainResult);
        this.#sendDenyAlert(ctx, domainResult, 'domain_blocked');
        return domainResult;
      }

      // 3. Budget / rate limit
      let budgetResult = { decision: 'allow' };
      if (this.#budgetController) {
        try {
          budgetResult = await this.#budgetController.check(ctx);
        } catch (err) {
          console.error('[SecurityGuard] Budget check failed:', err.message);
          budgetResult = this.#failsafe('Budget service unavailable');
        }
      }
      if (budgetResult.decision === 'deny') {
        this.#auditLogger.enqueue(ctx, budgetResult);
        this.#sendDenyAlert(ctx, budgetResult, 'rate_limit_triggered');
        return budgetResult;
      }

      // 4. Time window
      const timeResult = this.#timeChecker.check(ctx);
      if (timeResult?.decision === 'deny') {
        this.#auditLogger.enqueue(ctx, timeResult);
        this.#sendDenyAlert(ctx, timeResult, 'rule_denied');
        return timeResult;
      }

      // All checks passed
      this.#auditLogger.enqueue(ctx, { decision: 'allow' });
      return { decision: 'allow' };

    } catch (err) {
      console.error('[SecurityGuard] Check error:', err.message);
      return this.#failsafe('Internal error');
    }
  }

  /**
   * Post-request hook (ProviderMiddleware.afterRequest)
   * @param {object} ctx
   * @param {object} result  RequestResult
   */
  async afterRequest(ctx, result) {
    // Record response status in audit log
    this.#auditLogger.enqueue(ctx, { decision: 'allow' }, result);

    // Deduct budget
    if (this.#budgetController) {
      try {
        await this.#budgetController.deduct(ctx, result);
        // Check budget alert threshold
        const remaining = await this.#budgetController.getRemainingBudget(ctx.agentId);
        await this.#alertManager.checkBudgetAlert(ctx.agentId, remaining);
      } catch (err) {
        console.error('[SecurityGuard] Budget deduction failed:', err.message);
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
    return { decision: 'deny', reason: `[fail-closed] Security check unavailable: ${reason}` };
  }

  #sendDenyAlert(ctx, result, event) {
    this.#alertManager.send(event, 'INFO', {
      agentId: ctx.agentId,
      requestId: ctx.requestId,
      message: `Request denied: ${result.reason ?? event}`,
    }).catch(() => {});
  }

  // Expose internals for testing and CLI
  get loader() { return this.#loader; }
  get auditLogger() { return this.#auditLogger; }
  get alertManager() { return this.#alertManager; }
}
