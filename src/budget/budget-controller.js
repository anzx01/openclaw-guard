// src/budget/budget-controller.js
// 预算与频率控制器（Redis 原子操作）

import { createHash } from 'crypto';

/** 将 "1m" / "1h" / "1s" 转换为毫秒 */
function parseWindow(w) {
  const n = parseInt(w);
  if (w.endsWith('s')) return n * 1000;
  if (w.endsWith('m')) return n * 60 * 1000;
  if (w.endsWith('h')) return n * 3600 * 1000;
  throw new Error(`无效的时间窗口格式: ${w}`);
}

/** Redis Lua 脚本：原子 check-and-increment */
const LUA_CHECK_INCR = `
local key = KEYS[1]
local limit = tonumber(ARGV[1])
local cost  = tonumber(ARGV[2])
local ttl   = tonumber(ARGV[3])
local current = tonumber(redis.call('GET', key) or 0)
if current + cost > limit then
  return -1
end
local new = redis.call('INCRBY', key, cost)
if new == cost then
  redis.call('EXPIRE', key, ttl)
end
return new
`;

export class BudgetController {
  /**
   * @param {import('ioredis').Redis} redis
   * @param {Map<string, object>} agentConfigs  agentId -> AgentBudgetConfig
   */
  constructor(redis, agentConfigs = new Map()) {
    this.redis = redis;
    this.agentConfigs = agentConfigs;
  }

  /**
   * 检查预算与频率限制
   * @param {import('../types.js').RequestContext} ctx
   * @returns {Promise<import('../types.js').GuardResult>}
   */
  async check(ctx) {
    const config = this.agentConfigs.get(ctx.agentId);
    if (!config) return { decision: 'allow' };

    // 1. 频率限制检查
    if (config.rateLimits) {
      for (const rl of config.rateLimits) {
        if (!this.#matchAction(ctx.action, rl.action)) continue;
        const result = await this.#checkRateLimit(ctx, rl);
        if (result.decision === 'deny') return result;
      }
    }

    // 2. 单次操作预算检查（仅资金类）
    if (config.budget?.singleOp) {
      const cost = this.#extractCost(ctx);
      const limit = config.budget.singleOp;
      if (cost.moneyCny && limit.moneyCny && cost.moneyCny > limit.moneyCny) {
        return { decision: 'deny', reason: `单笔金额 ${cost.moneyCny} 超过限额 ${limit.moneyCny} CNY` };
      }
    }

    // 3. 每日预算检查
    if (config.budget?.daily) {
      const result = await this.#checkBudget(ctx, 'daily', config.budget.daily);
      if (result.decision === 'deny') return result;
    }

    // 4. 每月预算检查
    if (config.budget?.monthly) {
      const result = await this.#checkBudget(ctx, 'monthly', config.budget.monthly);
      if (result.decision === 'deny') return result;
    }

    return { decision: 'allow' };
  }

  /**
   * 请求成功后扣减预算
   * @param {import('../types.js').RequestContext} ctx
   * @param {import('../types.js').RequestResult} result
   */
  async deduct(ctx, result) {
    if (result.status !== 'success') return;
    const config = this.agentConfigs.get(ctx.agentId);
    if (!config?.budget) return;

    const cost = result.budgetCost ?? this.#extractCost(ctx);
    const now = new Date();

    if (config.budget.daily) {
      await this.#deductBudget(ctx.agentId, 'daily', this.#dailyKey(now), cost, this.#dailyTTL(now));
    }
    if (config.budget.monthly) {
      await this.#deductBudget(ctx.agentId, 'monthly', this.#monthlyKey(now), cost, this.#monthlyTTL(now));
    }
  }

  // ─── 频率限制（滑动窗口，Redis Sorted Set）─────────────────

  async #checkRateLimit(ctx, rl) {
    const windowMs = parseWindow(rl.window);
    const now = Date.now();
    const key = `guard:rate:${ctx.agentId}:${rl.action}:${rl.window}`;

    // 幂等键防重复计数
    const idempotencyKey = this.#idempotencyKey(ctx);

    const pipeline = this.redis.pipeline();
    pipeline.zremrangebyscore(key, 0, now - windowMs);
    pipeline.zcard(key);
    pipeline.zadd(key, 'NX', now, idempotencyKey);
    pipeline.expire(key, Math.ceil(windowMs / 1000) + 1);
    const results = await pipeline.exec();

    const count = results[1][1];
    if (count >= rl.maxCount) {
      return {
        decision: 'deny',
        reason: `操作 ${rl.action} 超过频率限制：${rl.window} 内最多 ${rl.maxCount} 次`,
      };
    }
    return { decision: 'allow' };
  }

  // ─── 预算检查（Lua 原子操作）──────────────────────────────

  async #checkBudget(ctx, period, limit) {
    const now = new Date();
    const periodKey = period === 'daily' ? this.#dailyKey(now) : this.#monthlyKey(now);
    const ttl = period === 'daily' ? this.#dailyTTL(now) : this.#monthlyTTL(now);
    const cost = this.#extractCost(ctx);

    // 检查 token 预算
    if (limit.tokens && cost.tokens) {
      const key = `guard:budget:${ctx.agentId}:${period}:tokens:${periodKey}`;
      const r = await this.redis.eval(LUA_CHECK_INCR, 1, key, limit.tokens, cost.tokens, ttl);
      if (r === -1) return { decision: 'deny', reason: `${period} token 预算已耗尽` };
    }

    // 检查调用次数预算
    if (limit.calls) {
      const key = `guard:budget:${ctx.agentId}:${period}:calls:${periodKey}`;
      const r = await this.redis.eval(LUA_CHECK_INCR, 1, key, limit.calls, 1, ttl);
      if (r === -1) return { decision: 'deny', reason: `${period} 调用次数预算已耗尽` };
    }

    return { decision: 'allow' };
  }

  async #deductBudget(agentId, period, periodKey, cost, ttl) {
    const pipeline = this.redis.pipeline();
    if (cost.tokens) {
      pipeline.incrby(`guard:budget:${agentId}:${period}:tokens:${periodKey}`, cost.tokens);
      pipeline.expire(`guard:budget:${agentId}:${period}:tokens:${periodKey}`, ttl);
    }
    if (cost.calls !== undefined) {
      pipeline.incr(`guard:budget:${agentId}:${period}:calls:${periodKey}`);
      pipeline.expire(`guard:budget:${agentId}:${period}:calls:${periodKey}`, ttl);
    }
    await pipeline.exec();
  }

  // ─── 剩余预算查询（用于告警）─────────────────────────────

  async getRemainingBudget(agentId) {
    const config = this.agentConfigs.get(agentId);
    if (!config?.budget?.daily) return null;
    const now = new Date();
    const key = `guard:budget:${agentId}:daily:calls:${this.#dailyKey(now)}`;
    const used = parseInt(await this.redis.get(key) ?? '0');
    const limit = config.budget.daily.calls ?? Infinity;
    return { used, limit, remaining: limit - used, ratio: used / limit };
  }

  // ─── 辅助方法 ─────────────────────────────────────────────

  #matchAction(action, pattern) {
    if (pattern === '*') return true;
    if (pattern === action) return true;
    const [pVerb, pTarget] = pattern.split(':');
    const [aVerb, aTarget] = action.split(':');
    if (pVerb !== aVerb && pVerb !== '*') return false;
    if (pTarget === '*' || !pTarget) return true;
    return pTarget === aTarget;
  }

  #extractCost(ctx) {
    return {
      tokens: ctx.params?.tokens ? Number(ctx.params.tokens) : undefined,
      calls: 1,
      moneyCny: ctx.params?.amount ? Number(ctx.params.amount) : undefined,
    };
  }

  #idempotencyKey(ctx) {
    const raw = `${ctx.agentId}:${ctx.action}:${Math.floor(ctx.timestamp / 60000)}`;
    return createHash('sha256').update(raw).digest('hex').slice(0, 16);
  }

  #dailyKey(date) {
    return `${date.getUTCFullYear()}${String(date.getUTCMonth() + 1).padStart(2, '0')}${String(date.getUTCDate()).padStart(2, '0')}`;
  }

  #monthlyKey(date) {
    return `${date.getUTCFullYear()}${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
  }

  #dailyTTL(date) {
    const tomorrow = new Date(date);
    tomorrow.setUTCDate(tomorrow.getUTCDate() + 1);
    tomorrow.setUTCHours(0, 0, 0, 0);
    return Math.ceil((tomorrow - date) / 1000) + 60;
  }

  #monthlyTTL(date) {
    const nextMonth = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1));
    return Math.ceil((nextMonth - date) / 1000) + 60;
  }
}
