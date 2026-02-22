// src/engine/rule-engine.js
// 规则匹配与决策

import micromatch from 'micromatch';

export class RuleEngine {
  /** @param {import('./policy-loader.js').PolicyLoader} loader */
  constructor(loader) {
    this.loader = loader;
  }

  /**
   * 评估请求是否允许
   * @param {import('../types.js').RequestContext} ctx
   * @returns {import('../types.js').GuardResult}
   */
  evaluate(ctx) {
    const policies = this.loader.getPoliciesFor(ctx.agentId);

    const matched = [];
    for (let pi = 0; pi < policies.length; pi++) {
      for (const rule of policies[pi].rules) {
        if (this.#matchRule(rule, ctx)) {
          matched.push({ rule, policyIndex: pi });
        }
      }
    }

    if (matched.length === 0) {
      const defaultEffect = policies[0]?.defaultEffect ?? 'deny';
      return { decision: defaultEffect === 'allow' ? 'allow' : 'deny', reason: '无匹配规则，使用默认策略' };
    }

    // 排序：priority 小的优先；同 priority 时 deny 优先；细粒度策略优先
    matched.sort((a, b) => {
      if (a.rule.priority !== b.rule.priority) return a.rule.priority - b.rule.priority;
      if (a.rule.effect !== b.rule.effect) return a.rule.effect === 'deny' ? -1 : 1;
      return a.policyIndex - b.policyIndex;
    });

    const { rule } = matched[0];
    return {
      decision: rule.effect === 'allow' ? 'allow' : 'deny',
      ruleId: rule.id,
      reason: rule.reason,
    };
  }

  /**
   * 域名过滤（仅对含 URL 的请求生效）
   * @param {import('../types.js').RequestContext} ctx
   * @returns {import('../types.js').GuardResult|null}
   */
  evaluateDomain(ctx) {
    if (!ctx.target) return null;

    let hostname;
    try {
      hostname = new URL(ctx.target).hostname;
    } catch {
      return null;
    }

    for (const policy of this.loader.getPoliciesFor(ctx.agentId)) {
      if (!policy.domainFilter) continue;
      const { mode, list } = policy.domainFilter;
      const matched = list.some((p) => micromatch.isMatch(hostname, p));

      if (mode === 'whitelist' && !matched) {
        return { decision: 'deny', reason: `域名 ${hostname} 不在白名单中` };
      }
      if (mode === 'blacklist' && matched) {
        return { decision: 'deny', reason: `域名 ${hostname} 命中黑名单` };
      }
    }
    return null;
  }

  #matchRule(rule, ctx) {
    if (!micromatch.isMatch(ctx.action, rule.match.action)) return false;
    if (rule.match.target && ctx.target) {
      if (!micromatch.isMatch(ctx.target, rule.match.target)) return false;
    }
    if (rule.match.params && ctx.params) {
      for (const [key, pattern] of Object.entries(rule.match.params)) {
        if (!micromatch.isMatch(String(ctx.params[key] ?? ''), pattern)) return false;
      }
    }
    return true;
  }
}
