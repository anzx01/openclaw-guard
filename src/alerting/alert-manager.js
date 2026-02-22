// src/alerting/alert-manager.js
// 实时告警管理（异步，带频率抑制）

export class AlertManager {
  #channels;
  #suppressWindowMs;
  #suppressMap = new Map(); // event:agentId -> lastSentAt

  /**
   * @param {Array<{type: string, url?: string}>} channels
   * @param {number} suppressWindowMs  默认 300000 (5分钟)
   */
  constructor(channels = [], suppressWindowMs = 300000) {
    this.#channels = channels;
    this.#suppressWindowMs = suppressWindowMs;
  }

  /**
   * 检查并发送告警（异步，不阻塞主链路）
   * @param {string} event
   * @param {string} level  'INFO' | 'WARNING' | 'CRITICAL'
   * @param {object} data
   */
  async send(event, level, data = {}) {
    const suppressKey = `${event}:${data.agentId ?? ''}`;
    const now = Date.now();

    // CRITICAL 不受抑制
    if (level !== 'CRITICAL') {
      const lastSent = this.#suppressMap.get(suppressKey) ?? 0;
      if (now - lastSent < this.#suppressWindowMs) return;
    }

    this.#suppressMap.set(suppressKey, now);

    const alert = {
      level,
      event,
      agentId: data.agentId,
      message: data.message ?? event,
      timestamp: new Date().toISOString(),
      auditRequestId: data.requestId,
      suggestion: data.suggestion,
    };

    // 异步发送，不等待结果
    for (const channel of this.#channels) {
      this.#sendToChannel(channel, alert).catch((err) => {
        console.error(`[SecurityGuard] 告警发送失败 (${channel.type}):`, err.message);
      });
    }
  }

  async #sendToChannel(channel, alert) {
    if (channel.type === 'webhook' && channel.url) {
      const res = await fetch(channel.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(alert),
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } else if (channel.type === 'stdout') {
      process.stderr.write(`[ALERT] ${JSON.stringify(alert)}\n`);
    }
  }

  /** 检查预算剩余并在需要时发送告警 */
  async checkBudgetAlert(agentId, remaining) {
    if (!remaining) return;
    const ratio = remaining.ratio ?? 1;
    if (ratio >= 0.2) return;

    const level = ratio <= 0 ? 'CRITICAL' : 'WARNING';
    const pct = Math.round(ratio * 100);
    await this.send('budget_threshold', level, {
      agentId,
      message: `代理 ${agentId} 预算剩余 ${pct}%（已用 ${remaining.used}/${remaining.limit}）`,
      suggestion: '请检查代理行为或调整预算配置',
    });
  }
}
