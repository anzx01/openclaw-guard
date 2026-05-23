// SPDX-License-Identifier: MIT
// Copyright (c) 2026 OpenClaw Guard contributors
// src/alerting/alert-manager.js
// Real-time alert manager (async, with suppression window)

export class AlertManager {
  #channels;
  #suppressWindowMs;
  #suppressMap = new Map(); // event:agentId -> lastSentAt

  /**
   * @param {Array<{type: string, url?: string}>} channels
   * @param {number} suppressWindowMs  default 300000 (5 minutes)
   */
  constructor(channels = [], suppressWindowMs = 300000) {
    this.#channels = channels;
    this.#suppressWindowMs = suppressWindowMs;
  }

  /**
   * Send alert (async, non-blocking)
   * @param {string} event
   * @param {string} level  'INFO' | 'WARNING' | 'CRITICAL'
   * @param {object} data
   */
  async send(event, level, data = {}) {
    const suppressKey = `${event}:${data.agentId ?? ''}`;
    const now = Date.now();

    // CRITICAL alerts bypass suppression
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

    // Fire-and-forget, do not block
    for (const channel of this.#channels) {
      this.#sendToChannel(channel, alert).catch((err) => {
        console.error(`[SecurityGuard] Alert send failed (${channel.type}):`, err.message);
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

  /** Check remaining budget and send alert if below threshold */
  async checkBudgetAlert(agentId, remaining) {
    if (!remaining) return;
    const ratio = remaining.ratio ?? 1;
    if (ratio >= 0.2) return;

    const level = ratio <= 0 ? 'CRITICAL' : 'WARNING';
    const pct = Math.round(ratio * 100);
    await this.send('budget_threshold', level, {
      agentId,
      message: `Agent ${agentId} budget remaining: ${pct}% (used ${remaining.used}/${remaining.limit})`,
      suggestion: 'Check agent behavior or adjust budget config',
    });
  }
}
