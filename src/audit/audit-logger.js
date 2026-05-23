// SPDX-License-Identifier: MIT
// Copyright (c) 2026 OpenClaw Guard contributors
// src/audit/audit-logger.js
// Async audit logger (in-memory queue + background worker)

import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { PiiScrubber } from '../utils/pii-scrubber.js';

const QUEUE_MAX = 10000;
const FLUSH_INTERVAL_MS = 500;
const FLUSH_BATCH_SIZE = 100;

export class AuditLogger {
  #queue = [];
  #prevRequestId = null;
  #scrubber;
  #backend;
  #timer = null;
  #overflowCount = 0;
  #onOverflow;

  /**
   * @param {object} config
   * @param {string} config.backend  'file' | 'stdout'
   * @param {string} [config.path]   required when backend=file
   * @param {Array}  [config.customPiiPatterns]
   * @param {Function} [config.onOverflow]  callback on queue overflow
   */
  constructor(config = {}) {
    this.#scrubber = new PiiScrubber(config.customPiiPatterns ?? []);
    this.#backend = config.backend ?? 'stdout';
    this.#onOverflow = config.onOverflow ?? (() => {});

    if (this.#backend === 'file') {
      if (!config.path) throw new Error('path is required when backend=file');
      try {
        fs.mkdirSync(config.path, { recursive: true });
      } catch (err) {
        throw new Error(`Failed to create audit log directory ${config.path}: ${err.message}`);
      }
      this.filePath = path.join(config.path, 'audit.jsonl');
    }
  }

  start() {
    this.#timer = setInterval(() => this.#flush(), FLUSH_INTERVAL_MS);
    // Allow process to exit when only the timer remains
    this.#timer.unref?.();
  }

  /**
   * Enqueue an audit entry (non-blocking, < 1μs)
   * @param {import('../types.js').RequestContext} ctx
   * @param {import('../types.js').GuardResult} guardResult
   * @param {import('../types.js').RequestResult} [requestResult]
   */
  enqueue(ctx, guardResult, requestResult) {
    if (this.#queue.length >= QUEUE_MAX) {
      this.#queue.shift(); // Drop oldest entry
      this.#overflowCount++;
      this.#onOverflow(this.#overflowCount);
    }

    const entry = {
      requestId: ctx.requestId,
      prevRequestId: this.#prevRequestId,
      timestamp: ctx.timestamp,
      agentId: ctx.agentId,
      userId: ctx.userId,
      action: ctx.action,
      target: ctx.target ? this.#scrubber.scrub(ctx.target) : undefined,
      paramsHash: ctx.params
        ? createHash('sha256').update(JSON.stringify(ctx.params)).digest('hex')
        : undefined,
      decision: guardResult.decision,
      ruleId: guardResult.ruleId,
      riskScore: 0,
      budgetCost: requestResult?.budgetCost,
      responseStatus: requestResult?.status,
      latencyMs: requestResult?.latencyMs,
    };

    this.#prevRequestId = ctx.requestId;
    this.#queue.push(entry);
  }

  async #flush() {
    if (this.#queue.length === 0) return;
    const batch = this.#queue.splice(0, FLUSH_BATCH_SIZE);
    try {
      await this.#write(batch);
    } catch (err) {
      console.error('[SecurityGuard] Audit log write failed:', err.message);
      // On write failure, push batch back to queue head (up to QUEUE_MAX)
      this.#queue.unshift(...batch.slice(0, QUEUE_MAX - this.#queue.length));
    }
  }

  async #write(entries) {
    const lines = entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
    if (this.#backend === 'file') {
      try {
        fs.appendFileSync(this.filePath, lines, 'utf-8');
      } catch (err) {
        throw new Error(`Audit log write failed: ${err.message}`);
      }
    } else {
      process.stdout.write(lines);
    }
  }

  /**
   * Graceful shutdown: wait for queue to drain (up to 5 seconds)
   */
  async close() {
    clearInterval(this.#timer);
    const deadline = Date.now() + 5000;
    while (this.#queue.length > 0 && Date.now() < deadline) {
      await this.#flush();
      if (this.#queue.length > 0) {
        await new Promise((r) => setTimeout(r, 50));
      }
    }
  }

  /**
   * Query audit log (file backend only)
   * Reverse-scans from end to avoid OOM on large files
   * @param {{ agentId?: string, decision?: string, from?: number, to?: number, limit?: number }} filter
   */
  query(filter = {}) {
    if (this.#backend !== 'file') throw new Error('query is only supported with file backend');
    if (!fs.existsSync(this.filePath)) return [];

    const limit = filter.limit ?? 1000;
    const results = [];

    let content;
    try {
      content = fs.readFileSync(this.filePath, 'utf-8');
    } catch (err) {
      console.error('[SecurityGuard] Failed to read audit log:', err.message);
      return [];
    }

    const lines = content.split('\n');
    // Scan from end; stop once we have enough matching entries
    for (let i = lines.length - 1; i >= 0 && results.length < limit; i--) {
      const line = lines[i].trim();
      if (!line) continue;
      let entry;
      try { entry = JSON.parse(line); } catch { continue; }
      if (filter.agentId && entry.agentId !== filter.agentId) continue;
      if (filter.decision && entry.decision !== filter.decision) continue;
      if (filter.from && entry.timestamp < filter.from) continue;
      if (filter.to && entry.timestamp > filter.to) continue;
      results.unshift(entry);
    }
    return results;
  }

  get overflowCount() { return this.#overflowCount; }
  get queueDepth() { return this.#queue.length; }
}
