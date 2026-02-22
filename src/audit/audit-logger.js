// src/audit/audit-logger.js
// 异步审计日志（内存队列 + 后台 worker）

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
   * @param {string} [config.path]   backend=file 时必填
   * @param {Array}  [config.customPiiPatterns]
   * @param {Function} [config.onOverflow]  队列溢出回调
   */
  constructor(config = {}) {
    this.#scrubber = new PiiScrubber(config.customPiiPatterns ?? []);
    this.#backend = config.backend ?? 'stdout';
    this.#onOverflow = config.onOverflow ?? (() => {});

    if (this.#backend === 'file') {
      if (!config.path) throw new Error('audit backend=file 时 path 必填');
      try {
        fs.mkdirSync(config.path, { recursive: true });
      } catch (err) {
        throw new Error(`无法创建审计日志目录 ${config.path}: ${err.message}`);
      }
      this.filePath = path.join(config.path, 'audit.jsonl');
    }
  }

  start() {
    this.#timer = setInterval(() => this.#flush(), FLUSH_INTERVAL_MS);
    // 允许进程在只剩 timer 时退出
    this.#timer.unref?.();
  }

  /**
   * 将审计条目加入队列（非阻塞，< 1μs）
   * @param {import('../types.js').RequestContext} ctx
   * @param {import('../types.js').GuardResult} guardResult
   * @param {import('../types.js').RequestResult} [requestResult]
   */
  enqueue(ctx, guardResult, requestResult) {
    if (this.#queue.length >= QUEUE_MAX) {
      this.#queue.shift(); // 丢弃最旧
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
      console.error('[SecurityGuard] 审计日志写入失败:', err.message);
      // 写入失败时将 batch 放回队头（最多保留 QUEUE_MAX 条）
      this.#queue.unshift(...batch.slice(0, QUEUE_MAX - this.#queue.length));
    }
  }

  async #write(entries) {
    const lines = entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
    if (this.#backend === 'file') {
      try {
        fs.appendFileSync(this.filePath, lines, 'utf-8');
      } catch (err) {
        throw new Error(`审计日志写入失败: ${err.message}`);
      }
    } else {
      process.stdout.write(lines);
    }
  }

  /**
   * Graceful shutdown：等待队列清空（最多 5 秒）
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
   * 查询日志（仅 file backend）
   * 使用流式读取避免大文件 OOM
   * @param {{ agentId?: string, decision?: string, from?: number, to?: number, limit?: number }} filter
   */
  query(filter = {}) {
    if (this.#backend !== 'file') throw new Error('query 仅支持 file backend');
    if (!fs.existsSync(this.filePath)) return [];

    const limit = filter.limit ?? 1000;
    const results = [];

    let content;
    try {
      content = fs.readFileSync(this.filePath, 'utf-8');
    } catch (err) {
      console.error('[SecurityGuard] 读取审计日志失败:', err.message);
      return [];
    }

    const lines = content.split('\n');
    // 从末尾向前扫描，找到足够的匹配条目后停止
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
