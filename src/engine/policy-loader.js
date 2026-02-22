// src/engine/policy-loader.js
// 策略文件加载、热更新、版本管理

import * as fs from 'fs';
import * as path from 'path';
import { createRequire } from 'module';
import { EventEmitter } from 'events';
import chokidar from 'chokidar';

const require = createRequire(import.meta.url);
const yaml = require('js-yaml');

const MAX_SNAPSHOTS = 10;

export class PolicyLoader extends EventEmitter {
  /** @type {Map<string, object>} */
  #policies = new Map();
  /** @type {Map<string, Array>} */
  #snapshots = new Map();
  #watcher = null;
  #policyDir;
  #defaultEffect;

  constructor(policyDir, defaultEffect = 'deny') {
    super();
    this.#policyDir = policyDir;
    this.#defaultEffect = defaultEffect;
  }

  async load() {
    if (!fs.existsSync(this.#policyDir)) {
      fs.mkdirSync(this.#policyDir, { recursive: true });
    }
    await this.#loadAll();
    this.#watch();
  }

  async #loadAll() {
    const files = this.#findYamlFiles(this.#policyDir);
    for (const file of files) {
      await this.#loadFile(file);
    }
  }

  #findYamlFiles(dir) {
    const results = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        results.push(...this.#findYamlFiles(full));
      } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
        results.push(full);
      }
    }
    return results;
  }

  async #loadFile(filePath) {
    try {
      const raw = fs.readFileSync(filePath, 'utf-8');
      const data = yaml.load(raw);
      const policy = this.#validate(data, filePath);
      policy.defaultEffect = policy.defaultEffect ?? this.#defaultEffect;
      const key = this.#policyKey(policy);
      this.#saveSnapshot(key, policy);
      this.#policies.set(key, policy);
      this.emit('policy:loaded', key, policy);
    } catch (err) {
      this.emit('policy:error', filePath, err);
      console.error(`[SecurityGuard] 策略加载失败 ${filePath}: ${err.message}`);
    }
  }

  #validate(data, filePath) {
    if (!data?.version || !data?.scope) {
      throw new Error(`策略文件缺少必填字段 version/scope: ${filePath}`);
    }
    if (data.scope === 'agent' && !data.target) {
      throw new Error(`scope=agent 时 target 必填: ${filePath}`);
    }
    for (const tr of data.timeRestrictions ?? []) {
      if (!tr.schedule?.timezone) {
        throw new Error(`时间规则 ${tr.id} 缺少 timezone 字段: ${filePath}`);
      }
    }
    if (!Array.isArray(data.rules)) data.rules = [];
    return data;
  }

  #policyKey(policy) {
    if (policy.scope === 'agent') return `agent:${policy.target}`;
    if (policy.scope === 'team') return `team:${policy.target ?? 'default'}`;
    return 'global';
  }

  #saveSnapshot(key, policy) {
    const list = this.#snapshots.get(key) ?? [];
    list.push({ version: policy.version, loadedAt: Date.now(), policy });
    if (list.length > MAX_SNAPSHOTS) list.shift();
    this.#snapshots.set(key, list);
  }

  #watch() {
    this.#watcher = chokidar.watch(this.#policyDir, {
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 300 },
    });
    this.#watcher.on('add', (f) => this.#loadFile(f));
    this.#watcher.on('change', (f) => this.#loadFile(f));
    this.#watcher.on('unlink', () => { this.#policies.clear(); this.#loadAll(); });
  }

  /** 返回适用于 agentId 的策略列表（agent > global） */
  getPoliciesFor(agentId) {
    const result = [];
    const agent = this.#policies.get(`agent:${agentId}`);
    if (agent) result.push(agent);
    const global = this.#policies.get('global');
    if (global) result.push(global);
    return result;
  }

  rollback(key) {
    const list = this.#snapshots.get(key);
    if (!list || list.length < 2) return false;
    list.pop();
    const prev = list[list.length - 1];
    this.#policies.set(key, prev.policy);
    this.emit('policy:rollback', key, prev.policy);
    return true;
  }

  async close() {
    await this.#watcher?.close();
  }
}
