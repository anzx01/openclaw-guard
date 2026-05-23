// SPDX-License-Identifier: MIT
// Copyright (c) 2026 OpenClaw Guard contributors
// src/utils/pii-scrubber.js
// PII scrubbing utility

const BUILT_IN_PATTERNS = [
  { name: 'phone_cn',    pattern: /1[3-9]\d{9}/g,                          mask: (m) => m.slice(0, 3) + '****' + m.slice(-4) },
  { name: 'id_card_cn',  pattern: /[1-9]\d{5}(18|19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]/g, mask: () => '***IDCARD***' },
  { name: 'bank_card',   pattern: /[1-9]\d{15,18}/g,                       mask: (m) => m.slice(0, 4) + '****' + m.slice(-4) },
  { name: 'email',       pattern: /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g, mask: (m) => { const [u, d] = m.split('@'); return u.slice(0, 2) + '***@' + d; } },
  { name: 'api_key',     pattern: /\b(sk-[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9\-._~+/]+=*)/g, mask: () => '[REDACTED_KEY]' },
];

export class PiiScrubber {
  #patterns;

  constructor(customPatterns = []) {
    this.#patterns = [...BUILT_IN_PATTERNS];
    for (const cp of customPatterns) {
      this.#patterns.push({
        name: cp.name,
        pattern: new RegExp(cp.pattern, 'g'),
        mask: () => cp.mask,
      });
    }
  }

  /**
   * Scrub PII from a string
   * @param {string} text
   * @returns {string}
   */
  scrub(text) {
    if (typeof text !== 'string') return text;
    let result = text;
    for (const { pattern, mask } of this.#patterns) {
      pattern.lastIndex = 0;
      result = result.replace(pattern, mask);
    }
    return result;
  }

  /**
   * Recursively scrub PII from all string fields in an object
   * @param {unknown} obj
   * @returns {unknown}
   */
  scrubObject(obj) {
    if (typeof obj === 'string') return this.scrub(obj);
    if (Array.isArray(obj)) return obj.map((v) => this.scrubObject(v));
    if (obj && typeof obj === 'object') {
      const result = {};
      for (const [k, v] of Object.entries(obj)) {
        result[k] = this.scrubObject(v);
      }
      return result;
    }
    return obj;
  }
}
