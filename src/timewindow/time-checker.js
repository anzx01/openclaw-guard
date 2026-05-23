// SPDX-License-Identifier: MIT
// Copyright (c) 2026 OpenClaw Guard contributors
// src/timewindow/time-checker.js
// Time window block checker

import micromatch from 'micromatch';

export class TimeChecker {
  /** @param {import('../engine/policy-loader.js').PolicyLoader} loader */
  constructor(loader) {
    this.loader = loader;
  }

  /**
   * Check if the current time falls within a blocked window
   * @param {import('../types.js').RequestContext} ctx
   * @returns {import('../types.js').GuardResult|null}
   */
  check(ctx) {
    const policies = this.loader.getPoliciesFor(ctx.agentId);
    const now = ctx.timestamp ? new Date(ctx.timestamp) : new Date();

    for (const policy of policies) {
      for (const tr of policy.timeRestrictions ?? []) {
        if (!micromatch.isMatch(ctx.action, tr.action)) continue;

        const blocked = this.#isBlocked(now, tr.schedule);
        if (tr.effect === 'deny' && blocked) {
          return {
            decision: 'deny',
            ruleId: tr.id,
            reason: `Action ${ctx.action} is blocked during ${tr.schedule.start}-${tr.schedule.end} (${tr.schedule.timezone})`,
          };
        }
        if (tr.effect === 'allow' && !blocked) {
          return {
            decision: 'deny',
            ruleId: tr.id,
            reason: `Action ${ctx.action} is only allowed during ${tr.schedule.start}-${tr.schedule.end} (${tr.schedule.timezone})`,
          };
        }
      }
    }
    return null;
  }

  /**
   * Check if the given time falls within the schedule window
   * @param {Date} now
   * @param {{ type: string, start: string, end: string, timezone: string }} schedule
   */
  #isBlocked(now, schedule) {
    const localTime = this.#toLocalTime(now, schedule.timezone);
    const currentMinutes = localTime.hours * 60 + localTime.minutes;
    const startMinutes = this.#parseTime(schedule.start);
    const endMinutes = this.#parseTime(schedule.end);

    if (startMinutes <= endMinutes) {
      // Normal range e.g. 09:00-18:00
      return currentMinutes >= startMinutes && currentMinutes < endMinutes;
    } else {
      // Cross-midnight range e.g. 22:00-06:00
      return currentMinutes >= startMinutes || currentMinutes < endMinutes;
    }
  }

  /** Convert UTC date to local hours/minutes in the given timezone */
  #toLocalTime(date, timezone) {
    try {
      const formatter = new Intl.DateTimeFormat('en-US', {
        timeZone: timezone,
        hour: 'numeric',
        minute: 'numeric',
        hour12: false,
      });
      const parts = formatter.formatToParts(date);
      const hours = parseInt(parts.find((p) => p.type === 'hour')?.value ?? '0');
      const minutes = parseInt(parts.find((p) => p.type === 'minute')?.value ?? '0');
      return { hours: hours === 24 ? 0 : hours, minutes };
    } catch {
      // Fall back to UTC if timezone is invalid
      return { hours: date.getUTCHours(), minutes: date.getUTCMinutes() };
    }
  }

  /** Parse "HH:MM" string to total minutes */
  #parseTime(timeStr) {
    const [h, m] = timeStr.split(':').map(Number);
    return h * 60 + (m ?? 0);
  }
}
