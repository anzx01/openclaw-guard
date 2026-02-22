// src/timewindow/time-checker.js
// 时间窗口封锁检查

import micromatch from 'micromatch';

export class TimeChecker {
  /** @param {import('../engine/policy-loader.js').PolicyLoader} loader */
  constructor(loader) {
    this.loader = loader;
  }

  /**
   * 检查当前时间是否在封锁窗口内
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
            reason: `操作 ${ctx.action} 在时间段 ${tr.schedule.start}-${tr.schedule.end} (${tr.schedule.timezone}) 内被封锁`,
          };
        }
        if (tr.effect === 'allow' && !blocked) {
          return {
            decision: 'deny',
            ruleId: tr.id,
            reason: `操作 ${ctx.action} 仅允许在时间段 ${tr.schedule.start}-${tr.schedule.end} (${tr.schedule.timezone}) 内执行`,
          };
        }
      }
    }
    return null;
  }

  /**
   * 判断当前时间是否在 schedule 定义的时间段内
   * @param {Date} now
   * @param {{ type: string, start: string, end: string, timezone: string }} schedule
   */
  #isBlocked(now, schedule) {
    const localTime = this.#toLocalTime(now, schedule.timezone);
    const currentMinutes = localTime.hours * 60 + localTime.minutes;
    const startMinutes = this.#parseTime(schedule.start);
    const endMinutes = this.#parseTime(schedule.end);

    if (startMinutes <= endMinutes) {
      // 普通时间段，如 09:00-18:00
      return currentMinutes >= startMinutes && currentMinutes < endMinutes;
    } else {
      // 跨午夜时间段，如 22:00-06:00
      return currentMinutes >= startMinutes || currentMinutes < endMinutes;
    }
  }

  /** 将 UTC 时间转换为指定时区的本地时间（小时和分钟） */
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
      // 时区无效时回退到 UTC
      return { hours: date.getUTCHours(), minutes: date.getUTCMinutes() };
    }
  }

  /** 将 "HH:MM" 转换为分钟数 */
  #parseTime(timeStr) {
    const [h, m] = timeStr.split(':').map(Number);
    return h * 60 + (m ?? 0);
  }
}
