import pino from "pino";

export const l = (...msgs) => pino().info(msgs.join(" "));
export const warn = (...msgs) => pino().warn(msgs.join(" "));
export const err = (...msgs) => pino().error(msgs.join(" "));

// Collapse a verbose error message for logging. CLN's xpay concatenates one
// failure sentence per routing retry (e.g. "We got temporary_channel_failure
// for X … updating our map." repeated 50+ times), which floods the logs on an
// ordinary failed lightning send. Dedupe repeated sentences and cap length.
export const shortError = (msg: any, max = 400): string => {
  let s = typeof msg === "string" ? msg : msg?.message ?? String(msg);
  const parts = s.split(/(?<=\.)\s+/);
  const seen = new Set<string>();
  const uniq: string[] = [];
  for (const p of parts) {
    const t = p.trim();
    if (t && !seen.has(t)) { seen.add(t); uniq.push(t); }
  }
  s = uniq.join(" ");
  const dropped = parts.length - uniq.length;
  if (dropped > 0) s += ` [${dropped} repeated lines collapsed]`;
  return s.length > max ? `${s.slice(0, max)}…` : s;
};

// Per-key log throttle for lines an attacker can emit at will (evicted-JWT
// replays from a proxy pool, frozen-account send attempts, lnurl scans of
// missing usernames). Returns null while the key is inside its quiet window,
// otherwise the number of calls suppressed since the last emitted line — so
// the first occurrence always logs, and the next one after the window carries
// the suppressed count. In-memory: a restart simply logs again.
const quietUntil = new Map<string, { until: number; dropped: number }>();
export const quiet = (key: string, ms = 10 * 60 * 1000): number | null => {
  const now = Date.now();
  const q = quietUntil.get(key);
  if (q && q.until > now) {
    q.dropped++;
    return null;
  }
  if (quietUntil.size > 10000) quietUntil.clear();
  quietUntil.set(key, { until: now + ms, dropped: 0 });
  return q?.dropped ?? 0;
};
export const suppressed = (n: number | null) =>
  n ? `(+${n} similar suppressed)` : "";

export const line = () => {
  const stack = new Error().stack;
  const stackLine = stack.split("\n")[1];
  const match = stackLine.match(/at\s+(.*):(\d+):(\d+)/);
  return `${match[1]}:${match[2]}`;
};
