// Tiny in-memory sliding-window rate limiter. Nothing here is ever persisted.
export class RateLimiter {
  constructor() {
    this.buckets = new Map();
  }

  /** Returns true if the hit is allowed, false if the limit is exceeded. */
  hit(key, max, windowMs, now = Date.now()) {
    let b = this.buckets.get(key);
    if (!b) {
      if (this.buckets.size > 500_000) this.buckets.clear(); // memory guard under a flood of distinct keys
      b = { times: [], windowMs };
      this.buckets.set(key, b);
    }
    b.windowMs = windowMs;
    const cutoff = now - windowMs;
    while (b.times.length && b.times[0] <= cutoff) b.times.shift();
    if (b.times.length >= max) return false;
    b.times.push(now);
    return true;
  }

  sweep(now = Date.now()) {
    for (const [k, b] of this.buckets) {
      if (!b.times.length || b.times[b.times.length - 1] <= now - b.windowMs) this.buckets.delete(k);
    }
  }
}
