// Portable, allocation-free firmware core: scheduling, rate limiting, bounded queues.
// Everything here takes time as a parameter (no clocks, no globals) so it is
// deterministic and unit-tested on the host (firmware/test/host).
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace ho {

// FNV-1a, used to derive deterministic per-node schedule phases.
inline uint32_t fnv1a(const char* s, uint32_t h = 2166136261u) {
  while (s && *s) { h ^= (uint8_t)*s++; h *= 16777619u; }
  return h;
}

// xorshift32 for bounded seeded jitter.
struct Rng {
  uint32_t s;
  explicit Rng(uint32_t seed) : s(seed ? seed : 0x9e3779b9u) {}
  uint32_t next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
  uint32_t below(uint32_t n) { return n ? next() % n : 0; }
};

// Monotonic periodic deadline. Phase = hash(node, collector) % period, so nodes and
// collectors are staggered deterministically. Missed periods are skipped (counted),
// never replayed as a catch-up burst; deadlines advance on the period grid, not from
// completion time, so they cannot drift.
class Periodic {
 public:
  void configure(uint32_t period_ms, uint32_t phase_seed, uint32_t now_ms, uint32_t jitter_max_ms = 0) {
    period_ = period_ms ? period_ms : 1;
    jitter_max_ = jitter_max_ms < period_ / 4 ? jitter_max_ms : period_ / 4;
    rng_ = Rng(phase_seed ^ 0xa5a5a5a5u);
    uint32_t phase = phase_seed % period_;
    // First deadline: next grid point at or after now with this phase.
    uint32_t base = now_ms - (now_ms % period_) + phase;
    if ((int32_t)(base - now_ms) < 0) base += period_;
    grid_ = base;
    due_ = grid_ + rng_.below(jitter_max_ + 1);
    configured_ = true;
  }
  // Returns true once per elapsed grid slot. `late_ms` receives scheduling lateness.
  bool poll(uint32_t now_ms, uint16_t* late_ms = nullptr) {
    if (!configured_ || (int32_t)(now_ms - due_) < 0) return false;
    uint32_t late = now_ms - due_;
    // Skip whole periods we slept through.
    uint32_t skipped = late / period_;
    missed_ += skipped;
    grid_ += period_ * (skipped + 1);
    due_ = grid_ + rng_.below(jitter_max_ + 1);
    if (late_ms) *late_ms = (uint16_t)((late % period_) > 0xffff ? 0xffff : (late % period_));
    return true;
  }
  uint32_t missed() const { return missed_; }
  uint32_t period() const { return period_; }
  uint32_t due() const { return due_; }

 private:
  uint32_t period_ = 1, jitter_max_ = 0, grid_ = 0, due_ = 0, missed_ = 0;
  Rng rng_{1};
  bool configured_ = false;
};

// Token bucket over application bytes. Integer arithmetic in millitokens.
class TokenBucket {
 public:
  void configure(uint32_t rate_per_s, uint32_t burst, uint32_t now_ms) {
    rate_ = rate_per_s;
    burst_milli_ = (uint64_t)burst * 1000u;
    level_milli_ = burst_milli_;
    last_ = now_ms;
  }
  void refill(uint32_t now_ms) {
    uint32_t dt = now_ms - last_;
    last_ = now_ms;
    uint64_t add = (uint64_t)dt * rate_;  // tokens*ms/s == millitokens
    level_milli_ = level_milli_ + add > burst_milli_ ? burst_milli_ : level_milli_ + add;
  }
  bool try_take(uint32_t n, uint32_t now_ms) {
    refill(now_ms);
    uint64_t need = (uint64_t)n * 1000u;
    if (need > level_milli_) return false;
    level_milli_ -= need;
    return true;
  }
  uint32_t available(uint32_t now_ms) { refill(now_ms); return (uint32_t)(level_milli_ / 1000u); }

 private:
  uint32_t rate_ = 0, last_ = 0;
  uint64_t burst_milli_ = 0, level_milli_ = 0;
};

// Bounded FIFO of encoded frames in a fixed circular byte arena. Each entry stores
// its enqueue time so stale normal data can expire. When full, the oldest entry is
// dropped (counted): after an outage the newest data is the most useful.
template <size_t ArenaBytes, size_t MaxEntries>
class FrameQueue {
 public:
  struct Entry { uint32_t off; uint16_t len; uint32_t t_ms; uint8_t kind; uint64_t seq; };

  // Returns false only if a single frame cannot fit in the arena at all.
  bool push(const uint8_t* data, uint16_t len, uint32_t now_ms, uint8_t kind, uint64_t seq) {
    if (len == 0 || len > ArenaBytes) return false;
    while (count_ == MaxEntries || ArenaBytes - used_ < len) { pop(); dropped_overflow_++; }
    uint32_t first_part = (uint32_t)(ArenaBytes - tail_) < len ? (uint32_t)(ArenaBytes - tail_) : len;
    memcpy(arena_ + tail_, data, first_part);
    if (first_part < len) memcpy(arena_, data + first_part, len - first_part);
    entries_[(first_ + count_) % MaxEntries] = Entry{tail_, len, now_ms, kind, seq};
    count_++;
    tail_ = (uint32_t)((tail_ + len) % ArenaBytes);
    used_ += len;
    if (used_ > high_water_) high_water_ = used_;
    return true;
  }
  const Entry* front() const { return count_ ? &entries_[first_] : nullptr; }
  // Copy the front frame into dst (handles wrap). Returns bytes copied or 0.
  uint16_t copy_front(uint8_t* dst, size_t cap) const {
    if (!count_) return 0;
    const Entry& e = entries_[first_];
    if (e.len > cap) return 0;
    uint32_t first_part = (uint32_t)(ArenaBytes - e.off) < e.len ? (uint32_t)(ArenaBytes - e.off) : e.len;
    memcpy(dst, arena_ + e.off, first_part);
    if (first_part < e.len) memcpy(dst + first_part, arena_, e.len - first_part);
    return e.len;
  }
  void pop() {
    if (!count_) return;
    used_ -= entries_[first_].len;
    first_ = (first_ + 1) % MaxEntries;
    count_--;
    if (!count_) { tail_ = 0; used_ = 0; first_ = 0; }
  }
  // Drop entries older than max_age_ms (counted as expired).
  void expire(uint32_t now_ms, uint32_t max_age_ms) {
    while (count_ && now_ms - entries_[first_].t_ms > max_age_ms) { pop(); dropped_expired_++; }
  }
  size_t size() const { return count_; }
  size_t used_bytes() const { return used_; }
  uint8_t fill_pct() const { return (uint8_t)((used_ * 100u) / ArenaBytes); }
  uint32_t dropped_overflow() const { return dropped_overflow_; }
  uint32_t dropped_expired() const { return dropped_expired_; }
  size_t high_water() const { return high_water_; }
  static constexpr size_t capacity_bytes() { return ArenaBytes; }

 private:
  uint8_t arena_[ArenaBytes];
  Entry entries_[MaxEntries];
  size_t first_ = 0, count_ = 0, used_ = 0, high_water_ = 0;
  uint32_t tail_ = 0;
  uint32_t dropped_overflow_ = 0, dropped_expired_ = 0;
};

// Exponential reconnect backoff with jitter, bounded [min,max].
class Backoff {
 public:
  Backoff(uint32_t min_ms, uint32_t max_ms, uint32_t seed) : min_(min_ms), max_(max_ms), cur_(min_ms), rng_(seed) {}
  uint32_t next() {
    uint32_t base = cur_;
    cur_ = cur_ > max_ / 2 ? max_ : cur_ * 2;
    // "Equal jitter": half fixed, half random, so synchronized reboots spread out.
    uint32_t v = base / 2 + rng_.below(base / 2 + 1);
    return v > max_ ? max_ : (v < min_ ? min_ : v);
  }
  void reset() { cur_ = min_; }

 private:
  uint32_t min_, max_, cur_;
  Rng rng_;
};

// Running RSSI statistics over a window (BLE / Wi-Fi). No allocation.
struct RssiStats {
  uint16_t count = 0;
  int8_t min = 127, max = -128;
  int32_t sum = 0;
  void add(int8_t v) {
    if (count == 0xffff) return;
    count++;
    sum += v;
    if (v < min) min = v;
    if (v > max) max = v;
  }
  void reset() { *this = RssiStats(); }
};

}  // namespace ho
