#pragma once
// Relay connect-latency ring and its percentiles (lib/fry_core/heartbeat_fields.h appends them to
// the installation heartbeat as relay_p50_ms / relay_p95_ms / relay_samples).
//
// The relay task records how long each upstream connect took; the heartbeat reads three numbers.
// The buffer is bounded (kLatencySamples) so its cost is fixed whatever the traffic, and the
// percentiles are computed on a sorted copy of at most kLatencySamples values, which the caller
// does at a heartbeat's cadence, not per connection.
//
// Definitions (pinned by test/test_relay_latency):
//   p50 = the median of the samples: the middle value, or for an even count the mean of the two
//         middle values (integer milliseconds, truncated).
//   p95 = nearest-rank: the ceil(0.95 * n)-th smallest value, i.e. sorted[(95*n + 99) / 100 - 1].
//   no samples -> both 0 and count 0 (the fields are always present, so a reader cannot tell
//         "no data" from "0 ms" except by relay_samples == 0).
#include <cstdint>

namespace fry_relay {

constexpr int kLatencySamples = 60;  // bounded ring: the last 60 successful connects

class LatencyRing {
 public:
  void reset() { count_ = 0; next_ = 0; }
  uint32_t count() const { return static_cast<uint32_t>(count_); }

  // Adds one sample; once full, the oldest is overwritten.
  void add(uint32_t ms) {
    buf_[next_] = ms;
    next_ = (next_ + 1) % kLatencySamples;
    if (count_ < kLatencySamples) count_++;
  }

  uint32_t p50Ms() const {
    uint32_t v[kLatencySamples];
    const int n = sorted(v);
    if (n == 0) return 0;
    if (n % 2 == 1) return v[n / 2];
    // 64-bit sum: two large samples must not wrap the average.
    return static_cast<uint32_t>((static_cast<uint64_t>(v[n / 2 - 1]) + v[n / 2]) / 2);
  }

  uint32_t p95Ms() const {
    uint32_t v[kLatencySamples];
    const int n = sorted(v);
    if (n == 0) return 0;
    int rank = (95 * n + 99) / 100;  // ceil(0.95 * n), 1-based
    if (rank < 1) rank = 1;
    if (rank > n) rank = n;
    return v[rank - 1];
  }

 private:
  // Copies the live samples into `v` in ascending order (insertion sort: n <= 60). Returns n.
  int sorted(uint32_t* v) const {
    const int n = count_;
    for (int i = 0; i < n; i++) v[i] = buf_[i];
    for (int i = 1; i < n; i++) {
      const uint32_t x = v[i];
      int j = i - 1;
      while (j >= 0 && v[j] > x) {
        v[j + 1] = v[j];
        j--;
      }
      v[j + 1] = x;
    }
    return n;
  }

  uint32_t buf_[kLatencySamples] = {};
  int next_ = 0;
  int count_ = 0;
};

}  // namespace fry_relay
