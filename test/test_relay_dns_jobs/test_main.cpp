// lib/fry_core/relay_dns.h DnsJobs: the resolver-job pool behind the relay's NeedConnect path.
//
// REV-B blocker this pins: a job used to stay attached to its client slot for the rest of the
// session. The resolver finishes while the loop is blocked in select(), so on the next pass the
// sweep caches the answer (cached=true) but cannot free the job (refs==1); the slot then takes the
// cache-hit early return and never gives the job back. With kDnsJobs=2, two long-lived hostname
// sessions pinned both jobs and every later hostname got no lookup at all - a SOCKS ConnectTimeout
// at 3000 ms, until one of the two sessions ended.
//
// The groups below drive that exact sequence in the pure pool, with the broken behaviour as an
// in-test control (begin() must fail while a finished job is still referenced), then prove the fix:
// the slot hands its finished job back before the cache-hit path and the third name proceeds. The
// last group reads src/esp32/vpn_wireguard.cpp and fails if the glue stops doing it in that order -
// and is checked against synthetic sources first, so it cannot pass by seeing nothing.
#include <unity.h>

#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "relay_dns.h"

using fry_relay::DnsCache;
using fry_relay::DnsJob;
using fry_relay::DnsJobs;
using fry_relay::kDnsJobs;

namespace {

const uint32_t kIp1 = 0x0A0D0D01u;
const uint32_t kIp2 = 0x0A0D0D02u;
const uint32_t kTtl = 300000;
const uint32_t kFailTtl = 15000;

// What the resolver task does when it finishes, in the order the shim does it.
void resolve(DnsJob* j, uint32_t ip) {
  j->ip = ip;
  j->ok = true;
  j->done = true;
}

// ---- the pool ---------------------------------------------------------------------------------

void test_two_busy_jobs_refuse_a_third_name() {
  DnsJobs p;
  DnsCache c;
  bool created = false;
  TEST_ASSERT_NOT_NULL(p.begin("a.test", &created));
  TEST_ASSERT_TRUE(created);
  TEST_ASSERT_NOT_NULL(p.begin("b.test", &created));
  TEST_ASSERT_TRUE(created);
  TEST_ASSERT_EQUAL_INT(kDnsJobs, p.liveCount());
  TEST_ASSERT_EQUAL_INT(0, p.freeCount());
  // Control: while both jobs are unresolved the third name is refused, exactly as designed.
  TEST_ASSERT_NULL(p.begin("c.test", &created));
  TEST_ASSERT_FALSE(created);
  TEST_ASSERT_EQUAL_INT(0, p.freeCount());
}

void test_a_finished_but_referenced_job_still_holds_its_slot() {
  // The blocker's mechanism, as a control: caching alone does not free the slot.
  DnsJobs p;
  DnsCache c;
  bool created = false;
  DnsJob* a = p.begin("a.test", &created);
  TEST_ASSERT_NOT_NULL(p.begin("b.test", &created));
  resolve(a, kIp1);
  p.sweep(c, 1000, kTtl, kFailTtl);  // the loop's pass: caches both, frees neither (refs==1)
  TEST_ASSERT_EQUAL_INT(kDnsJobs, p.liveCount());
  TEST_ASSERT_EQUAL_INT(0, p.freeCount());
  uint32_t ip = 0;
  TEST_ASSERT_TRUE(c.lookup("a.test", 1000, &ip));  // the answer IS cached...
  TEST_ASSERT_NULL(p.begin("c.test", &created));    // ...and the third name still gets nothing
}

void test_the_cache_hit_path_gives_the_job_back_and_the_third_name_proceeds() {
  DnsJobs p;
  DnsCache c;
  bool created = false;
  DnsJob* a = p.begin("a.test", &created);
  DnsJob* b = p.begin("b.test", &created);
  resolve(a, kIp1);
  resolve(b, kIp2);
  p.sweep(c, 1000, kTtl, kFailTtl);
  TEST_ASSERT_EQUAL_INT(0, p.freeCount());

  // The fix, in the shim's order: the slot settles its finished job and drops its reference BEFORE
  // it looks in the cache (needConnect's first statement), so the slot is free again.
  TEST_ASSERT_TRUE(p.finishSlot(a, c, 1000, kTtl, kFailTtl));
  TEST_ASSERT_NULL(a);  // finishSlot clears the slot's pointer
  p.sweep(c, 1000, kTtl, kFailTtl);
  TEST_ASSERT_EQUAL_INT(1, p.freeCount());

  DnsJob* third = p.begin("c.test", &created);
  TEST_ASSERT_NOT_NULL_MESSAGE(third, "a third hostname must get a resolver job once a session has its answer");
  TEST_ASSERT_TRUE(created);
  // The first session's answer is still usable, so it never resolves that name again.
  uint32_t ip = 0;
  TEST_ASSERT_TRUE(c.lookup("a.test", 1000, &ip));
  TEST_ASSERT_EQUAL_UINT32(kIp1, ip);
}

void test_a_failed_lookup_also_gives_the_slot_back() {
  DnsJobs p;
  DnsCache c;
  bool created = false;
  DnsJob* a = p.begin("bad.test", &created);
  TEST_ASSERT_NOT_NULL(p.begin("b.test", &created));
  a->done = true;  // the resolver failed: ok stays false
  p.sweep(c, 500, kTtl, kFailTtl);
  TEST_ASSERT_TRUE(p.finishSlot(a, c, 500, kTtl, kFailTtl));
  p.sweep(c, 500, kTtl, kFailTtl);
  TEST_ASSERT_EQUAL_INT(1, p.freeCount());
  TEST_ASSERT_TRUE(c.blocked("bad.test", 500));
  TEST_ASSERT_NOT_NULL(p.begin("c.test", &created));
}

void test_a_shared_job_lives_until_every_slot_releases_it() {
  DnsJobs p;
  DnsCache c;
  bool created = false;
  DnsJob* j1 = p.begin("same.test", &created);
  TEST_ASSERT_TRUE(created);
  TEST_ASSERT_EQUAL_INT(1, j1->refs);
  DnsJob* j2 = p.begin("same.test", &created);
  TEST_ASSERT_FALSE(created);  // the second slot joins the first job
  TEST_ASSERT_EQUAL_INT(2, j1->refs);
  TEST_ASSERT_TRUE(j1 == j2);
  resolve(j1, kIp1);
  p.sweep(c, 100, kTtl, kFailTtl);
  TEST_ASSERT_TRUE(p.finishSlot(j1, c, 100, kTtl, kFailTtl));
  p.sweep(c, 100, kTtl, kFailTtl);
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, p.liveCount(), "j2 still waits on it, so the job must stay");
  TEST_ASSERT_TRUE(p.finishSlot(j2, c, 100, kTtl, kFailTtl));  // the second slot reads the same answer
  p.sweep(c, 100, kTtl, kFailTtl);
  TEST_ASSERT_EQUAL_INT(kDnsJobs, p.freeCount());
}

void test_an_abandoned_job_is_still_cached_for_the_next_request() {
  DnsJobs p;
  DnsCache c;
  bool created = false;
  DnsJob* a = p.begin("gone.test", &created);
  p.release(a);  // the client slot closed while the resolver was still running
  TEST_ASSERT_EQUAL_INT(0, a->refs);
  resolve(a, kIp2);
  p.sweep(c, 200, kTtl, kFailTtl);  // caches it and frees it: nothing references it
  TEST_ASSERT_EQUAL_INT(kDnsJobs, p.freeCount());
  uint32_t ip = 0;
  TEST_ASSERT_TRUE(c.lookup("gone.test", 200, &ip));
  TEST_ASSERT_EQUAL_UINT32(kIp2, ip);
}

void test_pending_counts_only_jobs_still_resolving() {
  DnsJobs p;
  DnsCache c;
  bool created = false;
  TEST_ASSERT_FALSE(p.pending());
  DnsJob* a = p.begin("a.test", &created);
  TEST_ASSERT_TRUE(p.pending());
  resolve(a, kIp1);
  TEST_ASSERT_FALSE_MESSAGE(p.pending(), "a finished job must not keep the select loop polling");
  TEST_ASSERT_TRUE(p.finishSlot(a, c, 0, kTtl, kFailTtl));
  p.sweep(c, 0, kTtl, kFailTtl);
  TEST_ASSERT_FALSE(p.pending());
  TEST_ASSERT_EQUAL_INT(kDnsJobs, p.freeCount());
}

void test_the_pool_survives_many_sessions() {
  // Ten sessions in a row, each resolving and handing its job back: the pool never runs dry.
  DnsCache c;
  DnsJobs p;
  for (int i = 0; i < 10; i++) {
    bool created = false;
    DnsJob* j = p.begin("loop.test", &created);
    TEST_ASSERT_NOT_NULL(j);
    resolve(j, kIp1);
    TEST_ASSERT_TRUE(p.finishSlot(j, c, static_cast<uint32_t>(i), kTtl, kFailTtl));
    p.sweep(c, static_cast<uint32_t>(i), kTtl, kFailTtl);
    TEST_ASSERT_EQUAL_INT(kDnsJobs, p.freeCount());
  }
}

// ---- the loop must service a DNS wait on a timeout pass (REV-C blocker) ------------------------
//
// A slot in Phase::NeedConnect watches no descriptor, so on an idle relay select() only ever
// returns on timeout - and serviceSlot() is reachable only from a Ready pass. If nothing services
// the NeedConnect slots on a timeout, the resolved answer sits in the cache while the slot waits
// for unrelated traffic, or times out: on a quiet relay every hostname CONNECT fails.
//
// The struct below is the loop's DNS-relevant behaviour with lwIP removed: slots waiting in
// NeedConnect and one pass type - a timeout, with NO ready descriptor and NO other traffic.

struct LoopModel {
  static const int kSlots = 4;
  fry_relay::DnsCache cache;
  DnsJobs jobs;
  DnsJob* slot[kSlots] = {};
  char host[kSlots][32] = {};
  int phase[kSlots] = {};  // 0 free, 1 NeedConnect, 2 Connecting (SOCKS reply queued), 3 failed
  uint32_t connectedIp[kSlots] = {};
  bool serviceDnsOnTimeout = true;  // false models the pre-fix loop

  void wait(int i, const char* name) {  // the client's CONNECT was parsed: enter NeedConnect
    for (int k = 0; k < 31 && name[k] != 0; k++) host[i][k] = name[k];
    phase[i] = 1;
  }

  // needConnect(), minus lwIP: settle the slot's finished job, then cache hit / negative / begin.
  void service(int i, uint32_t now) {
    if (phase[i] != 1) return;
    jobs.finishSlot(slot[i], cache, now, kTtl, kFailTtl);
    uint32_t ip = 0;
    if (cache.lookup(host[i], now, &ip)) {
      phase[i] = 2;
      connectedIp[i] = ip;
      return;
    }
    if (cache.blocked(host[i], now)) {
      phase[i] = 3;
      return;
    }
    if (slot[i] == nullptr) {
      bool created = false;
      slot[i] = jobs.begin(host[i], &created);
    }
  }

  // A pass where select() returned zero fds: the sweep runs at the top (as in the relay loop, so
  // an abandoned job's answer is cached) and then only the NeedConnect slots are serviced.
  void timeoutPass(uint32_t now) {
    jobs.sweep(cache, now, kTtl, kFailTtl);
    if (!serviceDnsOnTimeout) return;
    for (int i = 0; i < kSlots; i++) service(i, now);
  }
};

void test_an_idle_relay_completes_resolved_connects_without_any_ready_event() {
  LoopModel m;
  m.wait(0, "a.test");
  m.wait(1, "b.test");
  m.wait(2, "c.test");

  // Pass 1: two jobs exist, the third name has to wait for capacity - exactly the blocker's shape.
  m.timeoutPass(1000);
  TEST_ASSERT_EQUAL_INT(2, m.jobs.liveCount());
  TEST_ASSERT_EQUAL_INT(1, m.phase[2]);

  // Both resolvers finish while the loop is idle (no ready fd ever fires).
  resolve(m.slot[0], kIp1);
  resolve(m.slot[1], kIp2);

  // Pass 2: the timeout pass itself must complete A and B and free their jobs...
  m.timeoutPass(1100);
  TEST_ASSERT_EQUAL_INT(2, m.phase[0]);
  TEST_ASSERT_EQUAL_INT(2, m.phase[1]);
  TEST_ASSERT_EQUAL_UINT32(kIp1, m.connectedIp[0]);
  TEST_ASSERT_EQUAL_UINT32(kIp2, m.connectedIp[1]);
  // ...and the third name picks up a freed job in that same pass.
  TEST_ASSERT_EQUAL_INT(1, m.phase[2]);
  TEST_ASSERT_NOT_NULL(m.slot[2]);

  resolve(m.slot[2], kIp1);
  m.timeoutPass(1200);
  TEST_ASSERT_EQUAL_INT_MESSAGE(2, m.phase[2], "an idle relay must complete the third hostname too");
  TEST_ASSERT_EQUAL_UINT32(kIp1, m.connectedIp[2]);
  TEST_ASSERT_EQUAL_INT(kDnsJobs, m.jobs.freeCount());

  // The two names are cached, so repeating them needs no lookup at all.
  uint32_t ip = 0;
  TEST_ASSERT_TRUE(m.cache.lookup("a.test", 1200, &ip));
  TEST_ASSERT_TRUE(m.cache.lookup("b.test", 1200, &ip));
}

void test_a_timeout_only_loop_that_skips_dns_waits_stalls_them() {
  // Control: the pre-fix loop (a Ready pass is the only thing that services a slot) never advances
  // any of them, which is the failure the fix removes.
  LoopModel m;
  m.serviceDnsOnTimeout = false;
  m.wait(0, "a.test");
  m.timeoutPass(1000);
  TEST_ASSERT_EQUAL_INT(0, m.jobs.liveCount());
  TEST_ASSERT_EQUAL_INT(1, m.phase[0]);
}



bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadRelaySource(std::string& out) {
  const std::string rel = "src/esp32/vpn_wireguard.cpp";
  const std::string self = __FILE__;
  const std::string tail = "test/test_relay_dns_jobs/test_main.cpp";
  std::vector<std::string> prefixes;
  if (self.size() >= tail.size() && self.compare(self.size() - tail.size(), tail.size(), tail) == 0) {
    prefixes.push_back(self.substr(0, self.size() - tail.size()));
  }
  const char* ups[] = {"", "../", "../../", "../../../", "../../../../"};
  for (size_t i = 0; i < sizeof(ups) / sizeof(ups[0]); i++) prefixes.push_back(ups[i]);
  for (size_t i = 0; i < prefixes.size(); i++) {
    if (readFile(prefixes[i] + rel, out)) return true;
  }
  return false;
}

// The body of needConnect(): from its signature to the next line that is just "}" at column 0.
bool needConnectBody(const std::string& src, std::string& body) {
  const size_t a = src.find("bool needConnect(fry_relay::Slot& s");
  if (a == std::string::npos) return false;
  const size_t b = src.find("\n}\n", a);
  if (b == std::string::npos) return false;
  body = src.substr(a, b - a);
  return true;
}

// "" when the glue releases the slot's finished job before it can take the cache-hit path, else why.
std::string checkReleaseBeforeCacheHit(const std::string& body) {
  const size_t rel = body.find("jobs.finishSlot(s_dns.job[idx]");
  if (rel == std::string::npos) return "needConnect never gives the slot's finished job back";
  const size_t look = body.find("cache.lookup(s.req.host");
  if (look == std::string::npos) return "needConnect no longer consults the cache";
  if (rel > look) return "the finished job is given back AFTER the cache-hit path: a hit returns first";
  // ...and it must be the first thing the function does, before any other early return
  const size_t firstReturn = body.find("return");
  if (firstReturn != std::string::npos && firstReturn < rel)
    return "needConnect can return before it gives the finished job back";
  return "";
}

void test_the_glue_gives_a_finished_job_back_before_the_cache_hit() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadRelaySource(src), "cannot read src/esp32/vpn_wireguard.cpp");
  std::string body;
  TEST_ASSERT_TRUE_MESSAGE(needConnectBody(src, body), "cannot find needConnect() in the relay glue");
  const std::string why = checkReleaseBeforeCacheHit(body);
  TEST_ASSERT_TRUE_MESSAGE(why.empty(), why.c_str());
}

// The relay loop: the DNS wait must be serviced on a TIMEOUT pass, before the Ready-only continue.
std::string checkTimeoutServicesDns(const std::string& loop) {
  const size_t sel = loop.find("classifySelect(sr, se)");
  if (sel == std::string::npos) return "the relay loop no longer classifies select()'s result";
  const size_t ready = loop.find("SelectAction::Ready) continue", sel);
  if (ready == std::string::npos) return "the relay loop no longer continues on a non-Ready pass";
  const size_t branch = loop.find("SelectAction::Timeout", sel);
  if (branch == std::string::npos || branch > ready)
    return "no SelectAction::Timeout branch before the Ready-only continue: a timeout pass services nothing";
  const size_t need = loop.find("Phase::NeedConnect", branch);
  if (need == std::string::npos || need > ready)
    return "the timeout branch does not restrict itself to the slots in Phase::NeedConnect";
  const size_t call = loop.find("needConnect(", need);
  if (call == std::string::npos || call > ready)
    return "the timeout branch never runs the resolution step for a waiting slot";
  return "";
}

void test_the_loop_services_dns_waits_on_a_timeout_pass() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadRelaySource(src), "cannot read src/esp32/vpn_wireguard.cpp");
  const size_t a = src.find("void relayTaskFn(void*)");
  TEST_ASSERT_TRUE_MESSAGE(a != std::string::npos, "cannot find relayTaskFn() in the relay glue");
  const size_t b = src.find("\n}\n", a);
  TEST_ASSERT_TRUE(b != std::string::npos);
  const std::string why = checkTimeoutServicesDns(src.substr(a, b - a));
  TEST_ASSERT_TRUE_MESSAGE(why.empty(), why.c_str());
}

void test_the_timeout_check_rejects_the_ready_only_loop() {
  // The pre-fix loop: a Ready pass is the only thing that services a slot. It must be rejected, so
  // a pass cannot come from a check that sees nothing.
  const std::string broken =
      "void relayTaskFn(void*) {\n"
      "  for (;;) {\n"
      "    const SelectAction act = classifySelect(sr, se);\n"
      "    if (act != SelectAction::Ready) continue;  // timeout / EINTR\n"
      "    for (int i = 0; i < FRY_RELAY_SLOTS; i++) progress |= serviceSlot(*s, i, rdC, rdU, wrU, now, st);\n"
      "  }\n"
      "}\n";
  TEST_ASSERT_FALSE(checkTimeoutServicesDns(broken).empty());

  const std::string no_guard =
      "void relayTaskFn(void*) {\n"
      "  for (;;) {\n"
      "    const SelectAction act = classifySelect(sr, se);\n"
      "    if (act == SelectAction::Timeout) { needConnect(*s, i, now, st); continue; }\n"
      "    if (act != SelectAction::Ready) continue;\n"
      "  }\n"
      "}\n";
  TEST_ASSERT_FALSE(checkTimeoutServicesDns(no_guard).empty());  // whole pool on every tick

  const std::string good =
      "void relayTaskFn(void*) {\n"
      "  for (;;) {\n"
      "    const SelectAction act = classifySelect(sr, se);\n"
      "    if (act == SelectAction::Timeout) {\n"
      "      for (int i = 0; i < FRY_RELAY_SLOTS; i++) {\n"
      "        if (slots[i] == nullptr || slots[i]->phase != Phase::NeedConnect) continue;\n"
      "        needConnect(*slots[i], i, now, st);\n"
      "      }\n"
      "      continue;\n"
      "    }\n"
      "    if (act != SelectAction::Ready) continue;\n"
      "  }\n"
      "}\n";
  TEST_ASSERT_EQUAL_STRING("", checkTimeoutServicesDns(good).c_str());
}

void test_the_order_check_rejects_the_broken_glue() {
  // The pre-fix body (cache-hit early return, job never given back) and a later release must both
  // be rejected, so a pass cannot come from a check that sees nothing.
  const std::string broken =
      "bool needConnect(fry_relay::Slot& s, int idx, uint32_t now, RelayStats& st) {\n"
      "  uint32_t ip = 0;\n"
      "  if (s_dns.cache.lookup(s.req.host, now, &ip)) {\n"
      "    connectTo(s, ip, now, st);\n"
      "    return true;\n"
      "  }\n"
      "  return false;\n"
      "}\n";
  std::string body;
  TEST_ASSERT_TRUE(needConnectBody(broken, body));
  TEST_ASSERT_FALSE(checkReleaseBeforeCacheHit(body).empty());

  const std::string late =
      "bool needConnect(fry_relay::Slot& s, int idx, uint32_t now, RelayStats& st) {\n"
      "  uint32_t ip = 0;\n"
      "  if (s_dns.cache.lookup(s.req.host, now, &ip)) {\n"
      "    connectTo(s, ip, now, st);\n"
      "    return true;\n"
      "  }\n"
      "  s_dns.jobs.finishSlot(s_dns.job[idx], s_dns.cache, now, 1, 2);\n"
      "  return false;\n"
      "}\n";
  TEST_ASSERT_TRUE(needConnectBody(late, body));
  TEST_ASSERT_FALSE(checkReleaseBeforeCacheHit(body).empty());

  const std::string good =
      "bool needConnect(fry_relay::Slot& s, int idx, uint32_t now, RelayStats& st) {\n"
      "  s_dns.jobs.finishSlot(s_dns.job[idx], s_dns.cache, now, 1, 2);\n"
      "  uint32_t ip = 0;\n"
      "  if (s_dns.cache.lookup(s.req.host, now, &ip)) {\n"
      "    connectTo(s, ip, now, st);\n"
      "    return true;\n"
      "  }\n"
      "  return false;\n"
      "}\n";
  TEST_ASSERT_TRUE(needConnectBody(good, body));
  TEST_ASSERT_EQUAL_STRING("", checkReleaseBeforeCacheHit(body).c_str());
}

}  // namespace

void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_two_busy_jobs_refuse_a_third_name);
  RUN_TEST(test_a_finished_but_referenced_job_still_holds_its_slot);
  RUN_TEST(test_the_cache_hit_path_gives_the_job_back_and_the_third_name_proceeds);
  RUN_TEST(test_a_failed_lookup_also_gives_the_slot_back);
  RUN_TEST(test_a_shared_job_lives_until_every_slot_releases_it);
  RUN_TEST(test_an_abandoned_job_is_still_cached_for_the_next_request);
  RUN_TEST(test_pending_counts_only_jobs_still_resolving);
  RUN_TEST(test_the_pool_survives_many_sessions);
  RUN_TEST(test_an_idle_relay_completes_resolved_connects_without_any_ready_event);
  RUN_TEST(test_a_timeout_only_loop_that_skips_dns_waits_stalls_them);
  RUN_TEST(test_the_glue_gives_a_finished_job_back_before_the_cache_hit);
  RUN_TEST(test_the_loop_services_dns_waits_on_a_timeout_pass);
  RUN_TEST(test_the_timeout_check_rejects_the_ready_only_loop);
  RUN_TEST(test_the_order_check_rejects_the_broken_glue);
  return UNITY_END();
}
