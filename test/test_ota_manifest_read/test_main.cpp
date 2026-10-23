// The ESP8266 OTA manifest body is read by our own loop, which cannot lose it to the core's connection check, and a body that
// does not arrive whole is reported as a failed READ (and retried soon), not as "manifest parse failed".
//
// Before: checkNow() called http.getString(). Bench P4 (lo/c1-p4-160615.lines.txt, t=223080): http=200 size=992, then in getString
// the TLS session was freed (free +12.8 K), len=0, deserializeJson=EmptyInput, "ota: manifest parse failed" 1 ms later. P3 had 4 of 8.
// getString() ignores writeToStream()'s error (ESP8266HTTPClient.cpp:749) and hands back an empty String.
//
// The mechanism, from the 3.30102.0 core sources: HTTPClient::writeToPrint() -> Stream::sendSize() -> SendGenericPeekBuffer
// (StreamSend.cpp:58). Each pass asks peekAvailable() (BearSSL's _pollRecvBuffer -> _run_until(RECVAPP, nonblocking), whose
// WiFiClient::available() samples getSize() and THEN calls optimistic_yield(100), WiFiClient.cpp:246-257, returning the stale 0) and then
// gives up when avpk == 0 && !inputCanTimeout(); inputCanTimeout() is connected(), which for BearSSL is false as soon as the TCP state
// leaves ESTABLISHED (WiFiClientSecureBearSSL.cpp:264-274, no "|| available()"). A body record and the server's FIN that land during that
// yield are therefore seen in the wrong order: nothing readable, then "closed". written == 0 -> ShortOperation -> returnError()
// (ESP8266HTTPClient.cpp:1095) -> _client->stop() frees the session with the body still in lwIP's queue.
//
// The reader here samples connected() BEFORE available(): the FIN comes after the data, so a close seen first can no longer hide data.
#include <unity.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_manifest_read.h"
#include "ota_retry.h"

namespace {

const std::string kBody = [] {
  std::string s = "{\"firmware_version\":\"0.4.9\",\"channel\":\"prod\",\"builds\":{\"esp8266\":{\"url\":\"https://x/";
  while (s.size() < 991) s += 'a';
  s.resize(991);
  s += '\n';
  return s;
}();

// The most available() + idle() calls any test may make on one connection. The longest legitimate wait is the 5000 ms read timeout at 1 ms per pass
// (one available() and one idle() each, 10000 calls), so this is 5x that: a reader that has lost its timeout, or that no longer idles, reaches it and
// is cut off (see guard()) instead of hanging the whole suite, which it did.
constexpr uint32_t kMaxCalls = 50000;

// The network as the app sees it: bytes lwIP holds, bytes still in flight, and the TCP state.
struct SimConn {
  std::string pending;   // in lwIP's queue, readable
  std::string inflight;  // lands the next time the app yields
  bool finWithInflight = false;
  bool open = true;      // TCP state == ESTABLISHED
  bool staleAvailable = true;  // available() yields after sampling the size, like WiFiClient::available()
  size_t maxPiece = 0;   // 0: everything pending at once
  bool readReturnsNothing = false;
  uint32_t t = 0;
  uint32_t calls = 0;
  bool runaway = false;  // available() + idle() were called more than kMaxCalls times: the reader under test is not giving up

  // Cut the reader off: the connection ends with nothing queued, so a reader that never times out returns Closed instead of looping forever, and the
  // test that expected TimedOut (or Ok) fails on its assertion. runaway names the cause.
  void guard() {
    if (++calls > kMaxCalls) {
      runaway = true;
      open = false;
      pending.clear();
      inflight.clear();
    }
  }
  void yield() {
    pending += inflight;
    inflight.clear();
    if (finWithInflight) open = false;
  }
  // BearSSL's connected(): the TCP state only, pending data is not consulted.
  bool connected() { return open; }
  // WiFiClient::available(): getSize() first, optimistic_yield() only when it was 0, the stale result returned.
  int available() {
    guard();
    int result = static_cast<int>(pending.size());
    if (maxPiece && static_cast<size_t>(result) > maxPiece) result = static_cast<int>(maxPiece);
    if (pending.empty() && staleAvailable) yield();
    return result;
  }
  int read(uint8_t* buf, size_t n) {
    if (readReturnsNothing) return 0;
    size_t k = std::min(n, pending.size());
    if (maxPiece) k = std::min(k, maxPiece);
    memcpy(buf, pending.data(), k);
    pending.erase(0, k);
    if (k) t += 1;  // reading takes time too: progress, not idling, is what keeps the timeout away
    return static_cast<int>(k);
  }
  uint32_t nowMs() { return t; }
  void idle() {
    guard();
    t += 1;
    yield();
  }
};

struct VecSink {
  std::string s;
  size_t cap = 1u << 20;
  bool append(const uint8_t* p, size_t n) {
    if (s.size() + n > cap) return false;
    s.append(reinterpret_cast<const char*>(p), n);
    return true;
  }
};

// The body and the FIN land together while the app is polling: available() says 0, connected() then says closed.
SimConn raceConn() {
  SimConn c;
  c.inflight = kBody;
  c.finWithInflight = true;
  return c;
}

// A model of the core's give-up rule, StreamSend.cpp SendGenericPeekBuffer lines 71-74: ask for data, then ask whether the
// connection can still deliver any. It is the control for the tests below: the simulated race must defeat it.
size_t coreSendSize(SimConn& c, size_t len) {
  size_t written = 0;
  std::string out;
  while (written < len) {
    const int avpk = c.available();
    if (avpk == 0 && !c.connected()) break;  // "no more data to read, ever"
    if (avpk > 0) {
      uint8_t b[256];
      const int r = c.read(b, std::min<size_t>(sizeof(b), len - written));
      if (r > 0) written += static_cast<size_t>(r);
    }
    c.t += 1;
    if (c.t > 5000) break;  // the HTTPClient read timeout
  }
  return written;
}

void test_control_the_cores_peek_loop_loses_the_body_in_that_race() {
  SimConn c = raceConn();
  const size_t written = coreSendSize(c, kBody.size());
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(0, static_cast<uint32_t>(written), "the core gives up with nothing written");
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(static_cast<uint32_t>(kBody.size()), static_cast<uint32_t>(c.pending.size()),
                                   "while the whole body sits in lwIP's queue (and is then freed with the session)");
  TEST_ASSERT_FALSE(c.connected());
}

void test_the_reader_gets_the_whole_body_in_the_same_race() {
  SimConn c = raceConn();
  VecSink out;
  const fry::ManifestRead r = fry::readManifestBody(c, kBody.size(), fry::kManifestReadTimeoutMs, out);
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::Ok), static_cast<int>(r));
  TEST_ASSERT_TRUE(out.s == kBody);
}

void test_data_that_arrived_before_the_close_is_read_after_it() {
  SimConn c;
  c.pending = kBody;
  c.open = false;  // the FIN is already in, the body is all queued
  VecSink out;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::Ok),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), fry::kManifestReadTimeoutMs, out)));
  TEST_ASSERT_TRUE(out.s == kBody);
}

void test_a_body_that_arrives_in_pieces_is_assembled() {
  SimConn c;
  c.pending = kBody.substr(0, 100);
  c.inflight = kBody.substr(100);
  c.finWithInflight = true;
  c.maxPiece = 37;
  VecSink out;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::Ok),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), fry::kManifestReadTimeoutMs, out)));
  TEST_ASSERT_TRUE(out.s == kBody);
}

void test_a_close_before_the_last_byte_is_closed_and_says_how_much_arrived() {
  SimConn c;
  c.pending = kBody.substr(0, 600);
  c.open = false;
  VecSink out;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::Closed),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), fry::kManifestReadTimeoutMs, out)));
  TEST_ASSERT_EQUAL_UINT32(600, static_cast<uint32_t>(out.s.size()));
}

void test_a_close_with_nothing_at_all_is_closed_with_zero() {
  SimConn c;
  c.open = false;
  VecSink out;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::Closed),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), fry::kManifestReadTimeoutMs, out)));
  TEST_ASSERT_EQUAL_UINT32(0, static_cast<uint32_t>(out.s.size()));
}

void test_silence_on_an_open_connection_times_out() {
  SimConn c;  // open, nothing ever comes
  VecSink out;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::TimedOut),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), fry::kManifestReadTimeoutMs, out)));
  TEST_ASSERT_FALSE_MESSAGE(c.runaway, "the reader kept waiting far past its timeout: it never gives up");
  TEST_ASSERT_TRUE_MESSAGE(c.t >= fry::kManifestReadTimeoutMs && c.t < fry::kManifestReadTimeoutMs + 50, "it waited the timeout, not forever");
}

void test_progress_restarts_the_timeout() {
  SimConn c;
  c.pending = kBody.substr(0, 10);
  c.maxPiece = 1;  // one byte per pass: far longer than the timeout in passes, but it never stalls
  c.inflight = kBody.substr(10);
  c.finWithInflight = true;
  VecSink out;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::Ok),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), 50, out)));
  TEST_ASSERT_TRUE(out.s == kBody);
}

void test_a_read_that_returns_nothing_does_not_spin() {
  SimConn c;
  c.pending = kBody;
  c.readReturnsNothing = true;
  VecSink out;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::TimedOut),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), 200, out)));
  TEST_ASSERT_FALSE_MESSAGE(c.runaway, "a read that returns nothing must end in the timeout, not spin");
}

// CONTROL for the cap itself: a reader with no timeout (what removing the check from readManifestBody() makes it), and one that polls without ever
// idling, are stopped by the fake connection within kMaxCalls calls. Without the cap these loops do not end.
void test_control_a_reader_without_a_timeout_is_cut_off_by_the_fake_connection() {
  SimConn c;  // open, nothing ever comes
  uint32_t passes = 0;
  while (c.connected()) {
    c.available();
    c.idle();
    passes++;
  }
  TEST_ASSERT_TRUE(c.runaway);
  TEST_ASSERT_EQUAL_UINT32(kMaxCalls / 2 + 1, passes);  // two calls per pass; the cap trips inside available() of the next pass
  TEST_ASSERT_EQUAL_UINT32(0, static_cast<uint32_t>(c.pending.size()));
  SimConn d;
  uint32_t polls = 0;
  while (d.connected()) {
    d.available();
    polls++;
  }
  TEST_ASSERT_TRUE(d.runaway);
  TEST_ASSERT_EQUAL_UINT32(kMaxCalls + 1, polls);
}

void test_a_sink_that_cannot_hold_the_body_is_no_room() {
  SimConn c;
  c.pending = kBody;
  VecSink out;
  out.cap = 300;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::NoRoom),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), fry::kManifestReadTimeoutMs, out)));
}

void test_it_reads_exactly_the_announced_length() {
  SimConn c;
  c.pending = kBody + "TRAILING-JUNK";
  VecSink out;
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestRead::Ok),
                        static_cast<int>(fry::readManifestBody(c, kBody.size(), fry::kManifestReadTimeoutMs, out)));
  TEST_ASSERT_TRUE(out.s == kBody);
}

void test_the_announced_size_decides_how_the_body_is_read() {
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestSize::Sized), static_cast<int>(fry::classifyManifestSize(992)));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestSize::Sized), static_cast<int>(fry::classifyManifestSize(1)));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestSize::Sized),
                        static_cast<int>(fry::classifyManifestSize(static_cast<int>(fry::kManifestMaxBytes))));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestSize::TooBig),
                        static_cast<int>(fry::classifyManifestSize(static_cast<int>(fry::kManifestMaxBytes) + 1)));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestSize::Unsized), static_cast<int>(fry::classifyManifestSize(0)));
  TEST_ASSERT_EQUAL_INT(static_cast<int>(fry::ManifestSize::Unsized), static_cast<int>(fry::classifyManifestSize(-1)));
  TEST_ASSERT_TRUE_MESSAGE(kBody.size() * 3 < fry::kManifestMaxBytes, "the cap leaves a manifest room to grow");
}

void test_only_transient_failures_are_retried_soon() {
  TEST_ASSERT_TRUE(fry::manifestReadRetrySoon(fry::ManifestRead::Closed));
  TEST_ASSERT_TRUE(fry::manifestReadRetrySoon(fry::ManifestRead::TimedOut));
  TEST_ASSERT_TRUE(fry::manifestReadRetrySoon(fry::ManifestRead::NoRoom));
  TEST_ASSERT_FALSE(fry::manifestReadRetrySoon(fry::ManifestRead::Ok));
  TEST_ASSERT_FALSE_MESSAGE(fry::manifestReadRetrySoon(fry::ManifestRead::TooBig), "a manifest over the cap is not going to shrink");
  TEST_ASSERT_EQUAL_STRING("closed", fry::manifestReadName(fry::ManifestRead::Closed));
  TEST_ASSERT_EQUAL_STRING("timed out", fry::manifestReadName(fry::ManifestRead::TimedOut));
  TEST_ASSERT_EQUAL_STRING("no memory", fry::manifestReadName(fry::ManifestRead::NoRoom));
  TEST_ASSERT_EQUAL_STRING("too big", fry::manifestReadName(fry::ManifestRead::TooBig));
}

// afterCheck() (src/core/ota_client.cpp) composes two bounded runs and takes the shorter wait. Mirrored here.
uint32_t afterCheckWait(bool heapRefused, uint8_t& heapRetries, bool readFailed, uint8_t& readRetries, uint32_t normal) {
  uint32_t wait = fry::otaNextCheckDelayMs(heapRefused, heapRetries, normal);
  const uint32_t readWait = fry::otaNextCheckDelayMs(readFailed, readRetries, normal);
  if (readWait < wait) wait = readWait;
  return wait;
}

void test_a_failed_read_is_retried_in_ten_minutes_at_most_six_times_independently_of_the_heap_run() {
  const uint32_t sixHours = 21600000UL;
  uint8_t hr = 0, rr = 0;
  for (int i = 0; i < 6; i++) TEST_ASSERT_EQUAL_UINT32(fry::kOtaHeapRetryMs, afterCheckWait(false, hr, true, rr, sixHours));
  TEST_ASSERT_EQUAL_UINT32_MESSAGE(sixHours, afterCheckWait(false, hr, true, rr, sixHours), "7th failed read in a row: 6 h");
  // A check that read fine resets the run; a heap refusal in between does not eat the read run's budget.
  TEST_ASSERT_EQUAL_UINT32(sixHours, afterCheckWait(false, hr, false, rr, sixHours));
  TEST_ASSERT_EQUAL_UINT32(fry::kOtaHeapRetryMs, afterCheckWait(true, hr, false, rr, sixHours));
  TEST_ASSERT_EQUAL_UINT32(fry::kOtaHeapRetryMs, afterCheckWait(false, hr, true, rr, sixHours));
  TEST_ASSERT_EQUAL_UINT8(1, rr);
  TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, hr, "the heap run was reset by the check that was not refused");
  // The bench cadence is never stretched.
  TEST_ASSERT_EQUAL_UINT32(45000UL, afterCheckWait(false, hr, true, rr, 45000UL));
}

// ---- call-site pins (source text; ota_client.cpp needs the Arduino core) -----------------------------------------------------

bool readFile(const std::string& path, std::string& out) {
  std::ifstream f(path.c_str(), std::ios::in | std::ios::binary);
  if (!f) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return !out.empty();
}

bool loadSource(const std::string& rel, std::string& out) {
  const std::string self = __FILE__;
  const std::string tail = "test/test_ota_manifest_read/test_main.cpp";
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

int countOf(const std::string& hay, const std::string& needle) {
  int n = 0;
  for (size_t pos = hay.find(needle); pos != std::string::npos; pos = hay.find(needle, pos + needle.size())) n++;
  return n;
}

void test_the_esp8266_manifest_path_does_not_call_getString() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "http.getString()"), "one getString() left: the ESP32's");
  const size_t gs = src.find("String body = http.getString();");
  TEST_ASSERT_TRUE_MESSAGE(gs != std::string::npos, "the ESP32 keeps its getString()");
  const size_t guard = src.rfind("#if defined(ARDUINO_ARCH_ESP8266)", gs);
  const size_t other = src.rfind("#else", gs);
  TEST_ASSERT_TRUE_MESSAGE(guard != std::string::npos && other != std::string::npos && guard < other,
                           "it sits in the #else of an ARDUINO_ARCH_ESP8266 guard");
  TEST_ASSERT_TRUE_MESSAGE(src.find("#endif", other) > gs, "...and no #endif between that #else and it");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "readManifest(http, sec, body)"), "the ESP8266 reads through readManifest()");
}

void test_a_failed_read_ends_the_check_and_marks_it_for_the_early_retry() {
  std::string src;
  TEST_ASSERT_TRUE_MESSAGE(loadSource("src/core/ota_client.cpp", src), "cannot read src/core/ota_client.cpp");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "s_readFailed = true;"), "set once, where the read failed");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::otaNextCheckDelayMs(s_readFailed, s_readRetries, OTA_CHECK_MS)"),
                                "afterCheck() applies the bounded policy to it");
  TEST_ASSERT_EQUAL_INT_MESSAGE(1, countOf(src, "fry::otaNextCheckDelayMs(s_heapRefused, s_heapRetries, OTA_CHECK_MS)"),
                                "...next to, not instead of, the heap one");
  const size_t at = src.find("readManifest(http, sec, body)");
  TEST_ASSERT_TRUE(at != std::string::npos);
  const size_t fail = src.find("s_readFailed = true;", at);
  const size_t eval = src.find("evaluateManifest(body, plan)", at);
  TEST_ASSERT_TRUE_MESSAGE(fail != std::string::npos && eval != std::string::npos && fail < eval,
                           "the read failure returns before the manifest is parsed");
  const size_t ret = src.find("return false;", fail);
  TEST_ASSERT_TRUE_MESSAGE(ret != std::string::npos && ret < eval, "...with return false");
  TEST_ASSERT_TRUE_MESSAGE(src.find("manifest read failed") != std::string::npos, "and says so in its own words");
  TEST_ASSERT_EQUAL_INT_MESSAGE(
      1, countOf(src, "bool checkNow() {\n#if defined(ARDUINO_ARCH_ESP8266)\n  s_heapRefused = false;\n#endif\n#if defined(ARDUINO_ARCH_ESP8266)\n  s_readFailed = false;\n#endif"),
      "cleared at the top of every checkNow(), after the heap flag's own prologue");
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}
void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_control_the_cores_peek_loop_loses_the_body_in_that_race);
  RUN_TEST(test_the_reader_gets_the_whole_body_in_the_same_race);
  RUN_TEST(test_data_that_arrived_before_the_close_is_read_after_it);
  RUN_TEST(test_a_body_that_arrives_in_pieces_is_assembled);
  RUN_TEST(test_a_close_before_the_last_byte_is_closed_and_says_how_much_arrived);
  RUN_TEST(test_a_close_with_nothing_at_all_is_closed_with_zero);
  RUN_TEST(test_silence_on_an_open_connection_times_out);
  RUN_TEST(test_progress_restarts_the_timeout);
  RUN_TEST(test_a_read_that_returns_nothing_does_not_spin);
  RUN_TEST(test_control_a_reader_without_a_timeout_is_cut_off_by_the_fake_connection);
  RUN_TEST(test_a_sink_that_cannot_hold_the_body_is_no_room);
  RUN_TEST(test_it_reads_exactly_the_announced_length);
  RUN_TEST(test_the_announced_size_decides_how_the_body_is_read);
  RUN_TEST(test_only_transient_failures_are_retried_soon);
  RUN_TEST(test_a_failed_read_is_retried_in_ten_minutes_at_most_six_times_independently_of_the_heap_run);
  RUN_TEST(test_the_esp8266_manifest_path_does_not_call_getString);
  RUN_TEST(test_a_failed_read_ends_the_check_and_marks_it_for_the_early_retry);
  return UNITY_END();
}
