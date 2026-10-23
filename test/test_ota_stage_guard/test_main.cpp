// A downloaded image that fails its sha256 must not be staged for the bootloader (ESP8266).
//
// Field evidence (esp6 void soak, the soak120_hm_ntp "hang"): boards flashed right after a sha-mismatch download session booted the REJECTED image
// ("got 77f551ec") instead of the freshly flashed one. ota_client.cpp called Update.end(false) on the mismatch. The ESP8266 Updater has no abort();
// its end(false) drops an update only while the stream is unfinished or an error is set (cores/esp8266/Updater.cpp:226-232). After a complete,
// error-free write it falls through to eboot_command_write(ACTION_COPY_RAW) (:350): the rejected image is installed at the next reboot.
//
// lib/fry_core/ota_stage_guard.h keeps the stream's last byte out of the Updater until the digest has been compared, so the update is unfinished
// when it is dropped. ota_client.cpp needs the Arduino core and cannot run natively, so this test has two halves, like test_ota_stack:
//   1. a MODEL of the Updater (begin/write/_writeBuffer/end/_verifyEnd as in core 3.30102.0, each method names the lines it follows) and of the
//      eboot command, driven through HeldTailWriter over a grid of image sizes, chunkings and buffer sizes;
//   2. pins on the ESP8266 view of ota_client.cpp: every discard goes through the writer, the mismatch branch also clears the eboot command,
//      and the ESP32 view is the code it was.
// Controls: a writer that holds nothing (the old behaviour) is caught by the same grid, and each source pin is broken in memory to see it fail.
#include <unity.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "ota_stage_guard.h"

namespace {

// ---- the eboot command in RTC memory --------------------------------------------------------------------------------------------------------

struct Eboot {
  int writes = 0;       // eboot_command_write() calls since reset()
  bool valid = false;   // a valid ACTION_COPY_RAW command is in RTC memory: the next boot copies it
  uint32_t addr = 0;    // args[0]: where the staged image is
  uint32_t size = 0;    // args[2]
};
Eboot g_eboot;

// ---- a model of UpdaterClass (core 3.30102.0), signing off (no ARDUINO_SIGNING in platformio.ini) and no setMD5() (ota_client.cpp never calls it) --

constexpr size_t kSector = 4096;
constexpr uint32_t kUpdateEnd = 0x1F0000;  // FS_start - 0x40200000 on the bench boards' map (:124)

class ModelUpdater {
 public:
  enum { kOk = 0, kWrite = 1, kErase = 2, kSpace = 3, kNoData = 5, kMagic = 8 };

  explicit ModelUpdater(size_t bufferSize) : bufferSize_(bufferSize), flash_(0x200000, 0xFF) {}

  // Updater.cpp:68-... begin(): refused while an update runs (:69); a fresh update starts with no error; buffer of 4096 or 256 B (:172-177).
  bool begin(size_t size) {
    if (size_ > 0) return false;
    if (size == 0) {
      error_ = kNoData;
      return false;
    }
    reset();
    error_ = kOk;
    const size_t rounded = (size + kSector - 1) & ~(kSector - 1);
    startAddress_ = kUpdateEnd - static_cast<uint32_t>(rounded);
    currentAddress_ = startAddress_;
    size_ = size;
    buffer_.assign(bufferSize_, 0);
    return true;
  }

  // Updater.cpp:436-467 write()
  size_t write(uint8_t* data, size_t len) {
    if (hasError() || !isRunning()) return 0;
    if (progress() + bufferLen_ + len > size_) {
      error_ = kSpace;
      return 0;
    }
    size_t left = len;
    while ((bufferLen_ + left) > bufferSize_) {
      const size_t toBuff = bufferSize_ - bufferLen_;
      std::memcpy(buffer_.data() + bufferLen_, data + (len - left), toBuff);
      bufferLen_ += toBuff;
      if (!writeBuffer()) return len - left;
      left -= toBuff;
    }
    std::memcpy(buffer_.data() + bufferLen_, data + (len - left), left);
    bufferLen_ += left;
    if (bufferLen_ == remaining()) {
      if (!writeBuffer()) return len - left;
    }
    return len;
  }

  // Updater.cpp:212-371 end(): :213-218 idle, :221 no data, :226-232 premature end, :234-239 evenIfRemaining, :339-342 _verifyEnd(), :344-350 staging.
  bool end(bool evenIfRemaining) {
    if (size_ == 0) {
      reset();
      return false;
    }
    if (!progress()) error_ = kNoData;
    if (hasError() || (!isFinished() && !evenIfRemaining)) {
      reset();
      return false;
    }
    if (evenIfRemaining) {
      if (bufferLen_ > 0) writeBuffer();
      size_ = progress();
    }
    if (!verifyEnd()) {
      reset();
      return false;
    }
    g_eboot.writes++;
    g_eboot.valid = true;
    g_eboot.addr = startAddress_;
    g_eboot.size = static_cast<uint32_t>(size_);
    reset();
    return true;
  }

  // Updater.h:163-168
  bool hasError() const { return error_ != kOk; }
  bool isRunning() const { return size_ > 0; }
  bool isFinished() const { return currentAddress_ == startAddress_ + size_; }
  size_t progress() const { return currentAddress_ - startAddress_; }
  size_t remaining() const { return size_ - (currentAddress_ - startAddress_); }

  uint32_t startAddress() const { return startAddress_; }
  const std::vector<uint8_t>& flash() const { return flash_; }
  // test hook: the flush with this 0-based index (since the last begin) fails like a flash write error
  void failFlush(int index) { failAt_ = index; }

 private:
  // Updater.cpp:375-434 _writeBuffer(): a failed erase or write moves _currentAddress to the end and sets the error (:411-414, :423-426).
  bool writeBuffer() {
    if (flushes_++ == failAt_) {
      currentAddress_ = startAddress_ + static_cast<uint32_t>(size_);
      error_ = kWrite;
      return false;
    }
    std::memcpy(flash_.data() + currentAddress_, buffer_.data(), bufferLen_);
    currentAddress_ += static_cast<uint32_t>(bufferLen_);
    bufferLen_ = 0;
    return true;
  }
  // Updater.cpp:485-...: a U_FLASH image must start with 0xE9
  bool verifyEnd() {
    if (flash_[startAddress_] != 0xE9) {
      currentAddress_ = startAddress_;
      error_ = kMagic;
      return false;
    }
    return true;
  }
  // Updater.cpp:47-66
  void reset() {
    buffer_.clear();
    bufferLen_ = 0;
    startAddress_ = 0;
    currentAddress_ = 0;
    size_ = 0;
    flushes_ = 0;
    failAt_ = -1;
  }

  size_t bufferSize_;
  std::vector<uint8_t> flash_;
  std::vector<uint8_t> buffer_;
  size_t bufferLen_ = 0;
  uint32_t startAddress_ = 0;
  uint32_t currentAddress_ = 0;
  size_t size_ = 0;
  int error_ = kOk;
  int flushes_ = 0;
  int failAt_ = -1;
};

// The behaviour before this change: every byte goes to the Updater, and the sha256 mismatch calls end(false) (what ota_client.cpp did).
template <class U>
class PassThroughWriter {
 public:
  PassThroughWriter(U& up, size_t) : up_(up) {}
  bool write(uint8_t* d, size_t n) { return n == 0 || up_.write(d, n) == n; }
  bool commit() { return up_.end(true); }
  void discard() { up_.end(false); }

 private:
  U& up_;
};

std::vector<uint8_t> makeImage(size_t n, uint32_t seed) {
  std::vector<uint8_t> v(n);
  uint32_t x = seed * 2654435761u + 12345u;
  for (size_t i = 0; i < n; i++) {
    x = x * 1664525u + 1013904223u;
    v[i] = static_cast<uint8_t>(x >> 24);
  }
  v[0] = 0xE9;
  return v;
}

const size_t kBufferSizes[] = {256, 4096};
const size_t kSizes[] = {1, 2, 3, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2048, 4095, 4096, 4097, 5000, 8191, 8192, 8193, 12289, 100003};
const size_t kChunks[] = {1, 3, 255, 256, 1000, 1024, 4096};

void resetWorld() { g_eboot = Eboot(); }

// Streams `image` through W in `chunk`-byte reads (the last read short), as the download loop does.
template <template <class> class W>
bool streamAll(W<ModelUpdater>& w, std::vector<uint8_t>& image, size_t chunk) {
  size_t done = 0;
  while (done < image.size()) {
    const size_t n = std::min(chunk, image.size() - done);
    if (!w.write(image.data() + done, n)) return false;
    done += n;
  }
  return true;
}

// The sha256 mismatch: the whole stream is in, then the update is dropped. true when nothing was staged, the Updater is idle and begin() works again.
template <template <class> class W>
bool mismatchNeverStages(size_t bufSize, size_t n, size_t chunk) {
  resetWorld();
  ModelUpdater up(bufSize);
  std::vector<uint8_t> image = makeImage(n, static_cast<uint32_t>(n * 31 + chunk));
  if (!up.begin(n)) return false;
  W<ModelUpdater> w(up, n);
  if (!streamAll(w, image, chunk)) return false;
  w.discard();
  if (g_eboot.writes != 0 || g_eboot.valid) return false;
  if (up.isRunning()) return false;
  if (!up.begin(n)) return false;  // the next OTA attempt can start
  up.end(false);
  return g_eboot.writes == 0;
}

// The sha256 matched: commit stages the streamed image exactly once, at the Updater's start address, with its size and bytes.
template <template <class> class W>
bool matchStagesImage(size_t bufSize, size_t n, size_t chunk) {
  resetWorld();
  ModelUpdater up(bufSize);
  std::vector<uint8_t> image = makeImage(n, static_cast<uint32_t>(n * 17 + chunk));
  if (!up.begin(n)) return false;
  const uint32_t start = up.startAddress();
  W<ModelUpdater> w(up, n);
  if (!streamAll(w, image, chunk)) return false;
  if (!w.commit()) return false;
  if (g_eboot.writes != 1 || !g_eboot.valid || g_eboot.addr != start || g_eboot.size != n) return false;
  if (up.isRunning()) return false;
  return std::memcmp(up.flash().data() + start, image.data(), n) == 0;
}

// ---- tests: the model ------------------------------------------------------------------------------------------------------------------------

void test_model_reproduces_the_field_defect() {
  // The old sequence on the model: the whole stream, then end(false). The rejected image is staged for the bootloader.
  for (size_t buf : kBufferSizes) {
    for (size_t n : kSizes) {
      resetWorld();
      ModelUpdater up(buf);
      std::vector<uint8_t> image = makeImage(n, 7);
      TEST_ASSERT_TRUE(up.begin(n));
      size_t done = 0;
      while (done < n) {
        const size_t k = std::min<size_t>(1024, n - done);
        TEST_ASSERT_EQUAL_UINT32(k, up.write(image.data() + done, k));
        done += k;
      }
      TEST_ASSERT_TRUE(up.isFinished());
      up.end(false);
      TEST_ASSERT_EQUAL_INT_MESSAGE(1, g_eboot.writes, "end(false) after a complete write must stage (this is the defect being modelled)");
      TEST_ASSERT_TRUE(g_eboot.valid);
      TEST_ASSERT_EQUAL_UINT32(n, g_eboot.size);
    }
  }
}

void test_the_other_early_exits_never_stage() {
  // ota_client.cpp's other paths after Update.begin(): no download buffer (nothing written), a short or stalled stream, a flash write error.
  for (size_t buf : kBufferSizes) {
    for (size_t n : kSizes) {
      // no data: end(false) right after begin
      resetWorld();
      ModelUpdater a(buf);
      TEST_ASSERT_TRUE(a.begin(n));
      a.end(false);
      TEST_ASSERT_EQUAL_INT(0, g_eboot.writes);
      TEST_ASSERT_FALSE(a.isRunning());
      // incomplete stream: cut after k bytes, every k in a spread of positions, then end(false)
      const size_t cuts[] = {1, n / 3, n / 2, n - 1};
      for (size_t k : cuts) {
        if (k == 0 || k >= n) continue;
        resetWorld();
        ModelUpdater b(buf);
        std::vector<uint8_t> image = makeImage(n, 11);
        TEST_ASSERT_TRUE(b.begin(n));
        TEST_ASSERT_EQUAL_UINT32(k, b.write(image.data(), k));
        b.end(false);
        TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_eboot.writes, "an incomplete stream must not stage");
        TEST_ASSERT_FALSE(b.isRunning());
      }
      // flash write error on flush f, then end(false): _currentAddress is at the end but hasError() is tested first (:226)
      const size_t flushes = n / buf + 1;
      for (size_t f = 0; f < flushes && f < 6; f++) {
        resetWorld();
        ModelUpdater c(buf);
        std::vector<uint8_t> image = makeImage(n, 13);
        TEST_ASSERT_TRUE(c.begin(n));
        c.failFlush(static_cast<int>(f));
        size_t done = 0;
        bool failed = false;
        while (done < n && !failed) {
          const size_t k = std::min<size_t>(1024, n - done);
          failed = c.write(image.data() + done, k) != k;
          done += k;
        }
        if (failed) {
          c.end(false);
          TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_eboot.writes, "a flash error must not stage");
          TEST_ASSERT_FALSE(c.isRunning());
        }
      }
    }
  }
}

void test_discard_after_the_whole_stream_never_stages() {
  for (size_t buf : kBufferSizes)
    for (size_t n : kSizes)
      for (size_t chunk : kChunks) {
        const bool ok = mismatchNeverStages<fry::HeldTailWriter>(buf, n, chunk);
        if (!ok) {
          char m[96];
          std::snprintf(m, sizeof m, "buffer %u size %u chunk %u", static_cast<unsigned>(buf), static_cast<unsigned>(n), static_cast<unsigned>(chunk));
          TEST_FAIL_MESSAGE(m);
        }
      }
}

void test_the_updater_is_unfinished_when_the_mismatch_is_known() {
  for (size_t buf : kBufferSizes)
    for (size_t n : kSizes)
      for (size_t chunk : kChunks) {
        resetWorld();
        ModelUpdater up(buf);
        std::vector<uint8_t> image = makeImage(n, 3);
        TEST_ASSERT_TRUE(up.begin(n));
        fry::HeldTailWriter<ModelUpdater> w(up, n);
        TEST_ASSERT_TRUE(streamAll(w, image, chunk));
        TEST_ASSERT_FALSE_MESSAGE(up.isFinished(), "the held byte must keep the Updater unfinished");
        TEST_ASSERT_TRUE(up.progress() < n);
      }
}

void test_commit_stages_the_streamed_image_once() {
  for (size_t buf : kBufferSizes)
    for (size_t n : kSizes)
      for (size_t chunk : kChunks) {
        const bool ok = matchStagesImage<fry::HeldTailWriter>(buf, n, chunk);
        if (!ok) {
          char m[96];
          std::snprintf(m, sizeof m, "buffer %u size %u chunk %u", static_cast<unsigned>(buf), static_cast<unsigned>(n), static_cast<unsigned>(chunk));
          TEST_FAIL_MESSAGE(m);
        }
      }
}

void test_commit_without_the_whole_stream_stages_nothing() {
  for (size_t buf : kBufferSizes)
    for (size_t n : kSizes) {
      if (n < 2) continue;
      for (size_t cut : {size_t(1), n / 2, n - 1}) {
        resetWorld();
        ModelUpdater up(buf);
        std::vector<uint8_t> image = makeImage(n, 5);
        TEST_ASSERT_TRUE(up.begin(n));
        fry::HeldTailWriter<ModelUpdater> w(up, n);
        TEST_ASSERT_TRUE(w.write(image.data(), cut));
        TEST_ASSERT_FALSE(w.commit());
        TEST_ASSERT_EQUAL_INT(0, g_eboot.writes);
        TEST_ASSERT_FALSE(up.isRunning());
      }
    }
}

void test_a_flash_error_while_streaming_or_on_the_last_byte_stages_nothing() {
  for (size_t buf : kBufferSizes)
    for (size_t n : {size_t(300), size_t(4097), size_t(9000), size_t(100003)}) {
      for (int f = 0; f < 8; f++) {
        resetWorld();
        ModelUpdater up(buf);
        std::vector<uint8_t> image = makeImage(n, 21);
        TEST_ASSERT_TRUE(up.begin(n));
        up.failFlush(f);
        fry::HeldTailWriter<ModelUpdater> w(up, n);
        bool ok = true;
        size_t done = 0;
        while (done < n && ok) {
          const size_t k = std::min<size_t>(1024, n - done);
          ok = w.write(image.data() + done, k);
          done += k;
        }
        bool commitFailed = false;
        if (ok) {
          ok = w.commit();  // the held byte's flush can fail too
          commitFailed = !ok;
        }
        if (!ok) {
          // ota_client.cpp does not discard after a failed commit(), so commit() itself must leave the Updater idle
          if (commitFailed) TEST_ASSERT_FALSE_MESSAGE(up.isRunning(), "a failed commit() must leave the Updater idle");
          w.discard();
          TEST_ASSERT_EQUAL_INT_MESSAGE(0, g_eboot.writes, "a flash error must never stage");
          TEST_ASSERT_FALSE(up.isRunning());
          TEST_ASSERT_TRUE(up.begin(n));  // and the next attempt starts
          up.end(false);
        }
      }
    }
}

void test_a_stream_longer_than_declared_is_refused_and_stages_nothing() {
  for (size_t buf : kBufferSizes) {
    for (size_t extra : {size_t(1), size_t(5), size_t(1024)}) {
      const size_t n = 5000;
      resetWorld();
      ModelUpdater up(buf);
      std::vector<uint8_t> image = makeImage(n + extra, 9);
      TEST_ASSERT_TRUE(up.begin(n));
      fry::HeldTailWriter<ModelUpdater> w(up, n);
      bool ok = true;
      size_t done = 0;
      while (done < image.size() && ok) {
        const size_t k = std::min<size_t>(1024, image.size() - done);
        ok = w.write(image.data() + done, k);
        done += k;
      }
      TEST_ASSERT_FALSE_MESSAGE(ok, "bytes past the declared size must be refused");
      w.discard();
      TEST_ASSERT_EQUAL_INT(0, g_eboot.writes);
      TEST_ASSERT_FALSE(up.isRunning());
    }
  }
}

void test_no_write_after_the_last_byte_was_taken() {
  resetWorld();
  ModelUpdater up(256);
  std::vector<uint8_t> image = makeImage(10, 1);
  TEST_ASSERT_TRUE(up.begin(10));
  fry::HeldTailWriter<ModelUpdater> w(up, 10);
  TEST_ASSERT_TRUE(w.write(image.data(), 10));
  uint8_t extra = 0;
  TEST_ASSERT_FALSE(w.write(&extra, 1));
  w.discard();
  TEST_ASSERT_EQUAL_INT(0, g_eboot.writes);
}

void test_controls_the_old_behaviour_is_caught() {
  // The same grid with a writer that holds nothing must fail on every size: the grid can see the defect.
  int caught = 0, cells = 0;
  for (size_t buf : kBufferSizes)
    for (size_t n : kSizes)
      for (size_t chunk : kChunks) {
        cells++;
        if (!mismatchNeverStages<PassThroughWriter>(buf, n, chunk)) caught++;
      }
  TEST_ASSERT_EQUAL_INT_MESSAGE(cells, caught, "the pass-through writer (old behaviour) must stage in every cell");
  // and the writer that does hold passes the very same grid, so the failures above are the defect and not the harness
  int clean = 0;
  for (size_t buf : kBufferSizes)
    for (size_t n : kSizes)
      for (size_t chunk : kChunks)
        if (mismatchNeverStages<fry::HeldTailWriter>(buf, n, chunk)) clean++;
  TEST_ASSERT_EQUAL_INT(cells, clean);
  // pass-through commit still stages, so the success path is not what distinguishes them
  TEST_ASSERT_TRUE(matchStagesImage<PassThroughWriter>(4096, 5000, 1024));
}

// ---- source pins: the ESP8266 view of ota_client.cpp --------------------------------------------------------------------------------------------

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
  const std::string tail = "test/test_ota_stage_guard/test_main.cpp";
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

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r')) a++;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r')) b--;
  return s.substr(a, b - a);
}

// What the compiler sees for one chip: the lines of `text` that survive the ARDUINO_ARCH_ESP8266 conditionals (`#if defined(...)`,
// `#if !defined(...)`, `#else`, `#endif`; any other #if is treated as true). Directive lines themselves are dropped.
std::string chipView(const std::string& text, bool esp8266) {
  std::istringstream in(text);
  std::string line, out;
  std::vector<bool> active{true};
  std::vector<bool> parent{true};
  std::vector<bool> cond{true};
  while (std::getline(in, line)) {
    const std::string t = trim(line);
    if (t.rfind("#if", 0) == 0) {
      bool c = true;
      if (t.find("defined(ARDUINO_ARCH_ESP8266)") != std::string::npos) {
        const bool negated = t.find("!defined(ARDUINO_ARCH_ESP8266)") != std::string::npos;
        c = negated ? !esp8266 : esp8266;
      }
      parent.push_back(active.back());
      cond.push_back(c);
      active.push_back(active.back() && c);
    } else if (t.rfind("#else", 0) == 0 && active.size() > 1) {
      const size_t i = active.size() - 1;
      active[i] = parent[i] && !cond[i];
    } else if (t.rfind("#endif", 0) == 0 && active.size() > 1) {
      active.pop_back();
      parent.pop_back();
      cond.pop_back();
    } else if (active.back()) {
      out += line;
      out += '\n';
    }
  }
  return out;
}

// Blanks // and /* */ comments and the contents of string literals, so a pin cannot be satisfied or tripped by prose.
std::string blankNonCode(const std::string& s) {
  std::string out(s.size(), ' ');
  enum State { Code, LineComment, BlockComment, Str } st = Code;
  for (size_t i = 0; i < s.size(); i++) {
    const char c = s[i];
    const char n = i + 1 < s.size() ? s[i + 1] : '\0';
    if (c == '\n') out[i] = '\n';
    switch (st) {
      case Code:
        if (c == '/' && n == '/') {
          st = LineComment;
          i++;
        } else if (c == '/' && n == '*') {
          st = BlockComment;
          i++;
        } else if (c == '"') {
          st = Str;
          out[i] = '"';
        } else if (c != '\n') {
          out[i] = c;
        }
        break;
      case LineComment:
        if (c == '\n') st = Code;
        break;
      case BlockComment:
        if (c == '*' && n == '/') {
          st = Code;
          i++;
        }
        break;
      case Str:
        if (c == '\\') {
          i++;
        } else if (c == '"') {
          st = Code;
          out[i] = '"';
        }
        break;
    }
  }
  return out;
}

// The text of downloadAndApply(): from its signature to the next line that is just "}" at column 0.
bool downloadText(const std::string& src, std::string& body) {
  const size_t a = src.find("FRY_OTA_ESP8266_NOINLINE bool downloadAndApply(");
  if (a == std::string::npos) return false;
  const size_t b = src.find("\n}\n", a);
  if (b == std::string::npos) return false;
  body = src.substr(a, b - a);
  return true;
}

// The mismatch branch inside it: from `if (got != want) {` to the `return false;` that ends it.
bool mismatchBranch(const std::string& fn, std::string& branch) {
  const size_t a = fn.find("if (got != want) {");
  if (a == std::string::npos) return false;
  const size_t b = fn.find("return false;", a);
  if (b == std::string::npos) return false;
  branch = fn.substr(a, b - a);
  return true;
}

// Returns "" when the source is right, else why not. `src` is the whole ota_client.cpp (or a deliberately broken copy of it).
std::string inspect(const std::string& src) {
  const std::string e8266 = chipView(src, true);
  const std::string e32 = chipView(src, false);
  std::string d8266, d32;
  if (!downloadText(e8266, d8266) || !downloadText(e32, d32)) return "downloadAndApply() not found";
  const std::string c8266 = blankNonCode(d8266);
  const std::string c32 = blankNonCode(d32);

  if (countOf(e8266, "\n#include \"ota_stage_guard.h\"") != 1) return "ESP8266 view lacks ota_stage_guard.h";
  if (countOf(e32, "ota_stage_guard.h") != 0) return "ESP32 view includes ota_stage_guard.h";
  if (countOf(e8266, "\n#include <eboot_command.h>") != 1) return "ESP8266 view lacks eboot_command.h";
  if (countOf(c8266, "fry::HeldTailWriter<UpdaterClass> upd(Update, static_cast<size_t>(len));") != 1) return "ESP8266: no HeldTailWriter built from the Update.begin() size";
  if (c8266.find("Update.begin(len)") == std::string::npos || c8266.find("Update.begin(len)") > c8266.find("HeldTailWriter")) return "ESP8266: the writer must come after Update.begin()";
  if (countOf(c8266, "Update.end(") != 0) return "ESP8266: a direct Update.end() is left (the Updater would stage a complete stream)";
  if (countOf(c8266, "Update.write(") != 0) return "ESP8266: a direct Update.write() bypasses the held byte";
  if (countOf(c8266, "Update.abort(") != 0) return "ESP8266: the Updater has no abort()";
  if (countOf(c8266, "upd.write(buf, r)") != 1) return "ESP8266: the download loop must write through upd";
  if (countOf(c8266, "upd.commit()") != 1) return "ESP8266: the success path must commit through upd";
  if (countOf(c8266, "upd.discard()") != 4) return "ESP8266: expected 4 discard sites (no buffer, write failed, incomplete, sha mismatch)";
  if (countOf(c8266, "eboot_command_clear()") != 1) return "ESP8266: expected one eboot_command_clear(), in the sha mismatch branch";

  std::string mm;
  if (!mismatchBranch(c8266, mm)) return "ESP8266: sha mismatch branch not found";
  const size_t dis = mm.find("upd.discard()");
  const size_t clr = mm.find("eboot_command_clear()");
  if (dis == std::string::npos) return "ESP8266: the mismatch branch does not discard through upd";
  if (clr == std::string::npos) return "ESP8266: the mismatch branch does not clear the eboot command";
  if (clr < dis) return "ESP8266: the eboot command must be cleared after the discard";

  // the ESP32 family is the code it was
  if (countOf(c32, "Update.abort()") != 3) return "ESP32: expected the 3 Update.abort() calls";
  if (countOf(c32, "Update.write(buf, r)") != 1) return "ESP32: Update.write(buf, r) changed";
  if (countOf(c32, "Update.end(true)") != 1) return "ESP32: Update.end(true) changed";
  if (c32.find("upd.write") != std::string::npos || c32.find("upd.commit") != std::string::npos || c32.find("upd.discard") != std::string::npos ||
      c32.find("HeldTailWriter") != std::string::npos || c32.find("eboot_command") != std::string::npos) {
    return "ESP32: the ESP8266 mechanism leaked into the ESP32 view";
  }
  return "";
}

std::string edit(std::string s, const std::string& from, const std::string& to) {
  const size_t p = s.find(from);
  TEST_ASSERT_TRUE_MESSAGE(p != std::string::npos, ("control edit: pattern not found: " + from).c_str());
  s.replace(p, from.size(), to);
  return s;
}

void test_sources_are_readable() {
  std::string s, h;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", s));
  TEST_ASSERT_TRUE(loadSource("lib/fry_core/ota_stage_guard.h", h));
}

void test_ota_client_discards_through_the_writer_on_esp8266() {
  std::string s;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", s));
  const std::string why = inspect(s);
  TEST_ASSERT_EQUAL_STRING("", why.c_str());
}

void test_pin_controls_each_break_is_caught() {
  std::string s;
  TEST_ASSERT_TRUE(loadSource("src/core/ota_client.cpp", s));
  TEST_ASSERT_EQUAL_STRING("", inspect(s).c_str());

  // the shipped defect: the mismatch branch back to Update.end(false)
  TEST_ASSERT_TRUE(inspect(edit(s, "upd.discard();\n    eboot_command_clear();", "Update.end(false);\n    eboot_command_clear();")) != "");
  // discard without the defensive clear, and the clear before the discard
  TEST_ASSERT_TRUE(inspect(edit(s, "upd.discard();\n    eboot_command_clear();", "upd.discard();")) != "");
  TEST_ASSERT_TRUE(inspect(edit(s, "upd.discard();\n    eboot_command_clear();", "eboot_command_clear();\n    upd.discard();")) != "");
  // the success path back to the Updater's own end(true) / the loop back to Update.write
  TEST_ASSERT_TRUE(inspect(edit(s, "if (!upd.commit()) {", "if (!Update.end(true)) {")) != "");
  TEST_ASSERT_TRUE(inspect(edit(s, "if (!upd.write(buf, r)) {", "if (Update.write(buf, r) != static_cast<size_t>(r)) {")) != "");
  // the writer dropped, the clear dropped from the ESP8266 view, the include gone
  TEST_ASSERT_TRUE(inspect(edit(s, "fry::HeldTailWriter<UpdaterClass> upd(Update, static_cast<size_t>(len));", "")) != "");
  TEST_ASSERT_TRUE(inspect(edit(s, "#include <eboot_command.h>", "")) != "");
  TEST_ASSERT_TRUE(inspect(edit(s, "#include \"ota_stage_guard.h\"", "")) != "");
  // an ESP32-view change
  TEST_ASSERT_TRUE(inspect(edit(s, "Update.abort();", "Update.end(false);")) != "");
}

}  // namespace

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_model_reproduces_the_field_defect);
  RUN_TEST(test_the_other_early_exits_never_stage);
  RUN_TEST(test_discard_after_the_whole_stream_never_stages);
  RUN_TEST(test_the_updater_is_unfinished_when_the_mismatch_is_known);
  RUN_TEST(test_commit_stages_the_streamed_image_once);
  RUN_TEST(test_commit_without_the_whole_stream_stages_nothing);
  RUN_TEST(test_a_flash_error_while_streaming_or_on_the_last_byte_stages_nothing);
  RUN_TEST(test_a_stream_longer_than_declared_is_refused_and_stages_nothing);
  RUN_TEST(test_no_write_after_the_last_byte_was_taken);
  RUN_TEST(test_controls_the_old_behaviour_is_caught);
  RUN_TEST(test_sources_are_readable);
  RUN_TEST(test_ota_client_discards_through_the_writer_on_esp8266);
  RUN_TEST(test_pin_controls_each_break_is_caught);
  return UNITY_END();
}
