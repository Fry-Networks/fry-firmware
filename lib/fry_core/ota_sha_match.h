#pragma once
// ESP8266 OTA: the sha256 check of the image, without a String.
//
// downloadAndApply() compared two Strings (`String got = hex; ... String want = shaExpect; ... if (got != want)`). A String that cannot get its
// buffer invalidates itself to the empty string (core 3.30102.0, cores/esp8266/WString.cpp: copy() :273-277 calls invalidate() :183-186 when
// reserve() fails; operator=(const String&) :301-309 likewise), and two empty Strings are equal (equals() :542-544: equal lengths, then
// compareTo() :531-540 returns 0 when either buffer is empty). A 64-character digest never fits the 11-character SSO buffer (SSOSIZE 12, WString.h:316),
// and the whole-stream sweeps passed with the free heap down to 512 B at the end of the stream, so both copies can fail together: "got == want" then
// holds for ANY image, and the Updater is committed with a digest that never matched. The compare must not depend on an allocation.
//
// sha256HexMatches() compares the two character buffers that already exist (DownloadWork::hex and the manifest's String) and allocates nothing.
// It is true only when `expect` is exactly 64 characters long and equals the 64-character digest `hex`, ignoring ASCII case. An empty or invalid
// expected String has length 0 and never matches, so a failed allocation anywhere on that side is a mismatch, never a match.
#include <cstddef>

namespace fry {

inline char asciiLowerChar(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + ('a' - 'A')) : c; }

// Lowercases a NUL-terminated string in place (the mismatch log prints the digest in lowercase, as it always did).
inline void asciiLowerInPlace(char* s) {
  if (!s) return;
  for (; *s; ++s) *s = asciiLowerChar(*s);
}

// `hex`: the NUL-terminated digest just computed (64 characters). `expect` / `expectLen`: the manifest's digest and its length.
inline bool sha256HexMatches(const char* hex, const char* expect, size_t expectLen) {
  if (!hex || !expect || expectLen != 64) return false;
  for (size_t i = 0; i < 64; ++i) {
    if (hex[i] == '\0') return false;  // a digest shorter than 64 characters is not a digest
    if (asciiLowerChar(hex[i]) != asciiLowerChar(expect[i])) return false;
  }
  return hex[64] == '\0';  // ...and one longer is not either
}

}  // namespace fry
