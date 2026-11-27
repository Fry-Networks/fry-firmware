#pragma once
// "a.b.c.d" of an IPAddress. arduino-pico has IPAddress::toString(); the arduino-api IPAddress LibreTiny uses has no such member.
#include <Arduino.h>

namespace fry_boards {

inline String ipToString(const IPAddress& ip) {
  String s;
  s.reserve(16);
  for (int i = 0; i < 4; i++) {
    if (i) s += '.';
    s += String(static_cast<unsigned>(ip[i]));
  }
  return s;
}

}  // namespace fry_boards
