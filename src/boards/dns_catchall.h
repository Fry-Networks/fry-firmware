#pragma once
// Captive-portal DNS: answers every A query with the setup AP's own address (PROTOCOL.md section 3, "DNS catch-all on port 53"),
// so a phone that joined the open setup AP lands on the portal. Over WiFiUDP only, so it runs on every Arduino core the boards
// use (LibreTiny ships no DNSServer). processNextRequest() is bounded: it handles at most one datagram per call.
#include <Arduino.h>
#include <WiFiUdp.h>

namespace fry_boards {

class DnsCatchAll {
 public:
  bool start(const IPAddress& answer) {
    answer_ = answer;
    return udp_.begin(53);
  }
  void stop() { udp_.stop(); }

  void processNextRequest() {
    const int len = udp_.parsePacket();
    if (len <= 0) return;
    uint8_t q[256];
    if (len < 12 || len > static_cast<int>(sizeof(q) - 16)) {  // header, and room for the 16 answer bytes
      drain(len);
      return;
    }
    const int got = udp_.read(q, len);
    if (got != len) return;
    // QR=0 (a query), opcode 0, exactly one question: anything else is not ours to answer.
    const bool isQuery = (q[2] & 0xF8) == 0x00 && q[4] == 0 && q[5] == 1;
    if (!isQuery) return;
    // Question: name labels to the zero byte, then QTYPE and QCLASS.
    int p = 12;
    while (p < len && q[p] != 0) p += q[p] + 1;
    if (p + 5 > len) return;
    const int qend = p + 5;
    const uint16_t qtype = (q[p + 1] << 8) | q[p + 2];
    q[2] = 0x81;  // QR=1, RD copied as 1
    q[3] = 0x80;  // RA=1, RCODE 0
    q[6] = 0;
    q[7] = (qtype == 1) ? 1 : 0;  // one answer, for an A query only; AAAA and the rest get an empty NOERROR
    q[8] = q[9] = q[10] = q[11] = 0;
    int out = qend;
    if (qtype == 1) {
      const uint8_t ans[16] = {0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
                               answer_[0], answer_[1], answer_[2], answer_[3]};
      memcpy(q + out, ans, sizeof(ans));
      out += sizeof(ans);
    }
    udp_.beginPacket(udp_.remoteIP(), udp_.remotePort());
    udp_.write(q, out);
    udp_.endPacket();
  }

 private:
  void drain(int len) {
    uint8_t scratch[32];
    while (len > 0) {
      const int n = udp_.read(scratch, len > static_cast<int>(sizeof(scratch)) ? static_cast<int>(sizeof(scratch)) : len);
      if (n <= 0) break;
      len -= n;
    }
  }
  WiFiUDP udp_;
  IPAddress answer_;
};

}  // namespace fry_boards
