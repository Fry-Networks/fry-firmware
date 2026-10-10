#pragma once
// ESP8266 relay link protocol (G-3/B5), zero Arduino includes, natively unit tested.
//
// The board holds one outbound WebSocket to hardwareapi (wss .../relay/v1/ws/{miner_key}). Every
// binary message starts with a one-byte type:
//   0x00 DATA  - raw SOCKS5 stream bytes, both directions
//   0x01 END   - either side ends the current stream; the board drops upstream and awaits a
//                fresh greeting
//   0x02 HELLO - board -> server once per link, JSON (version, env, board id, flash, heap)
// The server is the SOCKS5 client. RelaySocksSession is the board's SOCKS5 server side for that
// byte stream, built on the same socks5_parse functions as the LAN :1080 relay - which itself is
// left untouched.
#include <cstddef>
#include <cstdint>

#include "socks5_parse.h"

namespace fry {

enum RelayMsgType : uint8_t {
  kRelayData = 0x00,
  kRelayEnd = 0x01,
  kRelayHello = 0x02,
};

// SOCKS5 REP codes this side sends (RFC 1928 section 6).
constexpr uint8_t kSocksRepOk = 0x00;
constexpr uint8_t kSocksRepFailure = 0x01;
constexpr uint8_t kSocksRepNotAllowed = 0x02;

// Destination policy, checked BEFORE resolving. The 8266 cannot verify the server certificate
// (setInsecure, documented in src/esp8266/http_tls.cpp), so the board does not take the server's
// word for where it may connect: domain names only, under kRelayDestSuffix, ports from the
// compiled list. IP literals are never accepted. hwapi's probe (relay_ws.py) connects to
// hardwareapi.frynetworks.com:443 and runs TLS end-to-end inside the stream.
extern const char* const kRelayDestSuffix;  // ".frynetworks.com"
bool relayDestAllowed(Socks5AddrType atyp, const char* host, uint16_t port);

// Checked AFTER resolving: refuses anything that is not a public unicast IPv4 address (0/8,
// 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, 192.0.2/24, 192.168/16,
// 198.18/15, 198.51.100/24, 203.0.113/24, 224/4 and above), so a Fry name can
// never be turned into a path onto the owner's LAN.
bool relayIpAllowed(uint8_t a, uint8_t b, uint8_t c, uint8_t d);

class RelaySocksSession {
 public:
  enum class State : uint8_t { Greeting, AwaitingConnect, Connecting, Relaying, Closed };
  enum class Action : uint8_t { None, Connect, Close };

  RelaySocksSession() { reset(); }
  void reset();

  // Feeds stream bytes from the server. Bytes the board must send back are written to
  // `reply` (up to replyCap; `replyLen` is set). In Relaying state the input is NOT consumed
  // here - the caller forwards it upstream (returns Action::None, `forward` = true).
  // Action::Connect: the caller resolves host()/port(), checks relayIpAllowed, connects, and then
  // calls onConnectResult(). Action::Close: the caller ends the stream (sends END).
  Action feed(const uint8_t* data, size_t len, uint8_t* reply, size_t replyCap, size_t& replyLen,
              bool& forward);

  // Writes the CONNECT reply (10 bytes) for `rep` into `reply`; returns its length (0 if no room).
  size_t onConnectResult(uint8_t rep, uint8_t* reply, size_t replyCap);

  State state() const { return _state; }
  const char* host() const { return _req.host; }
  uint16_t port() const { return _req.port; }

 private:
  State _state;
  uint8_t _buf[262];  // worst case CONNECT: 4 header + 1 len + 255 domain + 2 port
  size_t _bufLen;
  Socks5ConnectRequest _req;
};

// HELLO JSON. Returns bytes written excluding NUL, or 0 if it does not fit.
size_t relayBuildHello(char* out, size_t outCap, const char* version, const char* env,
                       const char* boardId, uint32_t flashReal, uint32_t flashHeader,
                       uint32_t flashId, uint32_t heapFree, uint32_t heapBlock);

}  // namespace fry
