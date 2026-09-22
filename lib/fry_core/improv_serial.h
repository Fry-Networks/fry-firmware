#pragma once
// Improv Serial (https://improv-wifi.com/serial/) — packet parser and encoder.
//
// Pure C++ with zero Arduino includes, so `pio test -e native` covers the whole wire format and
// the Arduino side (src/core/improv_serial_glue.cpp) is left with nothing but moving bytes
// between this and Serial.
//
// One packet on the wire:
//   'I' 'M' 'P' 'R' 'O' 'V' | version (0x01) | type | len | payload[len] | checksum
// checksum = the sum of every preceding byte of the packet, & 0xFF.
//
// The same UART also carries ordinary log text, so the parser resynchronises on the header
// instead of assuming a packet starts where the last one ended.
#include <cstddef>
#include <cstdint>

namespace fry {
namespace improv {

const uint8_t kVersion = 0x01;

// Packet types.
const uint8_t kTypeCurrentState = 0x01;
const uint8_t kTypeErrorState = 0x02;
const uint8_t kTypeRpc = 0x03;
const uint8_t kTypeRpcResult = 0x04;

enum class State : uint8_t {
  Ready = 0x02,  // "ready, authorized" — this device has no authorization step
  Provisioning = 0x03,
  Provisioned = 0x04,
};

enum class Error : uint8_t {
  None = 0x00,
  InvalidRpc = 0x01,
  UnknownCommand = 0x02,
  UnableToConnect = 0x03,
  Unknown = 0xFF,
};

enum class Command : uint8_t {
  WifiSettings = 0x01,
  RequestState = 0x02,
  RequestDeviceInfo = 0x03,
  RequestScannedWifi = 0x04,
};

// Field limits. The largest command that exists is WifiSettings:
// cmd + len + (1 + 32) ssid + (1 + 64) password = 100 bytes of payload.
const size_t kMaxSsid = 32;
const size_t kMaxPass = 64;
const uint8_t kMaxPayload = 128;
// "IMPROV" + version + type + len + payload + checksum.
const size_t kMaxPacket = 6 + 1 + 1 + 1 + static_cast<size_t>(kMaxPayload) + 1;

bool isKnownCommand(uint8_t command);

// What a single fed byte did.
enum class Result : uint8_t {
  None = 0,         // consumed; nothing complete yet (or it was junk between packets)
  Rpc = 1,          // a complete, checksum-valid RPC packet is available via command()/data()
  BadChecksum = 2,  // a whole packet arrived and was discarded: checksum mismatch
  Malformed = 3,    // the packet was rejected before its checksum (bad version/length)
};

// Byte-at-a-time Improv packet reader. Fixed-size buffer, no heap, no String.
class Parser {
 public:
  Result feed(uint8_t b);

  // Valid after feed() returned Result::Rpc, until the next feed().
  uint8_t command() const { return _command; }
  const uint8_t* data() const { return _data; }
  uint8_t dataLen() const { return _dataLen; }

 private:
  enum class Stage : uint8_t { Header, Version, Type, Length, Payload, Checksum };

  Result restart(Result r, uint8_t b);

  Stage _stage = Stage::Header;
  uint8_t _headerIdx = 0;
  uint8_t _type = 0;
  uint8_t _len = 0;
  uint8_t _got = 0;
  uint32_t _sum = 0;
  uint8_t _payload[kMaxPayload];

  uint8_t _command = 0;
  const uint8_t* _data = nullptr;
  uint8_t _dataLen = 0;
};

// Splits a WifiSettings (0x01) payload — [ssidLen][ssid][passLen][pass] — into NUL-terminated
// buffers. Returns false, leaving both buffers untouched, if the payload is truncated or a field
// does not fit (ssid > kMaxSsid, password > kMaxPass, or larger than the buffer given). An empty
// password is valid; an open network sends one.
bool decodeWifiSettings(const uint8_t* data, uint8_t dataLen, char* ssid, size_t ssidCap,
                        char* pass, size_t passCap);

// Encoders. Each returns the number of bytes written to `out`, or 0 if it would not fit.
size_t encodeCurrentState(State state, uint8_t* out, size_t outCap);
size_t encodeError(Error error, uint8_t* out, size_t outCap);
// RPC result for `command`: payload [cmd][dataLen][len1][str1][len2][str2]... `count` may be 0,
// which is the empty result that terminates a scan response.
size_t encodeRpcResult(uint8_t command, const char* const* strings, uint8_t count, uint8_t* out,
                       size_t outCap);

}  // namespace improv
}  // namespace fry
