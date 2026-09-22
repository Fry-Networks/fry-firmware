#include "improv_serial.h"

#include <cstring>

namespace fry {
namespace improv {

namespace {

const char kHeader[6] = {'I', 'M', 'P', 'R', 'O', 'V'};

// Writes "IMPROV" + version + type + len into out and returns the running checksum so far.
// Callers have already checked that the whole packet fits.
size_t writeFrame(uint8_t* out, uint8_t type, uint8_t len) {
  memcpy(out, kHeader, sizeof(kHeader));
  out[6] = kVersion;
  out[7] = type;
  out[8] = len;
  return 9;
}

// Appends the checksum byte (sum of every preceding byte of the packet) and returns the total.
size_t sealPacket(uint8_t* out, size_t n) {
  uint32_t sum = 0;
  for (size_t i = 0; i < n; i++) sum += out[i];
  out[n] = static_cast<uint8_t>(sum & 0xFF);
  return n + 1;
}

}  // namespace

bool isKnownCommand(uint8_t command) {
  return command == static_cast<uint8_t>(Command::WifiSettings) ||
         command == static_cast<uint8_t>(Command::RequestState) ||
         command == static_cast<uint8_t>(Command::RequestDeviceInfo) ||
         command == static_cast<uint8_t>(Command::RequestScannedWifi);
}

// Back to hunting for a header, re-testing the byte that broke the packet. "IMPROV" has no
// proper prefix that is also a suffix, so the only partial match a single byte can begin is
// the leading 'I' — that one check is the whole resynchronisation rule for this needle.
Result Parser::restart(Result r, uint8_t b) {
  _stage = Stage::Header;
  _headerIdx = (b == static_cast<uint8_t>(kHeader[0])) ? 1 : 0;
  _sum = _headerIdx ? b : 0;
  return r;
}

Result Parser::feed(uint8_t b) {
  switch (_stage) {
    case Stage::Header:
      if (b == static_cast<uint8_t>(kHeader[_headerIdx])) {
        _sum += b;
        if (++_headerIdx == sizeof(kHeader)) _stage = Stage::Version;
        return Result::None;
      }
      // Junk between packets (log lines share this UART) — start over on this byte.
      restart(Result::None, b);
      return Result::None;

    case Stage::Version:
      if (b != kVersion) return restart(Result::Malformed, b);
      _sum += b;
      _stage = Stage::Type;
      return Result::None;

    case Stage::Type:
      _sum += b;
      _type = b;
      _stage = Stage::Length;
      return Result::None;

    case Stage::Length:
      if (b > kMaxPayload) return restart(Result::Malformed, b);  // cannot buffer it
      _sum += b;
      _len = b;
      _got = 0;
      _stage = _len ? Stage::Payload : Stage::Checksum;
      return Result::None;

    case Stage::Payload:
      _sum += b;
      _payload[_got++] = b;
      if (_got == _len) _stage = Stage::Checksum;
      return Result::None;

    case Stage::Checksum: {
      const bool ok = (b == static_cast<uint8_t>(_sum & 0xFF));
      const uint8_t type = _type;
      const uint8_t len = _len;
      // Whatever the verdict, the next byte starts a fresh search: a rejected packet must never
      // leave the parser out of step for the packet after it. The checksum byte is re-tested as
      // a possible header start, because after a REJECTED packet it may not have been a checksum
      // at all - it may be the first byte of the real header that follows the junk.
      restart(Result::None, b);
      if (!ok) return Result::BadChecksum;
      if (type != kTypeRpc) return Result::None;  // devices only ever receive RPC packets
      // RPC payload is [command][dataLen][data...]; anything else is an invalid RPC.
      if (len < 2 || static_cast<uint8_t>(len - 2) != _payload[1]) return Result::Malformed;
      _command = _payload[0];
      _data = _payload + 2;
      _dataLen = _payload[1];
      return Result::Rpc;
    }
  }
  return Result::None;
}

bool decodeWifiSettings(const uint8_t* data, uint8_t dataLen, char* ssid, size_t ssidCap,
                        char* pass, size_t passCap) {
  if (!data || !ssid || !pass) return false;
  if (dataLen < 1) return false;

  const uint8_t ssidLen = data[0];
  if (ssidLen > kMaxSsid || ssidLen >= ssidCap) return false;
  if (static_cast<size_t>(dataLen) < 1u + ssidLen + 1u) return false;

  const uint8_t passLen = data[1 + ssidLen];
  if (passLen > kMaxPass || passLen >= passCap) return false;
  if (static_cast<size_t>(dataLen) < 1u + ssidLen + 1u + passLen) return false;

  memcpy(ssid, data + 1, ssidLen);
  ssid[ssidLen] = 0;
  memcpy(pass, data + 2 + ssidLen, passLen);
  pass[passLen] = 0;
  return true;
}

size_t encodeCurrentState(State state, uint8_t* out, size_t outCap) {
  if (!out || outCap < 11) return 0;
  size_t n = writeFrame(out, kTypeCurrentState, 1);
  out[n++] = static_cast<uint8_t>(state);
  return sealPacket(out, n);
}

size_t encodeError(Error error, uint8_t* out, size_t outCap) {
  if (!out || outCap < 11) return 0;
  size_t n = writeFrame(out, kTypeErrorState, 1);
  out[n++] = static_cast<uint8_t>(error);
  return sealPacket(out, n);
}

size_t encodeRpcResult(uint8_t command, const char* const* strings, uint8_t count, uint8_t* out,
                       size_t outCap) {
  if (!out) return 0;

  size_t dataLen = 0;
  for (uint8_t i = 0; i < count; i++) {
    if (!strings || !strings[i]) return 0;
    const size_t len = strlen(strings[i]);
    if (len > 255) return 0;
    dataLen += 1 + len;
  }
  const size_t payloadLen = 2 + dataLen;  // [cmd][dataLen] + the strings
  if (payloadLen > kMaxPayload) return 0;
  if (outCap < 9 + payloadLen + 1) return 0;

  size_t n = writeFrame(out, kTypeRpcResult, static_cast<uint8_t>(payloadLen));
  out[n++] = command;
  out[n++] = static_cast<uint8_t>(dataLen);
  for (uint8_t i = 0; i < count; i++) {
    const size_t len = strlen(strings[i]);
    out[n++] = static_cast<uint8_t>(len);
    memcpy(out + n, strings[i], len);
    n += len;
  }
  return sealPacket(out, n);
}

}  // namespace improv
}  // namespace fry
