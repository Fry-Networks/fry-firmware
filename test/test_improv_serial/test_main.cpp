// Improv Serial wire-format tests (lib/fry_core/improv_serial.*).
//
// Every expected packet below is a GOLDEN VECTOR: the bytes were laid out by hand from the
// protocol description (header, version, type, length, payload, checksum = sum of the preceding
// bytes & 0xFF), not captured from this encoder. An encoder bug therefore cannot make its own
// output "correct", which is the whole point of pinning a wire format down.
//
// The same UART carries ordinary log lines, so the resync and bad-checksum cases matter as much
// as the happy paths: a device that loses framing after one corrupt byte is a device the web
// flasher can never talk to again without a reboot.
#ifdef ARDUINO
#include <Arduino.h>
#endif
#include <unity.h>

#include <cstring>

#include "improv_serial.h"

using fry::improv::Command;
using fry::improv::decodeWifiSettings;
using fry::improv::encodeCurrentState;
using fry::improv::encodeError;
using fry::improv::encodeRpcResult;
using fry::improv::Error;
using fry::improv::isKnownCommand;
using fry::improv::Parser;
using fry::improv::Result;
using fry::improv::State;

namespace {

// ---- golden vectors ------------------------------------------------------------------------
const uint8_t kStateReady[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x01, 0x01, 0x02, 0xE2};
const uint8_t kStateProvisioning[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x01, 0x01, 0x03, 0xE3};
const uint8_t kStateProvisioned[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x01, 0x01, 0x04, 0xE4};
const uint8_t kErrUnableToConnect[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x02, 0x01, 0x03, 0xE4};
const uint8_t kErrUnknownCommand[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x02, 0x01, 0x02, 0xE3};
// RPC result, command 0x04, zero strings — the empty result that terminates a scan response.
const uint8_t kEmptyScanResult[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x04, 0x02, 0x04, 0x00, 0xE8};
// RPC result, command 0x01, one string: the dashboard URL the flasher opens when setup finishes.
const uint8_t kUrlResult[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x04, 0x2B, 0x01, 0x29,
                              0x28, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x64, 0x2E, 0x66,
                              0x72, 0x79, 0x2F, 0x6E, 0x65, 0x77, 0x5F, 0x72, 0x65, 0x67, 0x69,
                              0x73, 0x74, 0x72, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x23, 0x6B, 0x65,
                              0x79, 0x3D, 0x46, 0x45, 0x4D, 0x2D, 0x30, 0x31, 0x9C};
// RPC result, command 0x03, four strings: name, firmware, chip, device name.
const uint8_t kDeviceInfoResult[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x04, 0x32, 0x03,
                                     0x30, 0x0C, 0x46, 0x72, 0x79, 0x20, 0x46, 0x69, 0x72, 0x6D,
                                     0x77, 0x61, 0x72, 0x65, 0x05, 0x30, 0x2E, 0x33, 0x2E, 0x31,
                                     0x08, 0x45, 0x53, 0x50, 0x33, 0x32, 0x2D, 0x43, 0x33, 0x13,
                                     0x46, 0x52, 0x59, 0x2D, 0x45, 0x53, 0x50, 0x33, 0x32, 0x2D,
                                     0x43, 0x33, 0x2D, 0x30, 0x41, 0x31, 0x42, 0x32, 0x43, 0x75};

// ---- incoming packets ----------------------------------------------------------------------
const uint8_t kWifiSettings[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x10, 0x01, 0x0E,
                                 0x05, 0x4D, 0x79, 0x4E, 0x65, 0x74, 0x07, 0x73, 0x33, 0x63, 0x72,
                                 0x65, 0x74, 0x21, 0x6E};  // ssid "MyNet", pass "s3cret!"
const uint8_t kWifiSettingsNoPass[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x0B, 0x01,
                                       0x09, 0x07, 0x4F, 0x70, 0x65, 0x6E, 0x4E, 0x65, 0x74, 0x00,
                                       0xB6};  // ssid "OpenNet", open network
const uint8_t kRequestState[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x02, 0x02, 0x00, 0xE5};
const uint8_t kRequestDeviceInfo[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x02, 0x03, 0x00, 0xE6};
const uint8_t kUnknownCommandPacket[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x02, 0x42, 0x00, 0x25};
// 33-character ssid: one over the 32 the protocol allows.
const uint8_t kOversizeSsid[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x25, 0x01, 0x23,
                                 0x21, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
                                 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
                                 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58, 0x58,
                                 0x58, 0x00, 0xA3};
// kRequestState with its checksum byte flipped.
const uint8_t kBadChecksum[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03, 0x02, 0x02, 0x00, 0x1A};

// Feeds every byte and returns the result of the LAST one, asserting that no earlier byte
// claimed to complete a packet.
Result feedAll(Parser& p, const uint8_t* bytes, size_t len) {
  Result last = Result::None;
  for (size_t i = 0; i < len; i++) {
    last = p.feed(bytes[i]);
    if (i + 1 < len) TEST_ASSERT_EQUAL(static_cast<int>(Result::None), static_cast<int>(last));
  }
  return last;
}

void assertBytes(const uint8_t* want, size_t wantLen, const uint8_t* got, size_t gotLen) {
  TEST_ASSERT_EQUAL_size_t(wantLen, gotLen);
  TEST_ASSERT_EQUAL_UINT8_ARRAY(want, got, wantLen);
}

void test_current_state_encodes_to_the_golden_bytes(void) {
  uint8_t out[64];
  assertBytes(kStateReady, sizeof(kStateReady), out, encodeCurrentState(State::Ready, out, sizeof(out)));
  assertBytes(kStateProvisioning, sizeof(kStateProvisioning), out,
              encodeCurrentState(State::Provisioning, out, sizeof(out)));
  assertBytes(kStateProvisioned, sizeof(kStateProvisioned), out,
              encodeCurrentState(State::Provisioned, out, sizeof(out)));
}

void test_error_state_encodes_to_the_golden_bytes(void) {
  uint8_t out[64];
  assertBytes(kErrUnableToConnect, sizeof(kErrUnableToConnect), out,
              encodeError(Error::UnableToConnect, out, sizeof(out)));
  assertBytes(kErrUnknownCommand, sizeof(kErrUnknownCommand), out,
              encodeError(Error::UnknownCommand, out, sizeof(out)));
}

void test_device_info_result_carries_four_strings(void) {
  uint8_t out[128];
  const char* info[] = {"Fry Firmware", "0.3.1", "ESP32-C3", "FRY-ESP32-C3-0A1B2C"};
  assertBytes(kDeviceInfoResult, sizeof(kDeviceInfoResult), out,
              encodeRpcResult(static_cast<uint8_t>(Command::RequestDeviceInfo), info, 4, out, sizeof(out)));
}

void test_single_string_url_result(void) {
  uint8_t out[128];
  const char* url[] = {"http://d.fry/new_registration#key=FEM-01"};
  assertBytes(kUrlResult, sizeof(kUrlResult), out,
              encodeRpcResult(static_cast<uint8_t>(Command::WifiSettings), url, 1, out, sizeof(out)));
}

void test_empty_result_terminates_a_scan_response(void) {
  uint8_t out[64];
  assertBytes(kEmptyScanResult, sizeof(kEmptyScanResult), out,
              encodeRpcResult(static_cast<uint8_t>(Command::RequestScannedWifi), nullptr, 0, out, sizeof(out)));
}

void test_encoders_refuse_a_buffer_that_is_too_small(void) {
  uint8_t out[64];
  TEST_ASSERT_EQUAL_size_t(0, encodeCurrentState(State::Ready, out, 10));
  TEST_ASSERT_EQUAL_size_t(0, encodeError(Error::None, out, 10));
  const char* big[] = {"0123456789012345678901234567890123456789012345678901234567890123456789",
                       "0123456789012345678901234567890123456789012345678901234567890123456789"};
  TEST_ASSERT_EQUAL_size_t(0, encodeRpcResult(0x01, big, 2, out, sizeof(out)));  // > kMaxPayload
}

void test_wifi_settings_round_trip(void) {
  Parser p;
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Rpc),
                    static_cast<int>(feedAll(p, kWifiSettings, sizeof(kWifiSettings))));
  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(Command::WifiSettings), p.command());

  char ssid[33] = {0};
  char pass[65] = {0};
  TEST_ASSERT_TRUE(decodeWifiSettings(p.data(), p.dataLen(), ssid, sizeof(ssid), pass, sizeof(pass)));
  TEST_ASSERT_EQUAL_STRING("MyNet", ssid);
  TEST_ASSERT_EQUAL_STRING("s3cret!", pass);
}

void test_wifi_settings_with_an_empty_password(void) {
  Parser p;
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Rpc),
                    static_cast<int>(feedAll(p, kWifiSettingsNoPass, sizeof(kWifiSettingsNoPass))));
  char ssid[33] = {0};
  char pass[65] = {'x', 0};
  TEST_ASSERT_TRUE(decodeWifiSettings(p.data(), p.dataLen(), ssid, sizeof(ssid), pass, sizeof(pass)));
  TEST_ASSERT_EQUAL_STRING("OpenNet", ssid);
  TEST_ASSERT_EQUAL_STRING("", pass);  // an open network, not a missing field
}

void test_oversize_ssid_is_rejected(void) {
  Parser p;
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Rpc),
                    static_cast<int>(feedAll(p, kOversizeSsid, sizeof(kOversizeSsid))));
  char ssid[33] = {0};
  char pass[65] = {0};
  // 33 characters: structurally a valid packet, but not a valid SSID - and one byte more than
  // the 32-char buffer the rest of the firmware stores it in.
  TEST_ASSERT_FALSE(decodeWifiSettings(p.data(), p.dataLen(), ssid, sizeof(ssid), pass, sizeof(pass)));
  TEST_ASSERT_EQUAL_STRING("", ssid);  // untouched
}

void test_truncated_wifi_settings_payload_is_rejected(void) {
  char ssid[33] = {0};
  char pass[65] = {0};
  const uint8_t claimsFiveHasTwo[] = {0x05, 'a', 'b'};
  TEST_ASSERT_FALSE(decodeWifiSettings(claimsFiveHasTwo, sizeof(claimsFiveHasTwo), ssid, sizeof(ssid),
                                       pass, sizeof(pass)));
  const uint8_t noPassLen[] = {0x02, 'a', 'b'};  // ssid complete, password length missing
  TEST_ASSERT_FALSE(decodeWifiSettings(noPassLen, sizeof(noPassLen), ssid, sizeof(ssid), pass, sizeof(pass)));
  TEST_ASSERT_FALSE(decodeWifiSettings(nullptr, 0, ssid, sizeof(ssid), pass, sizeof(pass)));
}

void test_junk_before_a_packet_does_not_desynchronise_the_parser(void) {
  Parser p;
  // A log line, a partial header, and a lone 'I' - the shapes that actually precede a packet on
  // a shared UART. "IIMPROV" is the interesting one: the second 'I' must be treated as the start.
  const char junk[] = "[health] up=12s heap=41000\nIMPRO IIMPROV";
  for (size_t i = 0; i < sizeof(junk) - 1; i++) {
    // Nothing in the junk completes a packet ("IIMPROV" leaves the parser mid-header).
    TEST_ASSERT_EQUAL(static_cast<int>(Result::None), static_cast<int>(p.feed(static_cast<uint8_t>(junk[i]))));
  }
  // Feeding the version byte of that dangling "IMPROV" and then junk must not wedge it either.
  p.feed(0x99);  // not version 0x01
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Rpc),
                    static_cast<int>(feedAll(p, kRequestDeviceInfo, sizeof(kRequestDeviceInfo))));
  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(Command::RequestDeviceInfo), p.command());
  TEST_ASSERT_EQUAL_UINT8(0, p.dataLen());
}

void test_bad_checksum_is_rejected_and_the_next_packet_still_parses(void) {
  Parser p;
  TEST_ASSERT_EQUAL(static_cast<int>(Result::BadChecksum),
                    static_cast<int>(feedAll(p, kBadChecksum, sizeof(kBadChecksum))));
  // The very next good packet must be understood: one corrupt byte may not cost framing.
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Rpc),
                    static_cast<int>(feedAll(p, kRequestState, sizeof(kRequestState))));
  TEST_ASSERT_EQUAL_UINT8(static_cast<uint8_t>(Command::RequestState), p.command());
}

void test_unknown_command_surfaces_as_a_command_not_as_silence(void) {
  Parser p;
  // It must parse - the device has to answer it with error 0x02 (unknown command) rather than
  // ignore it, so the parser may not swallow it.
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Rpc),
                    static_cast<int>(feedAll(p, kUnknownCommandPacket, sizeof(kUnknownCommandPacket))));
  TEST_ASSERT_EQUAL_UINT8(0x42, p.command());
  TEST_ASSERT_FALSE(isKnownCommand(p.command()));
  TEST_ASSERT_TRUE(isKnownCommand(static_cast<uint8_t>(Command::WifiSettings)));
  TEST_ASSERT_TRUE(isKnownCommand(static_cast<uint8_t>(Command::RequestState)));
  TEST_ASSERT_TRUE(isKnownCommand(static_cast<uint8_t>(Command::RequestDeviceInfo)));
  TEST_ASSERT_TRUE(isKnownCommand(static_cast<uint8_t>(Command::RequestScannedWifi)));
}

void test_a_wrong_version_byte_is_malformed_not_a_packet(void) {
  Parser p;
  uint8_t bad[sizeof(kRequestState)];
  memcpy(bad, kRequestState, sizeof(kRequestState));
  bad[6] = 0x02;  // version
  Result last = Result::None;
  for (size_t i = 0; i < sizeof(bad); i++) last = p.feed(bad[i]);
  TEST_ASSERT_NOT_EQUAL(static_cast<int>(Result::Rpc), static_cast<int>(last));
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Rpc),
                    static_cast<int>(feedAll(p, kRequestState, sizeof(kRequestState))));
}

void test_an_oversize_length_byte_is_refused_without_desynchronising(void) {
  Parser p;
  const uint8_t header[] = {0x49, 0x4D, 0x50, 0x52, 0x4F, 0x56, 0x01, 0x03};
  for (size_t i = 0; i < sizeof(header); i++) p.feed(header[i]);
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Malformed), static_cast<int>(p.feed(0xFF)));  // > kMaxPayload
  TEST_ASSERT_EQUAL(static_cast<int>(Result::Rpc),
                    static_cast<int>(feedAll(p, kRequestState, sizeof(kRequestState))));
}

}  // namespace

// Unity's setUp/tearDown have C linkage, so they must sit at global scope.
void setUp() {}

void tearDown() {}

int main(int, char**) {
  UNITY_BEGIN();
  RUN_TEST(test_current_state_encodes_to_the_golden_bytes);
  RUN_TEST(test_error_state_encodes_to_the_golden_bytes);
  RUN_TEST(test_device_info_result_carries_four_strings);
  RUN_TEST(test_single_string_url_result);
  RUN_TEST(test_empty_result_terminates_a_scan_response);
  RUN_TEST(test_encoders_refuse_a_buffer_that_is_too_small);
  RUN_TEST(test_wifi_settings_round_trip);
  RUN_TEST(test_wifi_settings_with_an_empty_password);
  RUN_TEST(test_oversize_ssid_is_rejected);
  RUN_TEST(test_truncated_wifi_settings_payload_is_rejected);
  RUN_TEST(test_junk_before_a_packet_does_not_desynchronise_the_parser);
  RUN_TEST(test_bad_checksum_is_rejected_and_the_next_packet_still_parses);
  RUN_TEST(test_unknown_command_surfaces_as_a_command_not_as_silence);
  RUN_TEST(test_a_wrong_version_byte_is_malformed_not_a_packet);
  RUN_TEST(test_an_oversize_length_byte_is_refused_without_desynchronising);
  return UNITY_END();
}
