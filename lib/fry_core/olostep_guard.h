#pragma once
// Safety core for the opt-in "olostep" web-relay: pure, host-testable, zero Arduino includes.
//
// Two invariants are enforced here, upstream of any executor:
//   A1  UNAUTHENTICATED ONLY. The relay never forwards, injects, stores, reads or uses cookies,
//       Authorization / Proxy-Authorization, bearer tokens, API keys or any session or credential
//       material, whether the owner's or a third party's. A job that asks for any of it is rejected
//       whole (fail closed); the outbound header set is an allowlist; inbound Set-Cookie is dropped.
//   EGRESS. Every URL a job supplies is server-controlled, so each one must be https and must not
//       point at the owner's LAN, loopback, link-local / metadata or other non-public space.
//
// No NVS, device token or secret is read in this module. Unit tested under `pio test -e native`.
#include <cstdint>
#include <map>
#include <string>

namespace fry_olostep {

using HeaderMap = std::map<std::string, std::string>;

// One relay job as the later (private) executor parses it. For the string fields an empty value
// means "absent". The parser MUST put any present, non-null action value (raw JSON text is fine)
// into a non-empty string so its presence cannot be missed.
struct Job {
  std::string method_endpoint;  // fetch target (URL)
  std::string url;              // alternate fetch target
  std::string method_payload;   // body
  std::string userAgent;
  std::string type_event;       // job kind
  HeaderMap method_headers;     // arbitrary header map
  // Credential / session selectors: any value rejects the job.
  std::string session_id;
  std::string lease_node;
  // Action / browser-class fields: any value rejects the job.
  std::string actions;
  std::string runScript;
  std::string burkeObject;
  std::string cerealObject;
  std::string saveFile;
  std::string htmlVisualizer;
  // Server-supplied result / callback endpoints (URLs).
  std::string save_html_endpoint;
  std::string error_callback_endpoint;
};

// false (reject) when the job carries session_id / lease_node, any credential-bearing header, a
// forbidden type_event, any action field, a missing fetch target (method_endpoint or url), or any
// present URL field (method_endpoint, url, save_html_endpoint, error_callback_endpoint) that fails
// olostep_url_allowed(). Otherwise true.
bool olostep_job_is_permitted(const Job& job);

// Allowlist: Accept, Accept-Language, Accept-Encoding, User-Agent, Referer (case-insensitive).
// Everything else is dropped; Cookie / Authorization / any auth header can never be emitted.
HeaderMap olostep_sanitize_outbound_headers(const HeaderMap& in);

// Drops Set-Cookie / Set-Cookie2 from a response header set; no cookie jar is retained anywhere.
HeaderMap olostep_sanitize_response_headers(const HeaderMap& in);
// true iff the response header set carries no Set-Cookie / Set-Cookie2.
bool olostep_response_is_clean(const HeaderMap& in);

// WS registration query string. Carries only device_id / version / platform, percent-encoded. It
// never advertises the browser / login / authenticated job classes.
std::string olostep_ws_capability_query(const std::string& device_id, const std::string& version,
                                        const std::string& platform);

// true ONLY for an https URL whose host is a public name or a public IP literal: no userinfo, a
// valid port, no encoded-IP forms (dword / hex / octal / short), not localhost / *.local /
// *.internal / other private suffixes, no bare (dot-less) hostname, and no IP literal in a
// private, loopback, link-local, CGNAT, multicast, reserved or documentation range.
// TODO(chip slice): literal-IP filtering does not stop DNS rebinding; the connect path must
// re-check the RESOLVED address against the same range set (olostep_ip_is_blocked_*) at
// socket-connect time.
// TODO(chip slice): any URL obtained at RUNTIME (e.g. a signed PUT URL) must be passed through
// olostep_url_allowed() at use time; upload flows are rejected at the job level here.
bool olostep_url_allowed(const std::string& url);

// The shared range table, for the resolved-address re-check. true = blocked (non-public).
bool olostep_ip_is_blocked_v4(const uint8_t ip[4]);
bool olostep_ip_is_blocked_v6(const uint8_t ip[16]);

}  // namespace fry_olostep
