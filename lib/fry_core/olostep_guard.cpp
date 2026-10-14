#include "olostep_guard.h"

#include <cstring>
#include <vector>

namespace fry_olostep {

namespace {

std::string lower(const std::string& s) {
  std::string o = s;
  for (char& c : o) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return o;
}

std::string trimLower(const std::string& s) {
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t')) b++;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) e--;
  return lower(s.substr(b, e - b));
}

// CR, LF, NUL, any other control character (< 0x20) or DEL: never allowed in a header name or value
// (a CRLF in a value would let a socket writer emit an injected Cookie / Authorization header).
bool hasControlChar(const std::string& s) {
  for (char c : s) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u < 0x20 || u == 0x7F) return true;
  }
  return false;
}

bool endsWith(const std::string& s, const char* suffix) {
  size_t n = strlen(suffix);
  return s.size() >= n && s.compare(s.size() - n, n, suffix) == 0;
}

bool contains(const std::string& s, const char* needle) { return s.find(needle) != std::string::npos; }

// Deliberately broad: any header that looks like it could carry credential or session material.
bool isAuthHeader(const std::string& rawName) {
  const std::string n = trimLower(rawName);
  if (n.empty()) return true;  // a nameless header is never legitimate; fail closed
  if (contains(n, "cookie") || contains(n, "auth") || contains(n, "token") || contains(n, "session") ||
      contains(n, "credential") || contains(n, "secret") || contains(n, "api-key") ||
      contains(n, "apikey") || contains(n, "bearer"))
    return true;
  return endsWith(n, "-key");
}

// ---- URL / address parsing ------------------------------------------------------------------

bool isDigit(char c) { return c >= '0' && c <= '9'; }
bool isHex(char c) { return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
int hexVal(char c) {
  if (isDigit(c)) return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return c - 'A' + 10;
}

// Strict dotted quad: exactly four decimal labels of 1-3 digits, no leading zeros, each <= 255.
bool parseStrictV4(const std::string& s, uint8_t out[4]) {
  size_t pos = 0;
  for (int i = 0; i < 4; i++) {
    size_t start = pos;
    int v = 0;
    while (pos < s.size() && isDigit(s[pos])) {
      v = v * 10 + (s[pos] - '0');
      pos++;
      if (pos - start > 3) return false;
    }
    size_t len = pos - start;
    if (len == 0) return false;
    if (len > 1 && s[start] == '0') return false;
    if (v > 255) return false;
    out[i] = static_cast<uint8_t>(v);
    if (i < 3) {
      if (pos >= s.size() || s[pos] != '.') return false;
      pos++;
    }
  }
  return pos == s.size();
}

std::vector<std::string> splitColon(const std::string& s) {
  std::vector<std::string> v;
  size_t start = 0;
  for (;;) {
    size_t p = s.find(':', start);
    if (p == std::string::npos) {
      v.push_back(s.substr(start));
      return v;
    }
    v.push_back(s.substr(start, p - start));
    start = p + 1;
  }
}

// Parses colon-separated groups; an optional dotted-quad tail counts as two groups.
bool parseGroups(const std::string& s, bool allowV4Tail, std::vector<uint16_t>& out) {
  if (s.empty()) return true;
  const std::vector<std::string> toks = splitColon(s);
  for (size_t i = 0; i < toks.size(); i++) {
    const std::string& t = toks[i];
    if (t.empty()) return false;
    if (t.find('.') != std::string::npos) {
      uint8_t q[4];
      if (!allowV4Tail || i + 1 != toks.size() || !parseStrictV4(t, q)) return false;
      out.push_back(static_cast<uint16_t>((q[0] << 8) | q[1]));
      out.push_back(static_cast<uint16_t>((q[2] << 8) | q[3]));
      continue;
    }
    if (t.size() > 4) return false;
    uint16_t v = 0;
    for (char c : t) {
      if (!isHex(c)) return false;
      v = static_cast<uint16_t>((v << 4) | hexVal(c));
    }
    out.push_back(v);
  }
  return true;
}

bool parseV6(const std::string& s, uint8_t out[16]) {
  std::vector<uint16_t> g;
  size_t dc = s.find("::");
  if (dc == std::string::npos) {
    if (!parseGroups(s, true, g) || g.size() != 8) return false;
  } else {
    if (s.find("::", dc + 1) != std::string::npos) return false;
    std::vector<uint16_t> left, right;
    if (!parseGroups(s.substr(0, dc), false, left)) return false;
    if (!parseGroups(s.substr(dc + 2), true, right)) return false;
    if (left.size() + right.size() > 7) return false;
    g = left;
    g.insert(g.end(), 8 - left.size() - right.size(), 0);
    g.insert(g.end(), right.begin(), right.end());
  }
  for (int i = 0; i < 8; i++) {
    out[2 * i] = static_cast<uint8_t>(g[i] >> 8);
    out[2 * i + 1] = static_cast<uint8_t>(g[i] & 0xFF);
  }
  return true;
}

bool hostnameBlocked(const std::string& h) {
  static const char* const kSuffix[] = {".localhost", ".local",  ".internal", ".localdomain",
                                        ".lan",       ".corp",   ".intranet", ".home.arpa"};
  if (h == "localhost" || h == "home.arpa") return true;
  for (const char* s : kSuffix) {
    if (endsWith(h, s)) return true;
  }
  return false;
}

// Host is not an IP literal: validate as a public DNS name.
bool publicHostnameOk(std::string h) {
  if (!h.empty() && h.back() == '.') h.pop_back();
  if (h.empty() || h.size() > 253) return false;
  if (h.find('.') == std::string::npos) return false;  // bare hostname
  if (hostnameBlocked(h)) return false;
  size_t start = 0;
  std::string last;
  for (;;) {
    size_t p = h.find('.', start);
    std::string label = h.substr(start, p == std::string::npos ? std::string::npos : p - start);
    if (label.empty() || label.size() > 63) return false;
    for (char c : label) {
      if (!((c >= 'a' && c <= 'z') || isDigit(c) || c == '-')) return false;
    }
    if (p == std::string::npos) {
      last = label;
      break;
    }
    start = p + 1;
  }
  // Numeric-looking last label = an encoded IP (dword / short / octal) or a non-strict quad.
  bool allDigits = true;
  for (char c : last) allDigits = allDigits && isDigit(c);
  if (allDigits) return false;
  if (last.size() > 2 && last[0] == '0' && last[1] == 'x') {
    bool hexOnly = true;
    for (size_t i = 2; i < last.size(); i++) hexOnly = hexOnly && isHex(last[i]);
    if (hexOnly) return false;
  }
  return true;
}

}  // namespace

// ---- A1: job / header / response / capability -----------------------------------------------

bool olostep_ip_is_blocked_v4(const uint8_t ip[4]) {
  const uint8_t a = ip[0], b = ip[1], c = ip[2];
  if (a == 0 || a == 10 || a == 127) return true;                // 0/8, 10/8, 127/8
  if (a == 100 && (b & 0xC0) == 64) return true;                 // 100.64/10 CGNAT
  if (a == 169 && b == 254) return true;                         // link-local + metadata
  if (a == 172 && (b & 0xF0) == 16) return true;                 // 172.16/12
  if (a == 192 && b == 168) return true;                         // 192.168/16
  if (a == 192 && b == 0 && c == 0) return true;                 // 192.0.0/24
  if (a == 192 && b == 0 && c == 2) return true;                 // 192.0.2/24 TEST-NET-1
  if (a == 192 && b == 88 && c == 99) return true;               // 192.88.99/24 6to4 anycast
  if (a == 198 && (b & 0xFE) == 18) return true;                 // 198.18/15 benchmark
  if (a == 198 && b == 51 && c == 100) return true;              // doc
  if (a == 203 && b == 0 && c == 113) return true;               // doc
  if (a >= 224) return true;                                     // multicast, reserved, broadcast
  return false;
}

bool olostep_ip_is_blocked_v6(const uint8_t ip[16]) {
  bool first12Zero = true;
  for (int i = 0; i < 12; i++) first12Zero = first12Zero && ip[i] == 0;
  if (first12Zero) return true;  // ::, ::1 and deprecated v4-compatible ::a.b.c.d
  bool mapped = true;
  for (int i = 0; i < 10; i++) mapped = mapped && ip[i] == 0;
  if (mapped && ip[10] == 0xFF && ip[11] == 0xFF) return olostep_ip_is_blocked_v4(ip + 12);
  // NAT64 64:ff9b::/96 embeds a v4 address.
  if (ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xFF && ip[3] == 0x9B) {
    bool z = true;
    for (int i = 4; i < 12; i++) z = z && ip[i] == 0;
    if (z) return olostep_ip_is_blocked_v4(ip + 12);
  }
  if (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0 && ip[3] == 0) return true;  // 2001::/32 Teredo
  if (ip[0] == 0x00 && ip[1] == 0x64 && ip[2] == 0xFF && ip[3] == 0x9B && ip[4] == 0x00 && ip[5] == 0x01)
    return true;                                                    // 64:ff9b:1::/48 local-use NAT64
  if (ip[0] == 0x01 && ip[1] == 0x00) {                             // 100::/64 discard-only
    bool z = true;
    for (int i = 2; i < 8; i++) z = z && ip[i] == 0;
    if (z) return true;
  }
  if (ip[0] == 0x20 && ip[1] == 0x02) return true;                  // 2002::/16 6to4 (embeds v4)
  if ((ip[0] & 0xFE) == 0xFC) return true;                          // fc00::/7
  if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0x80) return true;         // fe80::/10
  if (ip[0] == 0xFE && (ip[1] & 0xC0) == 0xC0) return true;         // fec0::/10 site-local
  if (ip[0] == 0xFF) return true;                                   // ff00::/8 multicast
  if (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0D && ip[3] == 0xB8) return true;  // doc
  return false;
}

bool olostep_url_allowed(const std::string& url) {
  static const char kScheme[] = "https://";
  const size_t kSchemeLen = sizeof(kScheme) - 1;
  if (url.size() <= kSchemeLen || lower(url.substr(0, kSchemeLen)) != kScheme) return false;
  for (char c : url) {
    const unsigned char u = static_cast<unsigned char>(c);
    if (u <= 0x20 || u >= 0x7F || c == '\\') return false;  // whitespace, control, non-ASCII, backslash
  }
  const size_t aStart = kSchemeLen;
  size_t aEnd = url.find_first_of("/?#", aStart);
  if (aEnd == std::string::npos) aEnd = url.size();
  const std::string auth = url.substr(aStart, aEnd - aStart);
  if (auth.empty() || auth.find('@') != std::string::npos) return false;  // userinfo is credential material

  std::string host, port;
  bool bracket = false;
  if (auth[0] == '[') {
    size_t close = auth.find(']');
    if (close == std::string::npos) return false;
    host = auth.substr(1, close - 1);
    bracket = true;
    const std::string rest = auth.substr(close + 1);
    if (!rest.empty()) {
      if (rest[0] != ':') return false;
      port = rest.substr(1);
      if (port.empty()) return false;
    }
  } else {
    size_t colon = auth.find(':');
    if (colon == std::string::npos) {
      host = auth;
    } else {
      host = auth.substr(0, colon);
      port = auth.substr(colon + 1);
      if (port.empty() || port.find(':') != std::string::npos) return false;
    }
  }
  if (!port.empty()) {
    if (port.size() > 5) return false;
    long pv = 0;
    for (char c : port) {
      if (!isDigit(c)) return false;
      pv = pv * 10 + (c - '0');
    }
    if (pv < 1 || pv > 65535) return false;
  }
  if (host.empty() || host.find('%') != std::string::npos) return false;

  if (bracket) {
    uint8_t ip6[16];
    if (!parseV6(host, ip6)) return false;
    return !olostep_ip_is_blocked_v6(ip6);
  }
  host = lower(host);
  bool numericOnly = true;
  for (char c : host) numericOnly = numericOnly && (isDigit(c) || c == '.');
  if (numericOnly) {
    uint8_t ip4[4];
    if (!parseStrictV4(host, ip4)) return false;  // dword / short / octal / malformed
    return !olostep_ip_is_blocked_v4(ip4);
  }
  return publicHostnameOk(host);
}

OlostepJobClass olostep_classify_job(const std::string& type_event) {
  static const char* const kPartner[] = {"rufus_batch",   "amazon_reviews",      "meta_batch",
                                         "copilot_batch", "chatgpt_batch",       "gemini_batch",
                                         "perplexity_batch", "meta_login",       "create_cplt_session",
                                         "reset_meta"};
  if (type_event.empty() || type_event == "batch") return OlostepJobClass::Unauthenticated;
  for (const char* p : kPartner) {
    if (type_event == p) return OlostepJobClass::AuthenticatedPartner;
  }
  return OlostepJobClass::Unknown;
}

OlostepJobClass olostep_job_classify_and_permit(const Job& job) {
  const OlostepJobClass cls = olostep_classify_job(job.type_event);
  if (cls == OlostepJobClass::Unknown) return OlostepJobClass::Unknown;
  const bool partner = cls == OlostepJobClass::AuthenticatedPartner;
  if (!partner && (!job.session_id.empty() || !job.lease_node.empty())) return OlostepJobClass::Unknown;
  for (const auto& kv : job.method_headers) {
    if (!partner && isAuthHeader(kv.first)) return OlostepJobClass::Unknown;
    if (hasControlChar(kv.first) || hasControlChar(kv.second)) return OlostepJobClass::Unknown;  // header injection
  }
  if (hasControlChar(job.userAgent)) return OlostepJobClass::Unknown;
  if (!job.actions.empty() || !job.runScript.empty() || !job.burkeObject.empty() ||
      !job.cerealObject.empty() || !job.saveFile.empty() || !job.htmlVisualizer.empty())
    return OlostepJobClass::Unknown;
  if (job.method_endpoint.empty() && job.url.empty()) return OlostepJobClass::Unknown;  // no fetch target
  const std::string* urls[] = {&job.method_endpoint, &job.url, &job.save_html_endpoint,
                               &job.error_callback_endpoint};
  for (const std::string* u : urls) {
    if (!u->empty() && !olostep_url_allowed(*u)) return OlostepJobClass::Unknown;
  }
  return cls;
}

bool olostep_job_is_permitted(const Job& job) {
  return olostep_job_classify_and_permit(job) != OlostepJobClass::Unknown;
}

HeaderMap olostep_sanitize_outbound_headers(const HeaderMap& in, OlostepJobClass cls) {
  static const char* const kAllow[] = {"accept", "accept-language", "accept-encoding", "user-agent",
                                       "referer"};
  HeaderMap out;
  for (const auto& kv : in) {
    const std::string n = trimLower(kv.first);
    if (hasControlChar(n) || hasControlChar(kv.second)) continue;  // never emit CR/LF/NUL/control chars
    if (cls == OlostepJobClass::AuthenticatedPartner) {
      static const char* const kFraming[] = {"host", "content-length", "connection", "transfer-encoding",
                                             "keep-alive", "proxy-connection", "te", "trailer", "upgrade"};
      bool framing = false;
      for (const char* f : kFraming) {
        if (n == f) { framing = true; break; }
      }
      if (framing) continue;  // the executor writes its own Host/Content-Length/Connection
      out[n] = kv.second;
      continue;
    }
    for (const char* a : kAllow) {
      if (n == a) {
        out[n] = kv.second;  // canonical name: trimmed and lowercased
        break;
      }
    }
  }
  return out;
}

HeaderMap olostep_sanitize_outbound_headers(const HeaderMap& in) {
  return olostep_sanitize_outbound_headers(in, OlostepJobClass::Unauthenticated);
}

HeaderMap olostep_sanitize_response_headers(const HeaderMap& in) {
  HeaderMap out;
  for (const auto& kv : in) {
    const std::string n = trimLower(kv.first);
    if (n == "set-cookie" || n == "set-cookie2") continue;
    out[kv.first] = kv.second;
  }
  return out;
}

bool olostep_response_is_clean(const HeaderMap& in) {
  return olostep_sanitize_response_headers(in).size() == in.size();
}

std::string olostep_ws_capability_query(const std::string& device_id, const std::string& version,
                                        const std::string& platform) {
  auto enc = [](const std::string& s) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string o;
    for (char c : s) {
      const unsigned char u = static_cast<unsigned char>(c);
      if ((u >= 'a' && u <= 'z') || (u >= 'A' && u <= 'Z') || isDigit(c) || c == '-' || c == '_' ||
          c == '.' || c == '~') {
        o += c;
      } else {
        o += '%';
        o += kHex[u >> 4];
        o += kHex[u & 0xF];
      }
    }
    return o;
  };
  return "device_id=" + enc(device_id) + "&version=" + enc(version) + "&platform=" + enc(platform) +
         "&ali=1&mli=1&burke=true";
}

}  // namespace fry_olostep
