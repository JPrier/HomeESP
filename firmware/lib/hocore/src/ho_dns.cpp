#include "ho_dns.h"

#include <string.h>

namespace ho {

size_t dns_build_query(uint8_t* out, size_t cap, uint16_t id, const char* qname, uint16_t qtype) {
  size_t qlen = strlen(qname);
  if (!valid_qname(qname, qlen)) return 0;
  size_t need = 12 + qlen + 2 + 4;
  if (need > cap) return 0;
  uint8_t* p = out;
  *p++ = (uint8_t)(id >> 8);
  *p++ = (uint8_t)id;
  *p++ = 0x01;  // RD
  *p++ = 0x00;
  *p++ = 0; *p++ = 1;  // QDCOUNT
  for (int i = 0; i < 6; i++) *p++ = 0;
  const char* s = qname;
  while (*s) {
    const char* dot = strchr(s, '.');
    size_t l = dot ? (size_t)(dot - s) : strlen(s);
    *p++ = (uint8_t)l;
    memcpy(p, s, l);
    p += l;
    s += l;
    if (*s == '.') s++;
  }
  *p++ = 0;
  *p++ = (uint8_t)(qtype >> 8);
  *p++ = (uint8_t)qtype;
  *p++ = 0;
  *p++ = 1;  // IN
  return (size_t)(p - out);
}

namespace {
// Skip a (possibly compressed) name starting at *pos. Bounded.
bool skip_name(const uint8_t* m, size_t len, size_t* pos) {
  size_t p = *pos;
  for (int guard = 0; guard < 128; guard++) {
    if (p >= len) return false;
    uint8_t l = m[p];
    if (l == 0) { *pos = p + 1; return true; }
    if ((l & 0xC0) == 0xC0) {
      if (p + 1 >= len) return false;
      *pos = p + 2;
      return true;
    }
    if (l & 0xC0) return false;
    p += 1 + l;
  }
  return false;
}
uint16_t rd16(const uint8_t* p) { return (uint16_t)((p[0] << 8) | p[1]); }
}  // namespace

DnsResult dns_classify(const uint8_t* m, size_t len, uint16_t expect_id, DnsExpect expect, const uint8_t expect_ipv4[4]) {
  DnsResult r{DnsAnswer::Malformed, 0, 0};
  if (len < 12) { r.error_code = -5; return r; }
  if (rd16(m) != expect_id) { r.error_code = -2; return r; }
  if (!(m[2] & 0x80)) { r.error_code = -3; return r; }
  r.rcode = m[3] & 0x0F;
  bool tc = (m[2] & 0x02) != 0;
  uint16_t qd = rd16(m + 4), an = rd16(m + 6);
  size_t pos = 12;
  for (uint16_t i = 0; i < qd; i++) {
    if (!skip_name(m, len, &pos) || pos + 4 > len) { r.error_code = -5; return r; }
    pos += 4;
  }
  switch (r.rcode) {
    case 0: break;
    case 2: r.answer = DnsAnswer::Servfail; return r;
    case 3: r.answer = expect == DnsExpect::Nxdomain ? DnsAnswer::ExpectedNxdomain : DnsAnswer::UnexpectedNxdomain; return r;
    case 5: r.answer = DnsAnswer::Refused; return r;
    default: r.answer = DnsAnswer::Malformed; return r;
  }
  if (tc) { r.answer = DnsAnswer::NoAnswer; r.error_code = -4; return r; }
  if (an == 0) { r.answer = expect == DnsExpect::Nxdomain ? DnsAnswer::Mismatch : DnsAnswer::NoAnswer; return r; }
  if (expect == DnsExpect::Nxdomain) { r.answer = DnsAnswer::Mismatch; return r; }
  bool any_a = false, match = false;
  for (uint16_t i = 0; i < an && i < 32; i++) {
    if (!skip_name(m, len, &pos) || pos + 10 > len) { r.answer = DnsAnswer::Malformed; r.error_code = -5; return r; }
    uint16_t type = rd16(m + pos), rdlen = rd16(m + pos + 8);
    pos += 10;
    if (pos + rdlen > len) { r.answer = DnsAnswer::Malformed; r.error_code = -5; return r; }
    if (type == 1 && rdlen == 4) {
      any_a = true;
      if (memcmp(m + pos, expect_ipv4, 4) == 0) match = true;
    }
    pos += rdlen;
  }
  if (expect == DnsExpect::Ipv4) r.answer = match ? DnsAnswer::Match : DnsAnswer::Mismatch;
  else r.answer = DnsAnswer::Match;
  (void)any_a;
  return r;
}

}  // namespace ho
