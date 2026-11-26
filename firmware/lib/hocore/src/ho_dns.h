// Minimal DNS wire codec for diagnostic probes: one question, A/AAAA/any qtype.
// Only parses what is needed to classify a response; never follows more than a
// bounded number of compression pointers.
#pragma once
#include <stddef.h>
#include <stdint.h>

#include "ho_codec.h"

namespace ho {

// Encode a standard recursive query. Returns length or 0 if it does not fit / bad name.
size_t dns_build_query(uint8_t* out, size_t cap, uint16_t id, const char* qname, uint16_t qtype);

struct DnsResult {
  DnsAnswer answer;
  uint8_t rcode;
  int16_t error_code;  // 0 ok, -2 id mismatch, -3 not a response, -4 truncated (TC), -5 parse error
};

// Classify a response against the expectation.
DnsResult dns_classify(const uint8_t* msg, size_t len, uint16_t expect_id, DnsExpect expect, const uint8_t expect_ipv4[4]);

}  // namespace ho
