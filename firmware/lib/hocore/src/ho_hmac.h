// Portable SHA-256 and HMAC-SHA256 (FIPS 180-4 / RFC 2104). Used to authenticate
// UDP echo probes; verified against RFC 4231 vectors in the host tests and against
// the Rust `hmac`/`sha2` crates via the shared echo golden vector.
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ho {

struct Sha256 {
  uint32_t h[8];
  uint8_t buf[64];
  uint64_t total;
  size_t blen;
  void init();
  void update(const uint8_t* d, size_t n);
  void final(uint8_t out[32]);
};

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]);

// Constant-time compare.
bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n);

// UDP echo request: "HE" | ver u8 | node_len u8 | node_id | seq u32 | nonce u32 | mono_ms u32 | mac[16]
// The MAC is HMAC-SHA256(key, everything before the MAC) truncated to 16 bytes.
// Response is identical except magic "HR" and the MAC recomputed by the server.
constexpr size_t kEchoMacLen = 16;
size_t echo_build(uint8_t* out, size_t cap, bool response, const char* node_id, uint32_t seq, uint32_t nonce,
                  uint32_t mono_ms, const uint8_t* key, size_t key_len);
// Verify a response for (node, seq, nonce). Returns true when authentic and matching.
bool echo_verify_response(const uint8_t* msg, size_t len, const char* node_id, uint32_t seq, uint32_t nonce,
                          const uint8_t* key, size_t key_len);

}  // namespace ho
