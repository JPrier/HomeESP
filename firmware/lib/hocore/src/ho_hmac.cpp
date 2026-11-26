#include "ho_hmac.h"

#include <string.h>

namespace ho {

namespace {
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
void block(uint32_t h[8], const uint8_t* p) {
  uint32_t w[64];
  for (int i = 0; i < 16; i++) w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; i++) {
    uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = hh + S1 + ch + K[i] + w[i];
    uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = S0 + mj;
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}
}  // namespace

void Sha256::init() {
  static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  memcpy(h, iv, sizeof(iv));
  total = 0;
  blen = 0;
}

void Sha256::update(const uint8_t* d, size_t n) {
  total += n;
  while (n) {
    size_t take = 64 - blen < n ? 64 - blen : n;
    memcpy(buf + blen, d, take);
    blen += take;
    d += take;
    n -= take;
    if (blen == 64) { block(h, buf); blen = 0; }
  }
}

void Sha256::final(uint8_t out[32]) {
  uint64_t bits = total * 8;
  uint8_t pad = 0x80;
  update(&pad, 1);
  uint8_t z = 0;
  while (blen != 56) update(&z, 1);
  uint8_t lenb[8];
  for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - 8 * i));
  update(lenb, 8);
  for (int i = 0; i < 8; i++) {
    out[4 * i] = (uint8_t)(h[i] >> 24);
    out[4 * i + 1] = (uint8_t)(h[i] >> 16);
    out[4 * i + 2] = (uint8_t)(h[i] >> 8);
    out[4 * i + 3] = (uint8_t)h[i];
  }
}

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
  uint8_t k[64] = {0};
  if (key_len > 64) {
    Sha256 s;
    s.init();
    s.update(key, key_len);
    s.final(k);
  } else {
    memcpy(k, key, key_len);
  }
  uint8_t ipad[64], opad[64];
  for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
  uint8_t inner[32];
  Sha256 s;
  s.init();
  s.update(ipad, 64);
  s.update(msg, msg_len);
  s.final(inner);
  s.init();
  s.update(opad, 64);
  s.update(inner, 32);
  s.final(out);
}

bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
  uint8_t d = 0;
  for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
  return d == 0;
}

namespace {
void put32(uint8_t* p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
}

size_t echo_build(uint8_t* out, size_t cap, bool response, const char* node_id, uint32_t seq, uint32_t nonce, uint32_t mono_ms,
                  const uint8_t* key, size_t key_len) {
  size_t n = strlen(node_id);
  size_t body = 4 + n + 12;
  if (n == 0 || n > 32 || body + kEchoMacLen > cap) return 0;
  out[0] = 'H';
  out[1] = response ? 'R' : 'E';
  out[2] = 1;
  out[3] = (uint8_t)n;
  memcpy(out + 4, node_id, n);
  put32(out + 4 + n, seq);
  put32(out + 8 + n, nonce);
  put32(out + 12 + n, mono_ms);
  uint8_t mac[32];
  hmac_sha256(key, key_len, out, body, mac);
  memcpy(out + body, mac, kEchoMacLen);
  return body + kEchoMacLen;
}

bool echo_verify_response(const uint8_t* msg, size_t len, const char* node_id, uint32_t seq, uint32_t nonce, const uint8_t* key,
                          size_t key_len) {
  size_t n = strlen(node_id);
  size_t body = 4 + n + 12;
  if (len != body + kEchoMacLen) return false;
  if (msg[0] != 'H' || msg[1] != 'R' || msg[2] != 1 || msg[3] != n || memcmp(msg + 4, node_id, n) != 0) return false;
  uint32_t s = (uint32_t)msg[4 + n] | ((uint32_t)msg[5 + n] << 8) | ((uint32_t)msg[6 + n] << 16) | ((uint32_t)msg[7 + n] << 24);
  uint32_t no = (uint32_t)msg[8 + n] | ((uint32_t)msg[9 + n] << 8) | ((uint32_t)msg[10 + n] << 16) | ((uint32_t)msg[11 + n] << 24);
  if (s != seq || no != nonce) return false;
  uint8_t mac[32];
  hmac_sha256(key, key_len, msg, body, mac);
  return ct_equal(mac, msg + body, kEchoMacLen);
}

}  // namespace ho
