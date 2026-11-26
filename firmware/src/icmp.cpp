#include "icmp.h"

#include <Arduino.h>

extern "C" {
#include <lwip/icmp.h>
#include <lwip/inet_chksum.h>
#include <lwip/ip_addr.h>
#include <lwip/prot/ip4.h>
#include <lwip/raw.h>
}

namespace node {

namespace {
constexpr uint16_t kId = 0x484F;  // "HO"
constexpr size_t kPayload = 24;   // small echo, matches typical client pings
raw_pcb* g_pcb = nullptr;
volatile IcmpState g_state = IcmpState::Idle;
volatile uint32_t g_rtt = 0;
uint32_t g_t0 = 0;
uint16_t g_seq = 0;

u8_t on_recv(void*, raw_pcb*, pbuf* p, const ip_addr_t*) {
  if (g_state != IcmpState::Waiting || p->len < IP_HLEN) return 0;
  const ip_hdr* iph = (const ip_hdr*)p->payload;
  size_t hl = (size_t)IPH_HL(iph) * 4;
  if (p->len < hl + sizeof(icmp_echo_hdr)) return 0;
  const icmp_echo_hdr* e = (const icmp_echo_hdr*)((const u8_t*)p->payload + hl);
  if (e->type != ICMP_ER || e->id != PP_HTONS(kId) || e->seqno != lwip_htons(g_seq)) return 0;
  g_rtt = micros() - g_t0;
  g_state = IcmpState::Replied;
  pbuf_free(p);
  return 1;  // consumed
}
}  // namespace

bool icmp_begin() {
  if (g_pcb) return true;
  g_pcb = raw_new(IP_PROTO_ICMP);
  if (!g_pcb) return false;
  raw_recv(g_pcb, on_recv, nullptr);
  raw_bind(g_pcb, IP_ADDR_ANY);
  return true;
}

bool icmp_start(const IPAddress& dst, uint16_t seq) {
  if (!g_pcb || g_state == IcmpState::Waiting) return false;
  pbuf* p = pbuf_alloc(PBUF_IP, sizeof(icmp_echo_hdr) + kPayload, PBUF_RAM);
  if (!p) { g_state = IcmpState::Failed; return false; }
  icmp_echo_hdr* e = (icmp_echo_hdr*)p->payload;
  ICMPH_TYPE_SET(e, ICMP_ECHO);
  ICMPH_CODE_SET(e, 0);
  e->id = PP_HTONS(kId);
  e->seqno = lwip_htons(seq);
  u8_t* d = (u8_t*)p->payload + sizeof(icmp_echo_hdr);
  for (size_t i = 0; i < kPayload; i++) d[i] = (u8_t)('a' + (i % 26));
  e->chksum = 0;
  e->chksum = inet_chksum(e, (u16_t)(sizeof(icmp_echo_hdr) + kPayload));
  ip_addr_t addr;
  ip_addr_set_ip4_u32(&addr, (uint32_t)dst);
  g_seq = seq;
  g_t0 = micros();
  g_state = IcmpState::Waiting;
  err_t err = raw_sendto(g_pcb, p, &addr);
  pbuf_free(p);
  if (err != ERR_OK) { g_state = IcmpState::Failed; return false; }
  return true;
}

IcmpState icmp_state() { return g_state; }
uint32_t icmp_rtt_us() { return g_rtt; }
void icmp_reset() { g_state = IcmpState::Idle; }

}  // namespace node
