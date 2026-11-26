// Non-blocking ICMP echo using an lwIP raw PCB. One outstanding request at a time.
#pragma once
#include <IPAddress.h>
#include <stdint.h>

namespace node {

enum class IcmpState : uint8_t { Idle, Waiting, Replied, Failed };

bool icmp_begin();
// Start an echo; returns false if busy or the send failed (state -> Failed).
bool icmp_start(const IPAddress& dst, uint16_t seq);
IcmpState icmp_state();
uint32_t icmp_rtt_us();
void icmp_reset();

}  // namespace node
