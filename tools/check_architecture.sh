#!/usr/bin/env bash
# Architecture gate (spec §19.4): pure layers must not depend on IO adapters.
#   protocol: no dependencies at all (no_std, allocation-free)
#   domain/logic: no tokio, rusqlite, reqwest, axum, rumqttc, socket2, std::net/fs IO
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
deps() { cargo tree -p "$1" -e normal --prefix none --locked 2>/dev/null | awk '{print $1}' | sort -u; }
for crate in ho-protocol; do
  extra=$(deps "$crate" | grep -v "^$crate$" || true)
  if [[ -n "$extra" ]]; then echo "FAIL: $crate must have no dependencies, found: $extra"; fail=1; fi
done
for crate in ho-domain ho-logic; do
  bad=$(deps "$crate" | grep -E '^(tokio|rusqlite|reqwest|axum|hyper|rumqttc|socket2|mio)$' || true)
  if [[ -n "$bad" ]]; then echo "FAIL: $crate depends on IO crates: $bad"; fail=1; fi
done
# Source-level: no IO or wall clocks in pure crates.
if grep -rnE 'std::fs|std::net::(TcpStream|TcpListener|UdpSocket)|SystemTime::now|Instant::now|tokio::' crates/domain/src crates/logic/src; then
  echo "FAIL: IO / wall clock usage in pure crates"; fail=1
fi
[[ $fail == 0 ]] && echo "architecture rules OK"
exit $fail
