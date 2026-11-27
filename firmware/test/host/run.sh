#!/usr/bin/env bash
# Build and run the firmware core host tests.
#   SANITIZE=1 enables ASan/UBSan (Linux CI). UPDATE_GOLDEN=1 rewrites C++-owned vectors.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${OUT_DIR:-$here/build}"
mkdir -p "$out"
CXX="${CXX:-g++}"
flags=(-std=c++17 -O1 -g -Wall -Wextra -Werror -Wshadow -Wconversion -Wno-sign-conversion -I"$root/lib/hocore/src")
if [[ "${SANITIZE:-0}" == "1" ]]; then
  flags+=(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
fi
"$CXX" "${flags[@]}" -o "$out/host_tests" \
  "$here/test_main.cpp" \
  "$root/lib/hocore/src/ho_codec.cpp" \
  "$root/lib/hocore/src/ho_dns.cpp" \
  "$root/lib/hocore/src/ho_hmac.cpp"
cd "$here"
HO_GOLDEN_DIR="${HO_GOLDEN_DIR:-$root/../tests/golden/protocol}" "$out/host_tests"
