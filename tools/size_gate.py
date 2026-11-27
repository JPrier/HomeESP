#!/usr/bin/env python3
"""Fail if PlatformIO's size report exceeds RAM/flash budgets (percent)."""
import re
import sys


def main() -> int:
    text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    ram_max, flash_max = float(sys.argv[2]), float(sys.argv[3])
    ram = re.search(r"RAM:.*?([\d.]+)%", text)
    flash = re.search(r"Flash:.*?([\d.]+)%", text)
    if not ram or not flash:
        print("size report not found")
        return 2
    r, f = float(ram.group(1)), float(flash.group(1))
    print(f"RAM {r}% (budget {ram_max}%), flash {f}% (budget {flash_max}%)")
    return 0 if r <= ram_max and f <= flash_max else 1


if __name__ == "__main__":
    sys.exit(main())
