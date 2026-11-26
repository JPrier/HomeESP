"""Make pyserial work with clone CH340 chips on WCH driver 3.9.2024.9 (Windows).

Import this module before opening ports, or run `python ch340_shim.py esptool ...`.
Originally: run esptool/other pyserial tools with a workaround for clone CH340 chips on
WCH driver 3.9.2024.9 (Windows).

Observed rule (see docs/hardware/ch340-windows.md): SetCommState fails with
ERROR_GEN_FAILURE (31) unless the baud rate changes AND one side of the change
is 9600. Re-applying the same settings fails too. pyserial re-applies the full
DCB on every timeout change, so we:
  * skip SetCommState when line settings are unchanged (timeouts only), and
  * hop through 9600 when a direct change is refused.
"""
import ctypes
import runpy
import sys

import serial
try:
    from serial import serialwin32, win32
except ImportError:  # non-Windows: nothing to patch
    serialwin32 = None

def _line_key(self):
    return (self._baudrate, self._bytesize, self._parity, self._stopbits,
            self._rtscts, self._dsrdtr, self._xonxoff)


def _apply_timeouts_only(self):
    timeouts = win32.COMMTIMEOUTS()
    if self._timeout is None:
        pass
    elif self._timeout == 0:
        timeouts.ReadIntervalTimeout = win32.MAXDWORD
    else:
        timeouts.ReadTotalTimeoutConstant = max(int(self._timeout * 1000), 1)
    if self._timeout != 0 and self._inter_byte_timeout is not None:
        timeouts.ReadIntervalTimeout = max(int(self._inter_byte_timeout * 1000), 1)
    if self._write_timeout is None:
        pass
    elif self._write_timeout == 0:
        timeouts.WriteTotalTimeoutConstant = win32.MAXDWORD
    else:
        timeouts.WriteTotalTimeoutConstant = max(int(self._write_timeout * 1000), 1)
    win32.SetCommTimeouts(self._port_handle, ctypes.byref(timeouts))


def _patched(self, *a, **kw):
    key = _line_key(self)
    if getattr(self, "_ch340_applied", None) == key:
        return _apply_timeouts_only(self)
    try:
        _orig(self, *a, **kw)
    except serial.SerialException:
        target = self._baudrate
        self._baudrate = 9600 if target != 9600 else 19200
        try:
            _orig(self, *a, **kw)
        except serial.SerialException:
            pass
        self._baudrate = target
        _orig(self, *a, **kw)
    self._ch340_applied = key


if serialwin32 is not None:
    _orig = serialwin32.Serial._reconfigure_port
    serialwin32.Serial._reconfigure_port = _patched

if __name__ == "__main__":
    tool = sys.argv[1]
    sys.argv = [tool] + sys.argv[2:]
    runpy.run_module(tool, run_name="__main__", alter_sys=True)
