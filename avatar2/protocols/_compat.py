"""Minimal drop-in replacement for stdlib telnetlib.Telnet.

telnetlib was removed in Python 3.13 (PEP 594). openocd.py and qmp.py only
ever use write(), read_until(), read_eager() and close(), so rather than
depend on a third-party backport this implements just that subset on top
of a plain TCP socket.
"""
import socket


class SimpleTelnet:
    def __init__(self, host, port, timeout=None):
        self._socket = socket.create_connection((host, port), timeout=timeout)
        self._buf = b""

    def write(self, data):
        self._socket.sendall(data)

    def read_until(self, match):
        while match not in self._buf:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise EOFError("telnet connection closed")
            self._buf += chunk
        pos = self._buf.find(match) + len(match)
        rval, self._buf = self._buf[:pos], self._buf[pos:]
        return rval

    def read_eager(self):
        self._socket.setblocking(False)
        try:
            chunk = self._socket.recv(4096)
            if chunk == b"":
                raise EOFError("telnet connection closed")
            self._buf += chunk
        except BlockingIOError:
            pass
        finally:
            self._socket.setblocking(True)
        rval, self._buf = self._buf, b""
        return rval

    def close(self):
        self._socket.close()
