# socketutil.py module
# Author: K. Walsh <kwalsh@cs.holycross.edu>
# Date: 15 January 2015
# Updated: 16 October 2020 - renamed to socketutil, added more helpers

"""
As of November 4th, 2020, this file has been heavily modified by project author (Evo Fearnley).

This file NO LONGER contains a helper class. Instead, it is a series of helper functions which take raw Python sockets
as parameters. Only the function calls themselves have been modified - all functionality should be identical.

This was done to support HTTPS/SSL-encrypted sockets, as the current class implementation does not allow for this.

FOR THE PURPOSES OF IMPLEMENTATION: The sockets themselves should be created normally, using the default Python
constructors and functions. These are SOLELY HELPER FUNCTIONS FOR RETRIEVING AND PARSING DATA.

-EF
"""

import socket as _socket

# copy some of the socket.* global variables and constants, so you can do
# socketutil.AF_INET if you like, instead of socket.AF_INET
AF_INET = _socket.AF_INET
SOCK_STREAM = _socket.SOCK_STREAM


"""Send to the underlying socket, but accepts strings or bytes, may send
less than the full length of the data."""


def send(self, data):
    if isinstance(data, str):
        data = str.encode()
    return _socket.socket.send(self, data)


"""Send to the underlying socket, but accepts strings or bytes."""


def sendall(self, data):
    if isinstance(data, str):
        data = data.encode()
    return _socket.socket.sendall(self, data)


"""Receive up to n bytes from the underlying socket."""


def recv(self, n):
    if len(self.rq) == 0:
        return _socket.socket.recv(self, n)
    else:
        data = self.rq
        self.rq = b""
        return data


"""Receive up to buffersize bytes (or len(buffer) if buffersize is
unspecified or zero) and store into an existing buffer."""


def recv_into(self, buffer, buffersize=0):
    if len(self.rq) == 0:
        return _socket.socket.recv_into(self, buffer, buffersize)
    else:
        if not buffersize:
            buffersize = len(buffer)
        n = min(buffersize, len(self.rq))
        buffer[0:n] = self.rq[0:n]
        self.rq = self.rq[n:]
        return n


"""Like recv(), but also returns the sender's address info."""


def recvfrom(self, n):
    if len(self.rq) == 0:
        return _socket.socket.recvfrom(self, n)
    else:
        data = self.rq
        self.rq = b""
        return data


"""Like recv_into(), but also returns the sender's address info."""


def recvfrom_into(self, buffer, buffersize=0):
    if len(self.rq) == 0:
        return _socket.socket.recvfrom_into(self, buffer, buffersize)
    else:
        if not buffersize:
            buffersize = len(buffer)
        n = min(buffersize, len(self.rq))
        buffer[0:n] = self.rq[0:n]
        self.rq = self.rq[n:]
        return n, self.getpeername()


"""Recieve up to n bytes from the underlying socket, decoded as an ASCII string."""


def recv_str(self, n):
    return self.recv(n).decode()


"""Receive exactly n bytes from the underlying socket, no more, no less.
This returns a bytes object of length n, or None if there was an error
before n bytes could be received from the socket."""


def recv_exactly(self, n):
    while len(self.rq) < n:
        more = _socket.socket.recv(self, max(4096, n - len(self.rq)))
        if not more:
            return None
        self.rq += more
    data, self.rq = self.rq[0:n], self.rq[n:]
    return data


"""Receive exactly n bytes from the underlying socket, no more, no less,
and decode and return the result as an ASCII string.
This returns a string of length n, or None if there was an error
before n bytes could be received from the socket."""


def recv_str_exactly(self, n):
    data = recv_exactly(self, n)
    if data:
        data = data.decode()
    return data


"""Receive all bytes up to a delimiter of your choice, discarding the
delimiter. For example, recv_until("\n") will read and return all bytes up
to the first unix newline, discarding the newline. Similarly,
recv_until("\r\n") will read and return all bytes up to the first http-style
newline, and recv_until("\r\n\r\n") will read and return everything up to
the first http-style blank line. You can use a bytes object or a string for
the delimiter. In all cases, the delimiter is removed from the result and
discarded. This returns the desired data as a bytes object, or None if there
was an error before the delimiter was seen."""


def recv_until(self, delim):
    if isinstance(delim, str):
        delim = delim.encode()
    while delim not in self.rq:
        more = _socket.socket.recv(self, 4096)
        if not more:
            return None
        self.rq += more
    data, self.rq = self.rq.split(delim, 1)
    return data


"""Receive all bytes up to a delimiter of your choice, discarding the
delimiter, then decode and return the result as an ASCII string.
For example, recv_until("\n") will read and return all bytes up
to the first unix newline, discarding the newline. Similarly,
recv_until("\r\n") will read and return all bytes up to the first http-style
newline, and recv_until("\r\n\r\n") will read and return everything up to
the first http-style blank line. You can use a bytes object or a string for
the delimiter. In all cases, the delimiter is removed from the result and
discarded. This returns the desired data as a string, or None if there
was an error before the delimiter was seen."""


def recv_str_until(self, delim):
    data = recv_until(self, delim)
    if data:
        data = data.decode()
    return data


"""Receive all bytes up to the next newline, remove and discard the newline,
and return the rest as a string. This will work with both unix-style "\n"
newlines and http-style "\r\n" newlines. It returns a string, or None if
there was an error before a newline was seen."""


def recv_line(self):
    while b"\n" not in self.rq:
        more = _socket.socket.recv(self, 4096)
        if not more:
            return None
        self.rq += more
    data, self.rq = self.rq.split(b"\n", 1)
    if data.endswith(b"\r"):
        data = data[:-1]
    return data.decode()


"""Receive all bytes up to the next blank line, remove and discard the blank
line and all newline separators, and return the lines. This works with both
http-style "\r\n" line endings and unix-style "\n" line endings. This
returns array of strings, one for each line with each decoded as an ASCII
string, or None if there was an error before a blank line was seen."""


def recv_lines(self):
    lines = []
    while True:
        line = self.recv_line()
        if line is None:
            return None # fixme: the lines received so far are permanently
        if len(line) == 0:
            return lines
        lines.append(line)

