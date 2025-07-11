import logging
import json
import telnetlib
import re
import threading

from avatar2 import archs


import socket


class UnixSocket:


    def __init__(self, file):

        self.buff = ""
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.connect(file)

    def read(self, length=1024):

        """ Read 1024 bytes off the socket """

        return self._socket.recv(length)

    def read_until(self, data):

        """ Read data into the buffer until we have data """

        while not data in self.buff:
            self.buff += self._socket.recv(1024).decode('ascii')

        pos = self.buff.find(data)
        rval = self.buff[:pos + len(data)]
        self.buff = self.buff[pos + len(data):]

        return rval

    def write(self, data):

        self._socket.send(data)

    def close(self):

        self._socket.close()


class QMPProtocol(object):
    def __init__(self, port, origin=None, unix_socket=None):

        self.port = port
        self.log = logging.getLogger('%s.%s' %
                                     (origin.log.name, self.__class__.__name__)
                                     ) if origin else \
            logging.getLogger(self.__class__.__name__)
        self.origin = origin
        self.id = 0
        self.unix_socket = unix_socket
        self.lock = threading.Lock()

    def __del__(self):
        self.shutdown()

    def connect(self):
        if self.unix_socket is not None:
            self._socket = UnixSocket(self.unix_socket)
            self._socket.read_until("\r\n")
        else:
            self._socket = telnetlib.Telnet('127.0.0.1', self.port)
            self._socket.read_until('\r\n'.encode('ascii'))
        self.execute_command('qmp_capabilities')
        return True

    def execute_command(self, cmd, args=None):
        with self.lock:
            # Build the QMP command
            command = {
                'execute': cmd,
                'id': self.id
            }
            if args:
                command['arguments'] = args

            # Send it
            command_str = json.dumps(command) + "\r\n"
            self.log.info("Sending command: %s" % command_str.strip())
            self._socket.write(command_str.encode('ascii'))

            # Read replies until we get our ID (skip events)
            while True:
                if self.unix_socket is not None:
                    raw = self._socket.read_until('\r\n')
                    self.log.info("Received: %s" % raw)
                    resp = json.loads(raw)
                else:
                    raw = self._socket.read_until('\r\n'.encode('ascii'))
                    self.log.info("Received: %s" % raw)
                    resp = json.loads(raw.decode('ascii'))

                if 'event' in resp:
                    continue
                if 'id' in resp:
                    break

            # Check and return
            if resp['id'] != self.id:
                raise Exception('Mismatching id for qmp response')
            self.id += 1

            if 'error' in resp:
                return resp['error']
            if 'return' in resp:
                return resp['return']

            raise Exception("Response contained neither an error nor a return")

    def reset(self):
        """
        Resets the target
        returns: True on success, else False
        """
        pass

    def shutdown(self):
        """
        returns: True on success, else False
        """
        # self._communicator.stop()
        pass

    def get_registers(self, raw=False):
        """
        Gets the current register state based on the hmp info registers
        command. In comparison to register-access with the register protocol,
        this function can also be called while the target is executing.
        :param raw:     If true, return output of the hmp-cmd without parsing
        :type raw:      ``bool``
        :return:        A dictionary with the registers or the register-string
        """

        regs_s = self.execute_command("human-monitor-command",
                                      {"command-line": "info registers"})
        if raw is True:
            return regs_s

        if issubclass(self.origin.avatar.arch, archs.ARM):
            regs_r = re.findall('(...)=([0-9a-f]{8})', regs_s)
            return dict([(r.lower(), int(v, 16)) for r, v in regs_r])
        else:
            raise Exception(("get_registers in non-raw mode called on "
                              "unsupported arch %s") %
                              self.origin.avatar.arch.__name__)

    def x86_get_segment_register_base(self, reg):
        """
        x86-only: get the segment register base using the hmp.
        :param reg:     name of the register
        :type reg:      ``str``
        :return:        The base of segment register ``reg`` on success
        """

        regs = self.get_registers(raw=True)
        regs_r = re.findall(reg.upper()+'\s?=[0-9a-f]+\s([0-9a-f]+)', regs)
        if len(regs_r) != 1:
            raise Exception("Couldn't retrieve base for %s" % reg)

        return int(regs_r[0], 16)
