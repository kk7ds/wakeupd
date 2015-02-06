import logging
import optparse
import os
import socket
import struct
import subprocess
import sys
import time

ETH_P_ALL = 3
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806

ETHER_PROTOS = {
    ETH_P_IP: 'IP',
    ETH_P_ARP: 'ARP',
}

ARP_OPS = {
    1: 'request',
    2: 'reply',
}


def hexify(data, delim=' '):
    hexed = []
    for c in data:
        hexed.append('%02x' % ord(c))
    return delim.join(hexed)


class ArpPacket(object):
    @classmethod
    def from_raw(cls, data):
        f = cls()
        f.htype, f.ptype, f.hlen, f.plen, op = (
            struct.unpack('>HHBBH', data[:8]))
        f.operation = ARP_OPS.get(op, '?')
        f._sender_mac = data[8:14]
        f._sender_ip = data[14:18]
        f._target_mac = data[18:24]
        f._target_ip = data[24:28]

        return f

    @property
    def sender_mac(self):
        return hexify(self._sender_mac, ':')

    @property
    def target_mac(self):
        return hexify(self._target_mac, ':')

    @property
    def sender_ip(self):
        return socket.inet_ntoa(self._sender_ip)

    @property
    def target_ip(self):
        return socket.inet_ntoa(self._target_ip)

    def __str__(self):
        lines = []
        lines.append('HType: %04x' % self.htype)
        lines.append('PType: %04x' % self.ptype)
        lines.append('HLen:  %04x' % self.hlen)
        lines.append('PLen:  %04x' % self.plen)
        lines.append('Op:    %s' % self.operation)
        lines.append('Sender: %s %s' % (self.sender_mac, self.sender_ip))
        lines.append('Target: %s %s' % (self.target_mac, self.target_ip))
        return '\n'.join(lines)


class EthernetFrame(object):
    @classmethod
    def from_raw(cls, data):
        f = cls()
        f.src = data[:6]
        f.dst = data[6:12]
        f.proto, = struct.unpack('>H', data[12:14])

        if f.proto == ETH_P_ARP:
            f.fproto = ArpPacket.from_raw(data[14:])
        else:
            f.fproto = None

        return f

    @property
    def source_mac(self):
        return hexify(self.src, ':')

    @property
    def dest_mac(self):
        return hexify(self.dst, ':')

    def __str__(self):
        lines = []
        lines.append('Src:   %s' % hexify(self.src, ':'))
        lines.append('Dst:   %s' % hexify(self.dst, ':'))
        lines.append('Proto: %04x (%s)' % (self.proto,
                                           ETHER_PROTOS.get(self.proto, '?')))
        return '\n'.join(lines) + '\n' + str(self.fproto)


class HostState(object):
    def __init__(self, ip, alias, interface=None, timeout=90):
        self._ip = ip
        self._alias = alias
        self._interface = interface
        self._timeout = timeout
        self._last_seen = 0
        self._last_ping = 0

    def ping(self):
        information_age = time.time() - self._last_seen
        ping_interval = self._timeout / 2
        if not self._last_ping or (
                information_age > ping_interval and
                time.time() - self._last_ping >= ping_interval and
                self.is_alive):
            LOG.info('Pinging %s' % self)
            with file(os.devnull, 'wb') as devnull:
                r = subprocess.call('fping -q -c1 -t50 %s' % self._ip,
                                shell=True, stdout=devnull, stderr=devnull)
                if r == 0:
                    self.seen_alive()
            self._last_ping = time.time()

    def seen_alive(self):
        last_seen_ago = '%i sec ago' % (time.time() - self._last_seen)
        LOG.info('%s seen alive (since %s)' % (
            self._alias, self._last_seen and last_seen_ago or 'never'))
        self._last_seen = time.time()

    @property
    def is_alive(self):
        return (time.time() - self._last_seen) < self._timeout

    def __str__(self):
        information_age = '%i sec ago' % (time.time() - self._last_seen)
        return '%s [%s]: Alive: %s (%s)' % (
            self._alias, self._ip, self.is_alive,
            self._last_seen and information_age or 'never')

    def wake(self, requester):
        LOG.warning('Waking %s for %s' % (self._alias, requester))
        if self._interface:
            intfarg = '-i %s' % self._interface
        else:
            intfarg = ''
        r = subprocess.call('etherwake %s %s' % (intfarg,
                                                 self._alias),
                            shell=True)
        if r != 0:
            LOG.error('Failed to wake %s' % (self._alias))


def update_timers(watches, arp_frame):
    seen = []
    for ip, state in watches.items():
        if arp_frame.sender_ip == ip:
            state.seen_alive()
        state.ping()
    return bool(seen)


def main():
    global LOG

    parser = optparse.OptionParser()
    parser.add_option('-D', '--debug', help='Debug output',
                      default=False, action='store_true')
    parser.add_option('-v', '--verbose', help='Verbose output',
                      default=False, action='store_true')
    parser.add_option('-t', '--timeout', default=90,
                      help='Timeout (sec) before considering a host offline',
                      type='int')
    options, args = parser.parse_args()

    if len(args) == 0:
        print 'Arguments are required in the form of ip:hostname'
        return 1

    logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s')
    LOG = logging.getLogger()

    if options.debug:
        LOG.setLevel(logging.DEBUG)
    elif options.verbose:
        LOG.setLevel(logging.INFO)
    else:
        LOG.setLevel(logging.WARNING)

    watches = {}

    for arg in args:
        if ':' not in arg:
            print '`%s\' is not in valid ip:hostname[:iface] format'
            return 1
        try:
            ip, hostname = arg.split(':')
            iface = None
        except ValueError:
            ip, hostname, iface = arg.split(':')

        watches[ip] = HostState(ip, hostname, interface=iface,
                                timeout=options.timeout)
        LOG.debug('Watching %s' % watches[ip])

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ARP));

    while True:
        data = s.recv(65535)
        f = EthernetFrame.from_raw(data)
        if f.proto == ETH_P_ARP:
            LOG.debug('ARP: %s %s -%s-> %s %s' % (
                f.fproto.sender_mac, f.fproto.sender_ip,
                f.fproto.operation,
                f.fproto.target_mac, f.fproto.target_ip))

            update_timers(watches, f.fproto)
            if f.fproto.target_ip in watches:
                watch = watches[f.fproto.target_ip]
                if not watch.is_alive:
                    watch.wake(f.fproto.sender_ip)

if __name__ == '__main__':
    sys.exit(main())
