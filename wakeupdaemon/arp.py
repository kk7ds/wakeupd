import socket
import struct

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


class ArpSocket(object):
    def __init__(self):
        self._socket = socket.socket(socket.AF_PACKET,
                                     socket.SOCK_RAW,
                                     socket.htons(ETH_P_ARP));

    def get_frame(self):
        data = self._socket.recv(65535)
        return EthernetFrame.from_raw(data)
