import ConfigParser
import logging
import optparse
import os
import subprocess
import sys
import time

from wakeupdaemon import arp


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
        LOG.warning('Unable to wake %s' % self._alias)


class HostStateWOL(HostState):
    def wake(self, requester):
        LOG.warning('Waking %s for %s with WOL' % (self._alias, requester))
        if self._interface:
            intfarg = '-i %s' % self._interface
        else:
            intfarg = ''
        cmd = 'etherwake %s %s' % (intfarg, self._alias)
        LOG.debug('Using command %s' % repr(cmd))
        r = subprocess.call(cmd, shell=True)
        if r != 0:
            LOG.error('Failed to wake %s' % (self._alias))


HOST_TYPES = {
    'wol': HostStateWOL,
}


def update_timers(watches, arp_frame):
    seen = []
    for ip, state in watches.items():
        if arp_frame.sender_ip == ip:
            state.seen_alive()
        state.ping()
    return bool(seen)


def load_hosts_from_conf(conf):
    def safe(fn, section, option, default):
        try:
            return fn(section, option)
        except ConfigParser.NoOptionError:
            return default

    hosts = []
    for hostdef in filter(lambda n: n.startswith('host:'), conf.sections()):
        _, name = hostdef.split(':')
        hosttype = safe(conf.get, hostdef, 'type', 'wol')
        if hosttype not in HOST_TYPES:
            raise Exception('Host %s has invalid type %s' % (name, hosttype))
        state = HOST_TYPES[hosttype](
            conf.get(hostdef, 'ip'), name,
            interface=safe(conf.get, hostdef, 'interface', None),
            timeout=safe(conf.getint, hostdef, 'timeout', 90))
        hosts.append(state)
    return hosts


def load_hosts_from_args(args):
    hosts = []
    for arg in args:
        try:
            ip, name = arg.split(':')
            iface = None
        except ValueError:
            ip, name, iface = arg.split(':')
        hosts.append(HostStateWOL(ip, name, interface=iface))
    return hosts


def load_hosts(conf, args):
    hosts = []
    hosts += load_hosts_from_conf(conf)
    hosts += load_hosts_from_args(args)
    return hosts


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

    conf = ConfigParser.ConfigParser()
    conf_file = os.path.expanduser(os.path.join('~', '.wakeupd'))
    if os.path.exists(conf_file):
        conf.read(conf_file)

    hosts = load_hosts(conf, args)
    if len(hosts) == 0:
        print 'No hosts are defined'
        return 1
    watches = dict([(host._ip, host) for host in hosts])

    logging.basicConfig(format='%(asctime)-15s %(levelname)s %(message)s')
    LOG = logging.getLogger()

    if options.debug:
        LOG.setLevel(logging.DEBUG)
    elif options.verbose:
        LOG.setLevel(logging.INFO)
    else:
        LOG.setLevel(logging.WARNING)


    sock = arp.ArpSocket()

    while True:
        f = sock.get_frame()
        if f.proto == arp.ETH_P_ARP:
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
