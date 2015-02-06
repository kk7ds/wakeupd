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
