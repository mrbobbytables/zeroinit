#!/usr/bin/env python3
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

import argparse
import fcntl
import ipaddress
import logging
import socket
import struct
import sys
from subprocess import Popen
from time import sleep

logging.basicConfig(format='[%(asctime)s][%(levelname)s][%(module)s][%(name)s][%(funcName)s] %(message)s', level=logging.WARNING)
log = logging.getLogger(__name__)

try:
    from zeroconf import ServiceBrowser, ServiceInfo, ServiceStateChange, Zeroconf
except ImportError:
    log.error('Zeroconf module not found. Execution cannot continue. Please install with: pip3 install zeroconf.')
    sys.exit(1)


LOG_LEVELS = {
    'CRITICAL': logging.CRITICAL,
    'DEBUG': logging.DEBUG,
    'ERROR': logging.ERROR,
    'INFO': logging.INFO,
    'WARNING': logging.WARNING }


def main(args):
    options = parse_opts(args)
    try:
        log.setLevel(LOG_LEVELS[options['log_level'].upper()])
        if options['zc_log']:
            zc_log = logging.getLogger('zeroconf')
            zc_log.setLevel(LOG_LEVELS[options['log_level'].upper()])
    except KeyError:
        log.error('log_level: {0} - Not defined. Execution Terminated.'.format(options['log_level']))
        sys.exit(1)

    try:
        bootstrap = Bootstrapper(**options)
        bootstrap.bootstrap()
    except KeyboardInterrupt:
            log.error('Discovery interrupted. Aborting.')
            sys.exit(1)


def parse_opts(args):

    parser = argparse.ArgumentParser(description='Zeroconf Bootstrapper.')
    parser.add_argument(
        '-e',
        '--expect',
        type=int,
        default=3,
        help='The number of members to expect before the leader is elected to call the action. -- Default: 3')

    parser.add_argument(
        '-i',
        '--iface',
        type=str,
        default='eth0',
        help='The interface to use for discovery. -- Default: eth0.')

    parser.add_argument(
        '-a',
        '--action',
        type=str,
        default='echo',
        help='The command or script that should be called by the leader once elected. -- Default: echo')

    parser.add_argument(
        '-l',
        '--log_level',
        type=str,
        default='WARNING',
        help='log level -- Default: WARNING')

    parser.add_argument(
        '-z',
        '--zc_log',
        type=bool,
        default=False,
        help='zc_log - enable zeroconf module logging -- Default: False')

    options = vars(parser.parse_args())
    return options




class Bootstrapper:
    def __init__(self, iface=None, expect=None, **kwargs):
        self.log_level = kwargs.get('log_level', 'INFO')
        self._log =  logging.getLogger(__name__)
        try:
            self._log.setLevel(LOG_LEVELS[self.log_level.upper()])
        except KeyError:
            log.error('log_level: {} - Not defined'.format(self.log_level))
            raise

        self._log.debug('Begin Bootstrapper initialization')

        self.iface = iface or 'eth0'
        self.expect = expect or 3

        self._discovery_peer_count = self.expect
        self._leader_id = 0
        self._peers = []

        self.action = kwargs.get('action', 'echo')
        self.bootstrap_ip = kwargs.get('bootstrap_ip', None)
        self.election_id = kwargs.get('election_id', None)
        self.service_discovery_type = kwargs.get('service_discovery_type', None)
        self.service_discovery_def = kwargs.get('service_discovery_def', None)
        self.service_leader_type = kwargs.get('service_leader_type', None)
        self.service_leader_def = kwargs.get('service_leader_def', None)

        self._log.debug('iface: {}'.format(self.iface))
        self._log.debug('expect: {}'.format(self.expect))
        self._log.debug('bootstrap_ip: {}'.format(self.bootstrap_ip))
        self._log.debug('election_id: {}'.format(self.election_id))
        self._log.debug('service_discovery_type: {}'.format(self.service_discovery_type))
        self._log.debug('service_discovery_def: {}'.format(self.service_discovery_def))
        self._log.debug('service_leader_type: {}'.format(self.service_leader_type))
        self._log.debug('service_leader_def: {}'.format(self.service_leader_def))



    @property
    def bootstrap_ip(self):
        return self._bootstrap_ip

    @bootstrap_ip.setter
    def bootstrap_ip(self, value=None):
        self._bootstrap_ip = value or self._get_iface_ip(self.iface)


    @property
    def election_id(self):
        return self._election_id

    @election_id.setter
    def election_id(self, value=None):
        self._election_id = value or int(ipaddress.IPv4Address(self.bootstrap_ip))


    @property
    def service_discovery_type(self):
        return self._service_discovery_type

    @service_discovery_type.setter
    def service_discovery_type(self, value=None):
        self._service_discovery_type = value or '_btstrp._tcp.local.'


    @property
    def service_leader_type(self):
        return self._service_leader_type

    @service_leader_type.setter
    def service_leader_type(self, value=None):
        self._service_leader_type = value or '_leader._tcp.local.'


    @property
    def service_discovery_def(self):
        return self._service_discovery_def

    @service_discovery_def.setter
    def service_discovery_def(self, bootstrap_ip=None, service_type=None, election_id=None):
        bootstrap_ip = bootstrap_ip or self.bootstrap_ip
        service_type = service_type or self.service_discovery_type
        election_id = election_id or self.election_id

        self._service_discovery_def = self.get_service_def(
            bootstrap_ip = bootstrap_ip,
            service_type = service_type,
            election_id = election_id )


    @property
    def service_leader_def(self):
        return self._service_leader_def

    @service_leader_def.setter
    def service_leader_def(self, bootstrap_ip=None, service_type=None, election_id=None):
        bootstrap_ip = bootstrap_ip or self.bootstrap_ip
        service_type = service_type or self.service_leader_type
        election_id = election_id or self.election_id

        self._service_leader_def = self.get_service_def(
            bootstrap_ip = bootstrap_ip,
            service_type = service_type,
            election_id = election_id )


    def get_service_def(self, bootstrap_ip=None, service_type=None, election_id=None):
        bootstrap_ip = bootstrap_ip or self.bootstrap_ip
        service_type = service_type or self.service_discovery_type
        election_id = election_id or self.election_id

        service_name = socket.gethostname() + '.' + service_type
        service_address = socket.inet_aton(bootstrap_ip)
        service_properties = { 'election_id': str(election_id) }
        service_server = socket.gethostname() + '.local.'

        service_def = ServiceInfo(
            type = service_type,
            name = service_name,
            address = service_address,
            port = 0,
            weight = 0,
            properties = service_properties,
            server = service_server )
        return service_def


    def _get_iface_ip(self, iface):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', iface[:15].encode('utf-8'))
            )[20:24])


    def _election_handler(self, zeroconf, service_type, name, state_change):
        if state_change is ServiceStateChange.Added and service_type == self.service_discovery_type:
                service_info = zeroconf.get_service_info(service_type, name)
                if service_info:
                    self._log.debug('service_discovery_added: {}'.format(service_info))
                    node = {  'election_id': int(service_info.properties.get(b'election_id')), 'bootstrap_ip':  socket.inet_ntoa(service_info.address) }
                    self._log.info('Peer discovered - IP: {0} - Election ID: {1}'.format(node['bootstrap_ip'], node['election_id']))
                    self._peers.append(node)
                    if len(self._peers) == self.expect:
                        self._leader_id = self.resolve_leader(self._peers)
                        self._log.debug('Leader resolved to election ID: {}'.format(self._leader_id))
                        if self.election_id == self._leader_id:
                            self._log.info('Promoted to leader. Registering leader service with: IP: {0} - Election ID: {1}'.format(self.bootstrap_ip, self.election_id))
                            sleep(1)
                            zeroconf.register_service(self.service_leader_def)

        if state_change is ServiceStateChange.Removed and service_type == self.service_discovery_type:
            self._discovery_peer_count -= 1
            log.debug('Peer unregistered. {} nodes left before leader executes action.'.format(self._discovery_peer_count))

        if state_change is ServiceStateChange.Added and service_type == self.service_leader_type:
            service_info = zeroconf.get_service_info(service_type, name)
            if service_info:
                self._log.info('Leader discovered - IP: {0} - Election ID: {1}'.format(socket.inet_ntoa(service_info.address), self._leader_id))
                sleep(1)
                zeroconf.unregister_service(self.service_discovery_def)


    def resolve_leader(self, peers=None):
        peers = peers or self._peers
        sorted_peers = sorted(peers, key=lambda x: x['election_id'])
        return sorted_peers[0]['election_id']

    def get_peer_addresses(self, peers=None):
        peer_ips = []
        peers = peers or self._peers
        for peer in peers:
            peer_ips.append(peer.get('bootstrap_ip'))
        return peer_ips


    def bootstrap(self):
        try:
            zeroconf = Zeroconf(interfaces=[ self.bootstrap_ip ])
            self._log.debug('Zeroconf instantiated.')
        except:
            self._log.error('Error instantiating zeroconf instance on interface: {0} with IP: {1}'.format(self.iface, self.bootstrap_ip))
            raise

        try:
            zeroconf.register_service(self.service_discovery_def)
            discovery_browser = ServiceBrowser(zeroconf, self.service_discovery_type, handlers=[ self._election_handler ])
            leader_browser = ServiceBrowser(zeroconf, self.service_leader_type, handlers=[ self._election_handler ])
        except:
            self._log.error('Error encountered with registered zeroconf services or browser.')
            raise

        while True:
            sleep(.1)
            if self._discovery_peer_count <= 0:
                log.debug('All peers unregistered from discovery service.')
                break

        if self.election_id == self._leader_id:
            zeroconf.unregister_service(self.service_leader_def)
            self._log.debug('Leader service unregistered.')

        sleep(1)
        try:
            zeroconf.close()
        except:
            self._log.error('Error encountered closing zerconf instance.')
            raise

        self._log.debug('Zerconf instance close.')

        if self.election_id == self._leader_id:
            bootstrap_command = [ self.action ] + self.get_peer_addresses(self._peers)
            self._log.info('Leader performing bootstrap action: {}'.format(' '.join(bootstrap_command)))
            Popen(bootstrap_command)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
