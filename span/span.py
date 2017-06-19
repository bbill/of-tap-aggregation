import re
import logging
import json
import time

from ryu.base import app_manager
from ryu.controller import handler
from ryu.controller import ofp_event
from ryu.controller.controller import Datapath
from ryu.topology import api as topo_api
from ryu.topology import event as topo_event
from ryu.topology.api import get_switch, get_link
from ryu.lib import dpid as lib_dpid
from ryu.lib.dpid import dpid_to_str
from ryu.lib import ofctl_nicira_ext
from ryu.lib import ofctl_v1_3 as ofctl
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import nicira_ext
from pprint import pprint
import networkx as nx
import paramiko
import netmiko

TAP_CONFIG = 'tap_config_mlnx_demo.json'
#TAP_CONFIG = 'tap_config.json'

LINUX_ADD_QDISC_INGRESS = "tc qdisc add dev {} handle ffff: ingress"
LINUX_ADD_QDISC_EGRESS = "tc qdisc add dev {} handle 1: root prio"
LINUX_ADD_FILTER = "tc filter add dev {} parent {}: {} matchall action mirred egress mirror dev {}"
LINUX_SHOW_FILTER = "tc filter show dev {} {} {}"
LINUX_DEL_QDISCS = "tc qdisc del dev {in_port} handle ffff: ingress && tc qdisc del dev {in_port} handle 1: root prio"
LINUX_DEL_FILTERS = "tc filter del dev {in_port} && tc filter del dev {in_port} ingress"

class SPAN(object):
    def __init__(self, hostname=None, username=None, password=None, device_type='linux'):
        self.hostname = hostname
        self.device_type = device_type
        self._client = None
        if hostname and username and password:
            self.connect(hostname, username, password, device_type)


    @property
    def connected(self):
        if self.device_type == 'linux':
            return self._client and self._client.get_transport()
        elif self.device_type == 'mellanox':
            return self._client and not self._client.remote_conn.closed
        else:
            pass
        return False

    def disconnect(self):
        if self._client:
            if self.device_type == 'linux':
                self._client.close()
            elif self.device_type == 'mellanox':
                self._client.disconnect()
            else:
                pass
            self._client = None

    def connect(self, hostname, username, password, device_type):
        if not (hostname and username and password):
            print('Invalid parameters!')
            return False
        self.hostname = hostname
        self.device_type = device_type
        if device_type == 'linux':
            try:
                self._client = paramiko.SSHClient()
                self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self._client.connect(self.hostname, username=username, password=password)
                return True
            except (paramiko.SSHException, socket.error) as e:
                print('Error connecting to {}: {}'.format(hostname, e))
            except paramiko.AuthenticationException as e:
                print('Authentication error for {}: {}'.format(hostname, e))
        elif device_type == 'mellanox':
            try:
                self._client = netmiko.ConnectHandler(device_type='mellanox_ssh',
                                                      ip=self.hostname,
                                                      username=username,
                                                      password=password)
                return True
            except Exception as e:
                print('Error connecting to {}: {}'.format(hostname, e))
        else:
            print('Non-supported device-type: {}'.format(self.device_type))
        return False

    def get_filter_span_ports(self, in_port, direction='ingress', pref=None):
        if not self.connected:
            return None
        preference = 'pref {}'.format(pref) if pref else ''
        if direction == 'ingress':
            cmd = LINUX_SHOW_FILTER.format(in_port, 'ingress', preference)
        else:
            cmd = LINUX_SHOW_FILTER.format(in_port, '', preference)
        stdin, stdout, stderr = self._client.exec_command(cmd)
        stdout = "".join(stdout.readlines())
        result = re.findall('(?<=Mirror to device )\w+', stdout)
        return result


    def add_filter(self, in_port, out_port, direction='both', pref=None, truncate=False):
        result = True
        if not self.connected:
            return False
        print('Adding span filter for "{}" device:\n'
              '** in_port: {}\n'
              '** out_port: {}\n'
              '** direction: {}\n'.format(self.device_type, in_port, out_port, direction))
        if self.device_type == 'linux':
            result = self.add_filter_linux(in_port, out_port, direction, pref)
        elif self.device_type == 'mellanox':
            result = self.add_filter_mellanox(in_port, out_port, direction, truncate)
        else:
            print('Non-supported device-type: "{}"'.format(self.device_type))
        return result


    def add_filter_linux(self, in_port, out_port, direction='both', pref=None):
        result = True
        cmds = []
        preference = 'pref {}'.format(pref) if pref else ''
        if direction in ['ingress', 'both']:
            ports = self.get_filter_span_ports(in_port, direction='ingress', pref=pref)
            if out_port in ports:
                print('Filter already exists')
                return False
            cmds.append(LINUX_ADD_QDISC_INGRESS.format(in_port))
            cmds.append(LINUX_ADD_FILTER.format(in_port, 'ffff', preference, out_port))
        if direction in ['egress', 'both']:
            ports = self.get_filter_span_ports(in_port, direction='egress', pref=pref)
            if out_port in ports:
                print('Filter already exists')
                return False
            cmds.append(LINUX_ADD_QDISC_EGRESS.format(in_port))
            cmds.append(LINUX_ADD_FILTER.format(in_port, '1', preference, out_port))
        for cmd in cmds:
            print('Adding filter to device {} with command: {}'.format(self.hostname, cmd))
            stdin, stdout, stderr = self._client.exec_command(cmd)
            stderr = stderr.readlines()
            if stderr:
                print('Error executing command: {}'.format('\n'.join(stderr)))
                result = False
        return result

    def add_filter_mellanox(self, in_port, out_port, direction='both', truncate=False):
        if not self._client.check_config_mode():
            self._client.enable()
            self._client.config_mode()
        cmds = ['interface ethernet {} shutdown'.format(out_port),
                           'monitor session 1',
                           'no destination interface',
                           'destination interface ethernet {} force'.format(out_port),
                           'add source interface ethernet {} direction {}'.format(in_port, direction),
                           'truncate' if truncate else '',
                           'no shutdown',
                           'exit',
                           'no interface ethernet {} shutdown'.format(out_port)
                          ]
        try:
            print('Configuring monitor session on device {} with commands:\n# {}'.format(self.hostname, '\n# '.join(cmds)))
            output = self._client.send_config_set(cmds)
        except Exception as e:
            print('Error executing commands: {}', e)
            return False
        if output.find('%') > -1:
            print('Some commands resulted with an error:\n{}'.format(output))
            return False
        print('Filter was successfully added.')
        return True

    def del_filters(self, in_port):
        if not self.connected:
            return None
        print('Clearing all filters on device {} from port "{}"'.format(self.hostname, in_port))
        self._client.exec_command(LINUX_DEL_FILTERS.format(in_port=in_port))
        self._client.exec_command(LINUX_DEL_QDISCS.format(in_port=in_port))

if __name__ == '__main__':
    span = SPAN()
    span.connect('10.143.34.57', 'admin', 'admin', 'mellanox')
    span.add_filter('1/20', '1/21', direction='both', truncate=True)
