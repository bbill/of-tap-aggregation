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

#TAP_CONFIG = 'tap_config_mlnx_demo.json'
TAP_CONFIG = 'tap_config.json'

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
        if self.device_type == 'linux':
            self._client.exec_command(LINUX_DEL_FILTERS.format(in_port=in_port))
            self._client.exec_command(LINUX_DEL_QDISCS.format(in_port=in_port))
        elif self.device_type == 'mellanox':
            pass
        else:
            pass


class SimpleTap(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleTap, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        # configuration
        self.config = {}
        # topology graph
        self.net=nx.DiGraph()
        # OF port_name to porn_no map
        self.of_port_map = {}
        # importing configuration from json file
        try:
            with open(TAP_CONFIG) as fh:
                self.config = json.loads(fh.read())
                self.logger.info('TAP configuration loaded from {}.'.format(TAP_CONFIG))
        except IOError:
            self.logger.error('Cant load app config file: {}!'.format(TAP_CONFIG))
        # getting specific configuration from json file
        self.switches_config = self.config.get('switches', {})
        self.rules_config = self.config.get('rules', {})
        self.taps_config = self.config.get('taps', {})
        # joined switches
        self.switches = None
        self.links = None
        self.joined_switches_dpid = []

        # reconfguting SPAN on SPAN devices
        for rule in self.rules_config:
            self.reconfigure_span(self.rules_config[rule].get('span'), rule)

    @handler.set_ev_cls(topo_event.EventSwitchEnter)
    def _switch_enter_handler(self, ev):
        dp = ev.switch.dp
        dpidstr = dpid_to_str(dp.id)
        if dpidstr not in self.switches_config.keys():
            self.logger.warning('Switch {} is not in the configuration. Skipping...'.format(dpidstr))
            return
        self.logger.info('Switch {} joined. Reconfiguring topology graph...'.format(dpidstr))
        self.joined_switches_dpid.append(dpidstr)
        self.logger.info("Ports available on {}:".format(dpidstr))
        # mapping port_name to port_no for switch DP
        for port in dp.ports.values():
            new_map = { port.name.decode('UTF-8'): port.port_no }
            if self.of_port_map.get(dp.id):
                self.of_port_map[dp.id].update(new_map)
            else:
                self.of_port_map[dp.id] = new_map
            self.logger.info("** port_name: {}, port_no: {}, speed: {}".format(port.name, port.port_no, port.curr_speed))

        # filling topology graph with current switches topology information
        self.logger.info('********** switches ************')
        self.switches = get_switch(self.topology_api_app, None)
        # pprint([switch.to_dict() for switch in self.switches])
        switch_ids = [switch.dp.id for switch in self.switches]
        self.net.add_nodes_from(switch_ids)

        # filling topology graph with current links topology information
        self.logger.info('********** links ************')
        self.links = get_link(self.topology_api_app, None)
        # pprint([link.to_dict() for link in self.links])
        link_ids = [(link.src.dpid,link.dst.dpid,{'s_port':link.src.port_no, 'd_port':link.dst.port_no}) for link in self.links]
        self.net.add_edges_from(link_ids)
        links = [(link.dst.dpid,link.src.dpid,{'s_port':link.dst.port_no, 'd_port':link.src.port_no}) for link in self.links]
        self.net.add_edges_from(link_ids)

        self.logger.info('Reconfiguring filters...')
        # resetting all rules on a switch
        self.reset_rules()
        # reconfiguring all rules
        time.sleep(2)
        self.reconfigure_rules()


    def send_desc_stats_request(self, dp):
        parser = dp.ofproto_parser
        req = parser.OFPDescStatsRequest(dp, 0)
        self.logger.info('Sending stats request to "{}"...'.format(dpid_to_str(dp.id)))
        dp.send_msg(req)


    def reset_rules(self):
        self.logger.info('Resetting rules on all switches...')
        for switch in self.switches:
            self.del_flows(switch.dp)
            self.drop_rule(switch.dp)
            self.lldp_rule(switch.dp)


    def reconfigure_rules(self):
        for rule_name in sorted(self.rules_config.keys()):
            rule = self.rules_config[rule_name]
            self.logger.info('Processing rule "{}"...'.format(rule_name))
            in_switch = lib_dpid.str_to_dpid(rule['in_switch'])
            out_switch = lib_dpid.str_to_dpid(rule['out_switch'])
            in_switch_dp = self.get_switch_dp(in_switch)
            out_switch_dp = self.get_switch_dp(out_switch)
            if not in_switch_dp:
                self.logger.info('Ingress switch {} is not in the topology'.format(rule['in_switch']))
                continue
            if not out_switch_dp:
                self.logger.info('Egress switch {} is not in the topology'.format(rule['out_switch']))
                continue
            try:
                path = nx.shortest_path(self.net, in_switch, out_switch)
            except nx.exception.NetworkXNoPath as e:
                self.logger.info(e)
                continue
            print(in_switch, out_switch, path)
            in_port = self.get_of_port_no(in_switch, rule['in_port'])
            out_port = self.get_of_port_no(in_switch, rule['out_port'])
            next_dpid = None
            next_port = None
            if path[0] == in_switch == out_switch:
                self.logger.info('dpid = {}, next_dpid = {}, in_port = {} ({}), out_port = {} ({})'.format(
                                dpid_to_str(in_switch), dpid_to_str(in_switch), in_port,
                                self.get_of_port_name(in_switch, in_port), out_port,
                                self.get_of_port_name(in_switch, out_port)))
                self.flow_inport_to_outport(self.get_switch_dp(in_switch), in_port, out_port)
                continue
            dpid = path.pop(0)
            while path:
                next_dpid = path.pop(0)
                if dpid == in_switch:
                    in_port = self.get_of_port_no(dpid, rule['in_port'])
                    out_port = self.net[dpid][next_dpid]['s_port']
                else:
                    in_port = next_port
                    out_port = self.net[dpid][next_dpid]['s_port']
                self.logger.info('dpid = {}, next_dpid = {}, in_port = {} ({}), out_port = {} ({})'.format(
                                dpid_to_str(dpid), dpid_to_str(next_dpid), in_port,
                                self.get_of_port_name(dpid, in_port), out_port,
                                self.get_of_port_name(dpid, out_port)))
                self.flow_inport_to_outport(self.get_switch_dp(dpid), in_port, out_port)
                next_port = self.net[dpid][next_dpid]['d_port']
                dpid = next_dpid
            in_port = next_port
            out_port = self.get_of_port_no(dpid, rule['out_port'])
            self.logger.info('dpid = {}, next_dpid = {}, in_port = {} ({}), out_port = {} ({})'.format(
                            dpid_to_str(dpid), dpid_to_str(next_dpid), in_port,
                            self.get_of_port_name(dpid, in_port), out_port,
                            self.get_of_port_name(dpid, out_port)))
            self.flow_inport_to_outport(self.get_switch_dp(dpid), in_port, out_port)
        return True

    def reconfigure_span(self, span_dict, rule_name=''):
        if not span_dict:
            return None
        tap_name = span_dict.get('tap')
        tap = self.taps_config.get(tap_name)
        if not tap:
            self.logger.error('No tap defined for rule {}!'.format(rule_name))
            return
        hostname = tap.get('hostname')
        username = tap.get('username')
        password = tap.get('password')
        device_type = tap.get('device_type')
        in_port = span_dict.get('in_port')
        out_port = span_dict.get('out_port')
        direction = span_dict.get('direction')
        truncate = span_dict.get('truncate')
        self.logger.info('Configuring SPAN ports for rule "{}" on device {} (Type: {}):'.format(rule_name, hostname, device_type))
        client = SPAN(hostname=hostname, username=username, password=password, device_type=device_type)
        client.del_filters(in_port)
        client.add_filter(in_port, out_port, direction=direction, truncate=truncate)


    def get_switch_dp(self, dpid):
        for switch in self.switches:
            if switch.dp.id == dpid:
                return switch.dp


    def get_of_port_no(self, dp, port_name):
        if isinstance(dp, Datapath):
            dp = dp.id
        # geting OF port_no from of_port_map
        switch = self.of_port_map.get(dp)
        if switch:
            return switch.get(port_name)
        return None


    def get_of_port_name(self, dp, port_no):
        if isinstance(dp, Datapath):
            dp = dp.id
        # geting OF port_no from of_port_map
        switch = self.of_port_map.get(dp)
        if switch:
            for port_name in switch.keys():
                if switch[port_name] == port_no:
                    return port_name
        return None

    def del_flows(self, dp):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        mod = parser.OFPFlowMod(dp, 0, 0, ofproto.OFPTT_ALL,
                                             ofproto.OFPFC_DELETE,
                                             0, 0, 0, 0xffffffff,
                                             ofproto.OFPP_ANY,
                                             ofproto.OFPG_ANY,
                                             0, match, [])
        dp.send_msg(mod)


    def drop_rule(self, dp):
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [ ]
        self.add_flow(dp, 0, match, actions)


    def lldp_rule(self, dp):
        parser = dp.ofproto_parser
        match = parser.OFPMatch(eth_dst="01:80:c2:00:00:0e", eth_type=0x88cc)
        action = parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER, dp.ofproto.OFPCML_NO_BUFFER)
        self.add_flow(dp, 65535, match, [action])


    def add_flow(self, dp, priority, match, actions):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority,
                                match=match, instructions=inst)
        dp.send_msg(mod)


    def flow_inport_to_outport(self, dp, in_port, out_port):
        parser = dp.ofproto_parser
        if in_port is None or out_port is None:
            self.logger.error('No in_port or out_port specified for DPID:{}'.format(dpid_to_str(dp.id)))
            return
        match = parser.OFPMatch(in_port=in_port)
        action = parser.OFPActionOutput(out_port)
        self.add_flow(dp, 2000, match, [ action ])
