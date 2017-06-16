import re
import paramiko

LINUX_ADD_QDISC_INGRESS = "tc qdisc add dev {} handle ffff: ingress"
LINUX_ADD_QDISC_EGRESS = "tc qdisc add dev {} handle 1: root prio"
LINUX_ADD_FILTER = "tc filter add dev {} parent {}: {} matchall action mirred egress mirror dev {}"
LINUX_SHOW_FILTER = "tc filter show dev {} {} {}"
LINUX_DEL_QDISCS = "tc qdisc del dev {in_port} handle ffff: ingress && tc qdisc del dev {in_port} handle 1: root prio"
LINUX_DEL_FILTERS = "tc filter del dev {in_port} && tc filter del dev {in_port} ingress"

class SPAN(object):
    def __init__(self, hostname=None, username=None, password = None, device_type="linux"):
        self.hostname = hostname
        self.device_type = device_type
        self._client = None
        if hostname and username and password:
            self.connect(hostname, username, password, device_type)

    @property
    def connected(self):
        if self.device_type == 'linux':
            return self._client is not None
        return False

    def disconnect(self):
        if self._client:
            if self.device_type == 'linux':
                self._client.close()
                del self._client

    def connect(self, hostname, username, password, device_type='linux'):
        if not (hostname and username and password):
            print('Invalid parameters!')
            return False
        self.hostname = hostname
        self.device_type = device_type
        if device_type == 'linux':
            self._client = paramiko.SSHClient()
            self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._client.connect(self.hostname, username=username, password=password)
            return True
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

    def add_filter(self, in_port, out_port, direction='both', pref=None):
        result = True
        if not self.connected:
            return False
        cmds = []
        if self.device_type == 'linux':
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
            print(cmds)
            for cmd in cmds:
                stdin, stdout, stderr = self._client.exec_command(cmd)
                stderr = stderr.readlines()
                if stderr:
                    print('Error executing command: {}'.format('\n'.join(stderr)))
                    result = False
        else:
            print('Non-supported device-type: {}'.format(self.device_type))
        return result

    def del_filters(self, in_port):
        if not self.connected:
            return None
        self._client.exec_command(LINUX_DEL_FILTERS.format(in_port=in_port))
        self._client.exec_command(LINUX_DEL_QDISCS.format(in_port=in_port))

if __name__ == '__main__':
    span = SPAN(device_type='linux')
    span.connect('192.168.2.212', 'root', 'vagrant')
    span.add_filter('eth0', 'lo', direction='both')
