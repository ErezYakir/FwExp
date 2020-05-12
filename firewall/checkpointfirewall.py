import re
import uuid
from .firewall import Firewall
import ipaddress
import json
from .ssh_client import RemoteClient
from globals import PROJECT_DIR


def _parse_single_network_object(obj):
    single_item = {'extra_info': {}}
    obj_type = obj['type']
    if obj_type == 'CpmiAnyObject':
        single_item['type'] = 'IP_RANGE'
        single_item['min_ip'] = int(ipaddress.IPv4Network('0.0.0.0/0', False)[0])
        single_item['max_ip'] = int(ipaddress.IPv4Network('0.0.0.0/0', False)[-1])
    elif obj_type == 'group':
        single_item['type'] = 'GROUP'
    elif obj_type == 'group-with-exclusion-!!need-to-implement!!':
        single_item['type'] = 'GROUP'
    elif obj_type == 'wildcard':
        single_item['type'] = 'WILDCARD'
        single_item['wildcard_ip'] = obj['ipv4-address']
        single_item['wildcard_mask'] = obj['ipv4-mask-wildcard']
    elif obj_type == 'network' or obj_type == 'CpmiInterface':
        net = ipaddress.IPv4Network('{}/{}'.format(obj['subnet4'], obj['mask-length4']), False)
        single_item['type'] = 'IP_RANGE'
        single_item['min_ip'] = int(net[0])
        single_item['max_ip'] = int(net[-1])
    elif obj_type == 'address-range':
        single_item['type'] = 'IP_RANGE'
        single_item['min_ip'] = int(ipaddress.IPv4Address(obj['ipv4-address-first']))
        single_item['max_ip'] = int(ipaddress.IPv4Address(obj['ipv4-address-last']))
    single_item['name'] = obj['name']
    for key in obj:
        if key == 'uid':
            single_item['id'] = obj[key]
        elif key in ['ipv4-address-first', 'ipv4-address-last', 'subnet4', 'mask-length4',
                     'ipv4-address', 'ipv4-mask-wildcard', 'type', 'subnet-mask']:
            pass
        else:
            single_item['extra_info'][key] = obj[key]

    return single_item


def _parse_single_service(obj):
    svc_item = {'extra_info': {}}
    for key in obj:
        if key == 'uid':
            svc_item['id'] = obj[key]
        elif key == 'port' and obj['type'] == 'service-udp':
            svc_item['udp-portrange'] = obj[key]
        elif key == 'port' and obj['type'] == 'service-tcp':
            svc_item['tcp-portrange'] = obj[key]
        elif key in ['interface-uuid', 'type', 'program-number', 'icmp-type', 'icmp-code', 'members']:
            svc_item[key] = obj[key]
        else:
            svc_item['extra_info'][key] = obj[key]
    return svc_item


def _parse_host_as_group(obj):
    parsed_objs = []
    members = []
    for interface in obj.get('interfaces', []):
        parsed_interface = _parse_single_network_object(interface)
        members.append(parsed_interface['id'])
        parsed_objs.append(parsed_interface)
    # Creating a new object that is not in checkpoint so host can be a group
    ip = int(ipaddress.IPv4Address(obj['ipv4-address']))
    new_obj_uuid = str(uuid.uuid4())
    members.append(new_obj_uuid)
    new_obj = {'name': obj['name'] + '_HOST_IP_OBJ', 'id': new_obj_uuid, 'type': 'IP_RANGE', 'min_ip': ip, 'max_ip': ip}
    parsed_objs.append(new_obj)

    # Now creating the group
    group_obj = {'type': 'GROUP', 'name': obj['name'], 'members': members, 'id': obj['uid'], 'extra_info': {}}
    for key in obj:
        if key not in ['type', 'name', 'interfaces', 'ipv4-address', 'uid']:
            group_obj['extra_info'][key] = obj[key]

    parsed_objs.append(group_obj)
    return parsed_objs


class CheckpointFirewall(Firewall):
    def __init__(self, ip, user, pwd, db_path, db_name="Firewall_info", port=22, gateway_name='test'):
        super().__init__(ip, user, pwd, db_path, db_name)
        self.misc_obj_types = ['vpn-community-meshed', 'vpn-community-star', 'dns-domain', 'RulebaseAction',
                                'CpmiLogicalServer', 'Global', 'security-zone', 'Track',
                                'threat-profile', 'ThreatExceptionRulebase',
                                'CpmiSrCommunity', 'CpmiVoipGwDomain',
                                'CpmiVoipSkinnyDomain', 'CpmiVoipSipDomain', 'dynamic-object',
                                'multicast-address-range', 'access-layer']
        self.network_obj_types = ['host', 'CpmiAnyObject', 'group', 'wildcard',
                                  'network', 'address-range', 'group-with-exclusion']
        self.service_obj_types = ['service-tcp', 'service-udp', 'service-dce-rpc',
                                  'service-icmp', 'service-rpc', 'service-group']
        self.port = port
        self.gateway = gateway_name
        self.config_path = PROJECT_DIR + "/checkpoint_config_files/"
        self.checkpoint_rules = {}
        self.checkpoint_objects = {}

    def fetch(self, fetch_remotely=True):
        if fetch_remotely:
            remote = RemoteClient(self.ip, self.user, self.pwd, self.port)
            response = remote.execute_command(
                '$MDS_FWDIR/scripts/web_api_show_package.sh -g {} -u {} -p {}'.format(self.gateway, self.user, self.pwd)
            )
            if 'successfully' not in response[0]:
                raise Exception('Could not export checkpoint configuration.')
            result_path = re.search('Result file location:\s(.+)', response[1]).group(1)
            remote.download_file(result_path, self.config_path)
            import tarfile
            tf = tarfile.open(self.config_path + result_path)
            tf.extractall(self.config_path)

        with open(self.config_path + 'Standard_objects.json', 'r') as f:
            self.checkpoint_objects = json.loads(f.read())
        with open(self.config_path + 'Network-Management server.json', 'r') as f:
            self.checkpoint_rules = json.loads(f.read())

    def _parse_policy(self):
        policy_list = []
        policy_item = {'extra_info': {}}
        for rule in self.checkpoint_rules:
            for key in rule:
                if key == 'uid':
                    policy_item['id'] = rule[key]
                elif key == 'rule-number':
                    policy_item['priority'] = rule[key]
                elif key == 'action':
                    policy_item['action'] = (self._get_obj_by_uid(rule['action'])['name'] == 'Accept')
                elif key in ['source-negate', 'destination-negate', 'service-negate', 'destination',
                             'source', 'enabled', 'service', 'name']:
                    policy_item[key] = rule[key]
                else:
                    policy_item['extra_info'][key] = rule[key]
            policy_list.append(policy_item)
            policy_item = {'extra_info': {}}
        return policy_list

    def _parse_services(self):
        parsed_objs = []
        for obj in self.checkpoint_objects:
            if obj['type'] in self.service_obj_types:
                new_svc = _parse_single_service(obj)
                parsed_objs.append(new_svc)
        return parsed_objs

    def _parse_network_objects(self):
        parsed_objs = []
        for obj in self.checkpoint_objects:
            if obj['type'] == 'host':
                # In checkpoint, host can contain subnets, so we'll consider it as a group
                new_network_objs = _parse_host_as_group(obj)
                parsed_objs.extend(new_network_objs)
            elif obj['type'] in self.network_obj_types:
                new_network_obj = _parse_single_network_object(obj)
                parsed_objs.append(new_network_obj)
        return parsed_objs

    def _get_obj_by_uid(self, uid):
        item = list(filter(lambda obj: obj['uid'] == uid, self.checkpoint_objects))[0]
        return item

    def _parse_misc(self):
        objs = []
        for obj in self.checkpoint_objects:
            if obj['type'] in self.misc_obj_types:
                objs.append(obj)
            elif obj['type'] in self.network_obj_types or obj['type'] in self.service_obj_types:
                pass
            else:
                print('Unrecognized checkpoint object type:', obj['type'])
                raise NotImplementedError('Unrecognized checkpoint object type:', obj['type'])
        return objs
