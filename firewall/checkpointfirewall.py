import requests
import re
from .firewall import Firewall
import ipaddress
import json


class CheckpointFirewall(Firewall):
    def __init__(self, ip, user, pwd, db_name):
        super().__init__(ip, user, pwd, db_name)
        self.known_obj_types = ['vpn-community-meshed', 'dns-domain', 'RulebaseAction', 'service-tcp',
                              'CpmiLogicalServer', 'Global', 'security-zone', 'Track', 'threat-profile',
                              'ThreatExceptionRulebase', 'host', 'CpmiAnyObject', 'group', 'wildcard', 'network',
                                'address-range', 'service-udp', 'service-dce-rpc', 'service-icmp', 'service-rpc',
                                'CpmiSrCommunity', 'service-group']

    def fetch(self):
        # TODO: fetch from http / ssh
        with open('checkpoint_config_files/Standard_objects.json', 'r') as f:
            self.checkpoint_objects = json.loads(f.read())
        with open('checkpoint_config_files/Network-Management server.json', 'r') as f:
            self.checkpoint_rules = json.loads(f.read())

    def _parse_policy(self):
        policy_list = []
        for rule in self.checkpoint_rules:
            rule['id'] = rule.pop('uid')
            rule['priority'] = rule.pop('rule-number')
            rule['action'] = (self._get_obj_by_uid(rule['action'])['name'] == 'Accept')
            rule.pop('comments', None)
            rule.pop('meta-info', None)
            rule.pop('time', None)
            rule.pop('install-on', None)
            rule.pop('track', None)
            rule.pop('action-settings', None)
            rule.pop('custom-fields', None)
            policy_list.append(rule)
        return policy_list

    def _parse_service_objects(self):
        #### List of possible object types:
        # host, vpn-community-meshed
        #### List of object possible parsed properties:
        # ip_min, ip_max
        parsed_objs = []
        for obj in self.checkpoint_objects:
            obj_type = obj['type']
            if obj_type == 'service-udp':
                # Match for Any: Indicates whether this service is used when 'Any' is set as the rule's service and
                # there are several service objects with the same source port and protocol.
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'udp',
                           'port': obj['port'], 'protocol': obj.get('protocol'),
                           'match-signature': obj['match-by-protocol-signature'], 'match-for-any': obj['match-for-any']}
            elif obj_type == 'service-dce-rpc':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'dce-rpc',
                           'interface-uuid': obj['interface-uuid']}
            elif obj_type == 'service-rpc':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'dce-rpc',
                           'program-number': obj['program-number']}
            elif obj_type == 'service-tcp':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'tcp',
                           'port': obj['port'], 'protocol': obj.get('protocol'),
                           'match-signature': obj['match-by-protocol-signature'], 'match-for-any': obj['match-for-any']}
            elif obj_type == 'service-icmp':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'icmp',
                           'icmp-type': obj['icmp-type'], 'icmp-code': obj['icmp-code']}
            elif obj_type == 'service-group':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'],
                           'type': 'group', 'members': obj['members']}
            elif obj_type in self.known_obj_types:
                continue
            else:
                raise NotImplementedError()
            parsed_objs.append(new_obj)
        return parsed_objs

    def _parse_address_objects(self):
        #### List of possible object types:
        # host, vpn-community-meshed
        #### List of object possible parsed properties:
        # ip_min, ip_max
        parsed_objs = []
        for obj in self.checkpoint_objects:
            obj_type = obj['type']
            if obj_type == 'host':
                ip = int(ipaddress.IPv4Address(obj['ipv4-address']))
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': obj['type'],
                           'interfaces': obj['interfaces'], 'ip_min': ip, 'ip_max': ip}
            elif obj_type == 'CpmiAnyObject':
                ip_min = int(ipaddress.IPv4Network('0.0.0.0/0')[0])
                ip_max = int(ipaddress.IPv4Network('0.0.0.0/0')[-1])
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': obj['type'],
                           'ip_min': ip_min, 'ip_max': ip_max}
            elif obj_type == 'group':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': obj['type'],
                           'members': obj['members']}
            elif obj_type == 'wildcard':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': obj['type'],
                           'wildcard_ip': obj['ipv4-address'], 'wildcard_mask': obj['ipv4-mask-wildcard']}
            elif obj_type == 'network':
                net = ipaddress.IPv4Network('{}/{}'.format(obj['subnet4'], obj['mask-length4']))
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': obj['type'],
                           'ip_min': int(net[0]), 'ip_max': int(net[-1])}
            elif obj_type == 'address-range':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': obj['type'],
                           'ip_min': int(ipaddress.IPv4Address(obj['ipv4-address-first'])),
                           'ip_max': int(ipaddress.IPv4Address(obj['ipv4-address-last']))}
            elif obj_type in self.known_obj_types:
                continue
            else:
                print (obj_type)
                raise NotImplementedError()
            parsed_objs.append(new_obj)
        return parsed_objs
    def _get_src_dst_obj_by_id(self, id):
        src_obj = self._get_obj_by_uid(id)
        if src_obj['type'] == 'dns-domain':
            # TODO: understand what this means
            return {'type': 'NOT-IMPLEMENTED', 'name': ''}
        elif src_obj['type'] == 'security-zone':
            # TODO: understand what this means
            return {'type': 'NOT-IMPLEMENTED', 'name': ''}
        elif src_obj['type'] in ['host', 'CpmiAnyObject']:
            return {'type': 'ADDRESS', 'name': src_obj['name']}
        elif src_obj['type'] == 'group':
            return {'type': 'GROUP', 'name': src_obj['name']}

    def _parse_addresses(self):
        address_list = []
        address_elem = {'name': '', 'id': '', 'value': {'type': '', 'fqdn': '', 'max_ip': 0, 'min_ip': 0}}
        for item in self.checkpoint_objects:
            if item['type'] == 'CpmiAnyObject':
                address_elem['name'] = item['name']
                address_elem['id'] = item['uid']
                address_elem['value']['type'] = 'IP_RANGE'
                ip4net = ipaddress.IPv4Network('0.0.0.0/0')
                address_elem['value']['min_ip'] = int(ip4net[0])
                address_elem['value']['max_ip'] = int(ip4net[-1])
                address_elem['domain'] = item['domain']['name']
                address_list.append(address_elem)
            elif item['type'] == 'host':
                address_elem['name'] = item['name']
                address_elem['id'] = item['uid']
                address_elem['value']['type'] = 'IP_RANGE'
                ip4addr = ipaddress.IPv4Address(item['ipv4-address'])
                address_elem['value']['min_ip'] = int(ip4addr)
                address_elem['value']['max_ip'] = int(ip4addr)
                address_elem['domain'] = item['domain']['name']
                address_list.append(address_elem)
            elif item['type'] == 'network':
                address_elem['name'] = item['name']
                address_elem['id'] = item['uid']
                address_elem['value']['type'] = 'IP_RANGE'
                network, mask = item['subnet4'], item['mask-length4']
                ip4net = ipaddress.IPv4Network('{}/{}'.format(network, mask))
                address_elem['value']['min_ip'] = int(ip4net[0])
                address_elem['value']['max_ip'] = int(ip4net[-1])
                address_elem['domain'] = item['domain']['name']
                address_list.append(address_elem)
            elif item['type'] == 'address-range':
                address_elem['name'] = item['name']
                address_elem['id'] = item['uid']
                address_elem['value']['type'] = 'IP_RANGE'
                address_elem['value']['min_ip'] = int(ipaddress.IPv4Address(item['ipv4-address-first']))
                address_elem['value']['max_ip'] = int(ipaddress.IPv4Address(item['ipv4-address-last']))
                address_elem['domain'] = item['domain']['name']
                address_list.append(address_elem)
            elif item['type'] == 'wildcard':
                address_elem['name'] = item['name']
                address_elem['id'] = item['uid']
                address_elem['value']['type'] = 'WILDCARD'
                address_elem['value']['wildcard-address'] = item['ipv4-address']
                address_elem['value']['wildcard-mask'] = item['ipv4-mask-wildcard']
                address_elem['domain'] = item['domain']['name']
                address_list.append(address_elem)
        return address_list

    def _parse_groups(self):
        address_list = []
        address_elem = {'name': '', 'id': '', 'value': {'type': '', 'name': ''}}
        for item in self.checkpoint_objects:
            if item['type'] == 'group':
                for member_id in item['members']:
                    member = self._get_obj_by_uid(member_id)
                    if member['type'] == 'group':
                        address_elem['value']['type'] = 'GROUP'
                    else:
                        address_elem['value']['type'] = 'ADDRESS'
                    address_elem['value']['name'] = member['name']
                address_list.append(address_elem)
        return address_list

    def _get_obj_by_uid(self, uid):
        item = list(filter(lambda obj: obj['uid'] == uid, self.checkpoint_objects))[0]
        return item

    def _get_addr_details(self, values):
        addr_type, fqdn, min_ip, max_ip = '', '', '', ''
        type = values.get('type')
        if type == 'fqdn':
            return ('FQDN', values.get('fqdn', ''), 0, 0)
        if type == 'iprange':
            ip_min = int(ipaddress.IPv4Address(values.get('start-ip')))
            ip_max = int(ipaddress.IPv4Address(values.get('end-ip')))
            return ('IP_RANGE', '', ip_min, ip_max)
        if type == 'dynamic':
            return ('NOT IMPLEMENTED', '', 0, 0)  # TODO: understand what is Address-Type of Dynamic and treat accordingly
        # if type is Null then it is type of subnet
        else:
            network, mask = values.get('subnet', '0.0.0.0 0.0.0.0').split(' ')
            ip_addresses_range = ipaddress.IPv4Network('{}/{}'.format(network,mask))
            return ('IP_RANGE', '', int(ip_addresses_range[0]), int(ip_addresses_range[-1]))