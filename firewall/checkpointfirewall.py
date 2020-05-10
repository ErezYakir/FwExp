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
                                'CpmiSrCommunity', 'service-group', 'CpmiVoipGwDomain', 'CpmiVoipSkinnyDomain',
                                'CpmiVoipSipDomain', 'dynamic-object', 'group-with-exclusion', 'multicast-address-range']

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
            #rule.pop('comments', None)
            rule.pop('meta-info', None)
            rule.pop('time', None)
            rule.pop('install-on', None)
            rule.pop('track', None)
            rule.pop('action-settings', None)
            rule.pop('custom-fields', None)
            policy_list.append(rule)
        return policy_list

    def _parse_services(self):
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
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'],
                           'udp-port': obj['port'], 'protocol': obj.get('protocol'),
                           'match-signature': obj['match-by-protocol-signature'], 'match-for-any': obj['match-for-any']}
            elif obj_type == 'service-dce-rpc':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'dce-rpc',
                           'interface-uuid': obj['interface-uuid']}
            elif obj_type == 'service-rpc':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'dce-rpc',
                           'program-number': obj['program-number']}
            elif obj_type == 'service-tcp':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'],
                           'tcp-port': obj['port'], 'protocol': obj.get('protocol'),
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

    def _parse_addresses(self):
        #### List of possible object types:
        # host, vpn-community-meshed
        #### List of object possible parsed properties:
        # ip_min, ip_max
        parsed_objs = []
        for obj in self.checkpoint_objects:
            obj_type = obj['type']
            if obj_type == 'host':
                members = []
                for interface in obj.get('interfaces', []):
                    net = ipaddress.IPv4Network('{}/{}'.format(interface['subnet4'], interface['mask-length4']))
                    parsed_objs.append({'name': interface['name'], 'id': obj['uid'], 'domain': obj['domain'],
                                        'type': 'IP_RANGE', 'min_ip': int(net[0]), 'max_ip': int(net[-1])})
                    members.append(obj['uid'])
                ip = int(ipaddress.IPv4Address(obj['ipv4-address']))
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'IP_RANGE',
                           'members': members, 'min_ip': ip, 'max_ip': ip}
            elif obj_type == 'CpmiAnyObject':
                ip_min = int(ipaddress.IPv4Network('0.0.0.0/0')[0])
                ip_max = int(ipaddress.IPv4Network('0.0.0.0/0')[-1])
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'IP_RANGE',
                           'min_ip': ip_min, 'max_ip': ip_max}
            elif obj_type == 'group':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'IP_RANGE',
                           'members': obj['members']}
            elif obj_type == 'wildcard':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'IP_RANGE',
                           'wildcard_ip': obj['ipv4-address'], 'wildcard_mask': obj['ipv4-mask-wildcard']}
            elif obj_type == 'network':
                net = ipaddress.IPv4Network('{}/{}'.format(obj['subnet4'], obj['mask-length4']))
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'IP_RANGE',
                           'min_ip': int(net[0]), 'max_ip': int(net[-1])}
            elif obj_type == 'address-range':
                new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'IP_RANGE',
                           'min_ip': int(ipaddress.IPv4Address(obj['ipv4-address-first'])),
                           'max_ip': int(ipaddress.IPv4Address(obj['ipv4-address-last']))}
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