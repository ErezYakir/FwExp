import requests
import re
from .firewall import Firewall
import ipaddress
import json


class CheckpointFirewall(Firewall):
    def __init__(self, ip, user, pwd):
        super().__init__(ip, user, pwd)

    def fetch(self):
        # TODO: fetch from http / ssh
        with open('checkpoint_config_files/Standard_objects.json', 'r') as f:
            self.checkpoint_objects = json.loads(f.read())
        with open('checkpoint_config_files/Network-Management server.json', 'r') as f:
            self.checkpoint_rules = json.loads(f.read())

    def _parse_policy(self):
        policy_list = []
        policy_elem = {'name': '', 'id': '', 'srcintf': [], 'dstintf': [], 'srcaddr': [], 'dstaddr': [], 'service': [],
                       'priority': -1, 'action': 0, 'enabled': 1}

        for item in self.checkpoint_rules:
            policy_elem['name'] = item['name']
            policy_elem['id'] = item['uid']
            for src_uid in item['source']:
                policy_elem['srcaddr'].append(self._get_src_dst_obj_by_id(src_uid))
            for dst_uid in item['destination']:
                policy_elem['dstaddr'].append(self._get_src_dst_obj_by_id(src_uid))
            for srv_uid in item['service']:
                policy_elem['service'].append(self._get_obj_by_uid(srv_uid)['name'])
            policy_elem['priority'] = item['rule-number']
            policy_elem['action'] = self._get_obj_by_uid(item['action'])['name'] == "Accept"
            policy_elem['enabled'] = item['enabled']
            policy_list.append(policy_elem)
            policy_elem = {'name': '', 'id': '', 'srcintf': [], 'dstintf': [], 'srcaddr': [], 'dstaddr': [],
                           'service': [], 'priority': -1, 'action': 0, 'enabled': 1}

        return policy_list

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