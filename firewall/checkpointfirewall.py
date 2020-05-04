import requests
import re
from .firewall import Firewall
import ipaddress
import json


class CheckpointFirewall(Firewall):
    def __init__(self, ip, user, pwd):
        super().__init__(ip, user, pwd)
        with open('checkpoint_config_files/Standard_objects.json', 'r') as f:
            self.checkpoint_objects = json.loads(f.read())
        with open('checkpoint_config_files/Network-Management server.json', 'r') as f:
            self.checkpoint_rules = json.loads(f.read())

    def fetch(self):
        # TODO: fetch from http / ssh
        pass

    def parseToDb(self):
        super().parseToDb()
        results = self._parse_policy()
        # insert to table: id, name, uuid, srcintf, dstintf, srcaddr, dstaddr, services, priority, action, is_enabled
        for res in results:
            self.cursor.execute(
                "INSERT INTO policy VALUES ('{}','{}','{}','{}','{}','{}','{}',{},{},{})".format(
                    res['name'], res['uuid'], ','.join(res['srcintf']), ','.join(res['dstintf']),
                    ','.join(res['srcaddr']), ','.join(res['dstaddr']), ','.join(res['service']), res['priority'],
                    int(res['action']), int(res['enabled'])))

    def _parse_addresses(self):
        p_entering_address_block = re.compile('^\s*config firewall address$', re.IGNORECASE)
        # -- Exiting address definition block
        p_exiting_address_block = re.compile('^end$', re.IGNORECASE)

        # -- Commiting the current address definition and going to the next one
        p_address_next = re.compile('^next$', re.IGNORECASE)

        # -- Policy number
        p_address_name = re.compile('^\s*edit\s+"(?P<address_name>.*)"$', re.IGNORECASE)

        # -- Policy setting
        p_address_set = re.compile('^\s*set\s+(?P<address_key>\S+)\s+(?P<address_value>.*)$', re.IGNORECASE)
        in_address_block = False

        address_list = []
        address_elem = {}

        order_keys = []

        with open("bkp.tmp", 'r') as fd_input:
            for line in fd_input:
                line = line.lstrip().rstrip().strip()

                # We match a address block
                if p_entering_address_block.search(line):
                    in_address_block = True

                # We are in a address block
                if in_address_block:
                    if p_address_name.search(line):
                        address_name = p_address_name.search(line).group('address_name')
                        address_elem['name'] = address_name
                        if not ('name' in order_keys): order_keys.append('name')

                    # We match a setting
                    if p_address_set.search(line):
                        address_key = p_address_set.search(line).group('address_key')
                        if not (address_key in order_keys): order_keys.append(address_key)

                        address_value = p_address_set.search(line).group('address_value').strip()
                        address_value = re.sub('["]', '', address_value)

                        address_elem[address_key] = address_value

                    # We are done with the current address id
                    if p_address_next.search(line):
                        address_list.append(address_elem)
                        address_elem = {}

                # We are exiting the address block
                if p_exiting_address_block.search(line):
                    in_address_block = False

        return (address_list, order_keys)

    def _parse_policy(self):
        policy_list = []
        policy_elem = {}

        for item in self.checkpoint_rules:
            policy_elem['name'] = item['name']
            policy_elem['uuid'] = item['uid']
            policy_elem['srcintf'] = []
            policy_elem['dstintf'] = []
            policy_elem['srcaddr'] = []
            policy_elem['dstaddr'] = []
            policy_elem['service'] = []
            for src_uid in item['source']:
                policy_elem['srcintf'] += self._get_obj_by_uid(src_uid).get('interfaces', []) # TODO: probably interface is uuid and need to fetch its name
                policy_elem['srcaddr'].append(self._get_obj_by_uid(src_uid).get('name'))
            for dst_uid in item['destination']:
                policy_elem['dstintf'] += self._get_obj_by_uid(dst_uid).get('interfaces', [])
                policy_elem['dstaddr'].append(self._get_obj_by_uid(dst_uid)['name'])
            for srv_uid in item['service']:
                policy_elem['service'].append(self._get_obj_by_uid(srv_uid)['name'])
            policy_elem['priority'] = item['rule-number']
            policy_elem['action'] = self._get_obj_by_uid(item['action'])['name'] == "Accept"
            policy_elem['enabled'] = item['enabled']
            policy_list.append(policy_elem)
            policy_elem = {}

        return policy_list

    def _get_obj_by_uid(self, uid):
        item = list(filter(lambda obj: obj['uid'] == uid, self.checkpoint_objects))[0]
        return item

    def _parse_groups(self):
        # -- Entering group definition block
        p_entering_group_block = re.compile('^\s*config firewall addrgrp$', re.IGNORECASE)
        # -- Exiting group definition block
        p_exiting_group_block = re.compile('^end$', re.IGNORECASE)
        # -- Commiting the current group definition and going to the next one
        p_group_next = re.compile('^next$', re.IGNORECASE)
        # -- Policy number
        p_group_name = re.compile('^\s*edit\s+"(?P<group_name>.*)"$', re.IGNORECASE)
        # -- Policy setting
        p_group_set = re.compile('^\s*set\s+(?P<group_key>\S+)\s+(?P<group_value>.*)$', re.IGNORECASE)

        in_group_block = False

        group_list = []
        group_elem = {}

        order_keys = []

        with open("bkp.tmp", 'r') as fd_input:
            for line in fd_input:
                line = line.lstrip().rstrip().strip()

                # We match a group block
                if p_entering_group_block.search(line):
                    in_group_block = True

                # We are in a group block
                if in_group_block:
                    if p_group_name.search(line):
                        group_name = p_group_name.search(line).group('group_name')
                        group_elem['name'] = group_name
                        if not ('name' in order_keys): order_keys.append('name')

                    # We match a setting
                    if p_group_set.search(line):
                        group_key = p_group_set.search(line).group('group_key')
                        if not (group_key in order_keys): order_keys.append(group_key)

                        group_value = p_group_set.search(line).group('group_value').strip()
                        group_value = re.sub('["]', '', group_value)

                        group_elem[group_key] = group_value

                    # We are done with the current group id
                    if p_group_next.search(line):
                        group_list.append(group_elem)
                        group_elem = {}

                # We are exiting the group block
                if p_exiting_group_block.search(line):
                    in_group_block = False

        return (group_list, order_keys)

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