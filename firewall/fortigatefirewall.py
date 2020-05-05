import urllib.request
import ssl
import requests
import re
from .firewall import Firewall, AddressType
import ipaddress


class FortigateFirewall(Firewall):
    def __init__(self, ip, user, pwd):
        super().__init__(ip, user, pwd)

    def fetch(self):
        ses = requests.Session()
        fetch_url = 'https://{}/api/v2/monitor/system/config/backup?destination=file&scope=global'.format(self.ip)
        login_url = 'https://{}/logincheck'.format(self.ip)
        # Login
        ses.post(url=login_url, data={'ajax': '1', 'username': self.user, 'secretkey': self.pwd}, verify=False)
        # Download file locally
        self.backup_config = ses.get(fetch_url, verify=False).text

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
        address_elem = {'name':'', 'id':'', 'value':{'type':'', 'fqdn':'', 'max_ip':0, 'min_ip':0}}

        order_keys = []

        for line in self.backup_config:
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
                    # convert to format
                    if address_elem.get('type') == 'fqdn':
                        address_elem = {'name':address_elem['name'], 'id':address_elem['uuid'],
                                        'value':{'type':'FQDN', 'fqdn':address_elem['fqdn']}}
                    elif address_elem.get('type') == 'iprange':
                        min_ip = int(ipaddress.IPv4Address(address_elem.get('start-ip', '0.0.0.0')))
                        max_ip = int(ipaddress.IPv4Address(address_elem.get('end-ip', '0.0.0.0')))
                        address_elem = {'name': address_elem['name'], 'id': address_elem['uuid'],
                                        'value': {'type': 'IP_RANGE', 'min_ip': min_ip, 'max_ip': max_ip}}
                    elif address_elem.get('type') == 'dynamic':
                        # TODO: understand what this address type mean in fortigate and edit code accordingly
                        address_elem = {'name': 'NOT-IMPLEMENTED', 'id': '', 'value': {'type': 'NOT-IMPLEMENTED'}}
                    else:
                        # means its subnet type
                        network, mask = address_elem.get('subnet', '0.0.0.0 0.0.0.0').split(' ')
                        address_range = ipaddress.IPv4Network('{}/{}'.format(network, mask))
                        address_elem = {'name': address_elem['name'], 'id': address_elem['uuid'],
                                        'value': {'type': 'IP_RANGE', 'min_ip': int(address_range[0]),
                                                  'max_ip': int(address_range[-1])}}
                    address_list.append(address_elem)
                    address_elem = {}

            # We are exiting the address block
            if p_exiting_address_block.search(line):
                in_address_block = False

        return address_list

    def _parse_policy(self):
        # -- Entering policy definition block
        p_entering_policy_block = re.compile('^\s*config firewall policy$', re.IGNORECASE)
        # -- Exiting policy definition block
        p_exiting_policy_block = re.compile('^end$', re.IGNORECASE)
        # -- Commiting the current policy definition and going to the next one
        p_policy_next = re.compile('^next$', re.IGNORECASE)
        # -- Policy number
        p_policy_number = re.compile('^\s*edit\s+(?P<policy_number>\d+)', re.IGNORECASE)
        # -- Policy setting
        p_policy_set = re.compile('^\s*set\s+(?P<policy_key>\S+)\s+(?P<policy_value>.*)$', re.IGNORECASE)

        in_policy_block = False

        policy_list = []
        policy_elem = {'name':'', 'id':'', 'srcintf':[], 'dstintf':[], 'srcaddr':[], 'dstaddr':[], 'service':[],
                       'priority':-1, 'action': 0, 'enabled': 1}

        order_keys = []
        priority = 1
        for line in self.backup_config.splitlines():
            line = line.lstrip().rstrip().strip()

            # We match a policy block
            if p_entering_policy_block.search(line):
                in_policy_block = True

            # We are in a policy block
            if in_policy_block:
                if p_policy_number.search(line):
                    policy_number = p_policy_number.search(line).group('policy_number')
                    #policy_elem['id'] = policy_number
                    policy_elem['priority'] = priority
                    priority += 1
                    if not ('id' in order_keys): order_keys.append('id')

                # We match a setting
                if p_policy_set.search(line):
                    policy_key = p_policy_set.search(line).group('policy_key')
                    if not (policy_key in order_keys): order_keys.append(policy_key)

                    policy_value = p_policy_set.search(line).group('policy_value').strip()
                    policy_value = re.sub('["]', '', policy_value)

                    if policy_key == 'uuid':
                        policy_key = 'id'
                    if policy_key == 'action':
                        policy_value = int(policy_value == 'accept')
                    if policy_key in ['srcaddr', 'dstaddr']:
                        if policy_value in self._get_all_group_names():
                            policy_value = {'type': 'GROUP', 'name': policy_value}
                        else:
                            policy_value = {'type': 'ADDRESS', 'name': policy_value}

                    if policy_key in ['srcintf', 'dstintf', 'service', 'srcaddr', 'dstaddr']:
                        policy_elem[policy_key].append(policy_value)
                    else:
                        policy_elem[policy_key] = policy_value

                # We are done with the current policy id
                if p_policy_next.search(line):
                    policy_list.append(policy_elem)
                    policy_elem = {'name':'', 'id':'', 'srcintf':[], 'dstintf':[], 'srcaddr':[], 'dstaddr':[], 'service':[],
                   'priority':-1, 'action': 0, 'enabled': 1}

            # We are exiting the policy block
            if p_exiting_policy_block.search(line):
                in_policy_block = False

        return policy_list

    def _get_all_group_names(self):
        groups_data = re.search("config firewall addrgrp[\s\S]+?end", self.backup_config)
        groups = re.findall("edit\s\"(.*?)\"", groups_data.group(0))
        return groups

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

        groups_names = []

        for line in self.backup_config:
            line = line.lstrip().rstrip().strip()

            # We match a group block
            if p_entering_group_block.search(line):
                in_group_block = True

            # We are in a group block
            if in_group_block:
                if p_group_name.search(line):
                    group_name = p_group_name.search(line).group('group_name')
                    group_elem['name'] = group_name
                    groups_names.append(group_name)
                    if not ('name' in order_keys): order_keys.append('name')

                # We match a setting
                if p_group_set.search(line):
                    group_key = p_group_set.search(line).group('group_key')
                    if not (group_key in order_keys): order_keys.append(group_key)

                    group_value = p_group_set.search(line).group('group_value').strip()
                    group_value = re.sub('["]', '', group_value)

                    if group_key == 'uuid':
                        group_key = 'id'
                    if group_key == 'member':
                        group_key = 'value'
                        group_value = [{'type':'empty_now', 'name':name} for name in group_value.split(' ')]
                    group_elem[group_key] = group_value

                # We are done with the current group id
                if p_group_next.search(line):
                    group_list.append(group_elem)
                    group_elem = {}

            # We are exiting the group block
            if p_exiting_group_block.search(line):
                in_group_block = False
        # calculate type of each element
        for i in range(len(group_list)):
            for j in range(len(group_list[i]['value'])):
                if group_list[i]['value'][j]['name'] in groups_names:
                    group_list[i]['value'][j]['type'] = 'GROUP'
                else:
                    group_list[i]['value'][j]['type'] = 'ADDRESS'
        return group_list
