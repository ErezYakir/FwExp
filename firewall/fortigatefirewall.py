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
        with open("bkp.tmp", 'w') as f:
            f.write(ses.get(fetch_url, verify=False).text)

    def parseToDb(self):
        super().parseToDb()
        results, keys = self._parse_policy()
        for res in results:
            self.cursor.execute(
                "INSERT INTO policy VALUES ('{}','{}','{}','{}', {})".format(res['name'], res['srcaddr'],
                                                                             res['dstaddr'], res['service'],
                                                                             int(res.get('action',
                                                                                         'deny') == 'accept')))
        results, keys = self._parse_addresses()
        for res in results:
            addr_type, fqdn, min_ip, max_ip = self._get_addr_details(res)
            # intert to table: name, type, fqdn, ip_min, ip_max, interface
            self.cursor.execute(
                "INSERT INTO addresses VALUES ('{}', '{}', '{}', {}, {}, '{}')".format(res['name'], addr_type,
                                                                                       fqdn, min_ip, max_ip,
                                                                                       res.get('associated-interface','')))

        results, keys = self._parse_groups()
        for res in results:
            self.cursor.execute(
                "INSERT INTO addressGroups VALUES ('{}', '{}')".format(res['name'], res['member'])
            )

        self.conn.commit()

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
        policy_elem = {}

        order_keys = []

        with open("bkp.tmp", 'r') as fd_input:
            for line in fd_input:
                line = line.lstrip().rstrip().strip()

                # We match a policy block
                if p_entering_policy_block.search(line):
                    in_policy_block = True

                # We are in a policy block
                if in_policy_block:
                    if p_policy_number.search(line):
                        policy_number = p_policy_number.search(line).group('policy_number')
                        policy_elem['id'] = policy_number
                        if not ('id' in order_keys): order_keys.append('id')

                    # We match a setting
                    if p_policy_set.search(line):
                        policy_key = p_policy_set.search(line).group('policy_key')
                        if not (policy_key in order_keys): order_keys.append(policy_key)

                        policy_value = p_policy_set.search(line).group('policy_value').strip()
                        policy_value = re.sub('["]', '', policy_value)

                        policy_elem[policy_key] = policy_value

                    # We are done with the current policy id
                    if p_policy_next.search(line):
                        policy_list.append(policy_elem)
                        policy_elem = {}

                # We are exiting the policy block
                if p_exiting_policy_block.search(line):
                    in_policy_block = False

        return (policy_list, order_keys)

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