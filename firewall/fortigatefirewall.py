import urllib.request
import shlex
import requests
import re
from .firewall import Firewall, AddressType
import ipaddress


class FortigateFirewall(Firewall):

    def fetch(self):
        ses = requests.Session()
        fetch_url = 'https://{}/api/v2/monitor/system/config/backup?destination=file&scope=global'.format(self.ip)
        login_url = 'https://{}/logincheck'.format(self.ip)
        # Login
        ses.post(url=login_url, data={'ajax': '1', 'username': self.user, 'secretkey': self.pwd}, verify=False)
        # Download file locally
        self.backup_config = ses.get(fetch_url, verify=False).text

    def _parse_network_objects(self):
        p_entering_address_block = re.compile('^\s*config firewall address$', re.IGNORECASE)
        p_exiting_address_block = re.compile('^end$', re.IGNORECASE)
        p_address_next = re.compile('^next$', re.IGNORECASE)
        p_address_name = re.compile('^\s*edit\s+"(?P<address_name>.*)"$', re.IGNORECASE)
        p_address_set = re.compile('^\s*set\s+(?P<address_key>\S+)\s+(?P<address_value>.*)$', re.IGNORECASE)
        in_address_block = False

        address_list = []
        address_elem = {'extra_info': {}}

        for line in self.backup_config.splitlines():
            line = line.lstrip().rstrip().strip()

            # We match a address block
            if p_entering_address_block.search(line):
                in_address_block = True

            # We are in a address block
            if in_address_block:
                if p_address_name.search(line):
                    address_name = p_address_name.search(line).group('address_name')
                    address_elem['name'] = address_name

                # We match a setting
                if p_address_set.search(line):
                    address_key = p_address_set.search(line).group('address_key')

                    address_value = p_address_set.search(line).group('address_value').strip()
                    address_value = re.sub('["]', '', address_value)

                    if address_key not in ['uuid', 'type', 'fqdn', 'start-ip', 'end-ip', 'subnet']:
                        address_elem['extra_info'][address_key] = address_value
                    else:
                        address_elem[address_key] = address_value

                # We are done with the current address id
                if p_address_next.search(line):
                    # convert to format
                    if address_elem.get('type') == 'fqdn':
                        address_elem = {'name':address_elem['name'], 'id':address_elem['uuid'],
                                        'type':'FQDN', 'fqdn':address_elem['fqdn']}
                    elif address_elem.get('type') == 'iprange':
                        min_ip = int(ipaddress.IPv4Address(address_elem.get('start-ip', '0.0.0.0')))
                        max_ip = int(ipaddress.IPv4Address(address_elem.get('end-ip', '0.0.0.0')))
                        address_elem = {'name': address_elem['name'], 'id': address_elem['uuid'],
                                        'type': 'IP_RANGE', 'min_ip': min_ip, 'max_ip': max_ip}
                    elif address_elem.get('type') == 'dynamic':
                        # TODO: understand what this address type mean in fortigate and edit code accordingly
                        address_elem = {'name': 'NOT-IMPLEMENTED', 'id': '', 'value': {'type': 'NOT-IMPLEMENTED'}}
                    else:
                        # means its subnet type
                        network, mask = address_elem.get('subnet', '0.0.0.0 0.0.0.0').split(' ')
                        address_range = ipaddress.IPv4Network('{}/{}'.format(network, mask), False)
                        address_elem = {'name': address_elem['name'], 'id': address_elem['uuid'],
                                        'type': 'IP_RANGE', 'min_ip': int(address_range[0]),
                                                  'max_ip': int(address_range[-1])}
                    address_list.append(address_elem)
                    address_elem = {'extra_info': {}}

            # We are exiting the address block
            if p_exiting_address_block.search(line):
                in_address_block = False

        address_list.extend(self._parse_groups())
        return address_list

    def _parse_policy(self):
        p_entering_policy_block = re.compile('^\s*config firewall policy$', re.IGNORECASE)
        p_exiting_policy_block = re.compile('^end$', re.IGNORECASE)
        p_policy_next = re.compile('^next$', re.IGNORECASE)
        p_policy_number = re.compile('^\s*edit\s+(?P<policy_number>\d+)', re.IGNORECASE)
        p_policy_set = re.compile('^\s*set\s+(?P<policy_key>\S+)\s+(?P<policy_value>.*)$', re.IGNORECASE)

        in_policy_block = False

        policy_list = []
        policy_elem = {'extra_info': {}}
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
                    policy_elem['priority'] = priority
                    policy_elem['enabled'] = 1
                    priority += 1

                # We match a setting
                if p_policy_set.search(line):
                    policy_key = p_policy_set.search(line).group('policy_key')

                    policy_value = p_policy_set.search(line).group('policy_value').strip()
                    #policy_value = re.sub('["]', '', policy_value)

                    if policy_key == 'uuid':
                        policy_elem['id'] = policy_value.strip("\"")
                    elif policy_key == 'action':
                        policy_elem['action'] = int(policy_value.strip("\"") == 'accept')
                    elif policy_key in ['srcaddr', 'dstaddr']:
                        addresses = []
                        for addr_name in shlex.split(policy_value):
                            addresses.append(self._get_obj_id_by_name(addr_name))
                        policy_elem[policy_key] = addresses
                    elif policy_key in ['service']:
                        # in fortigate service has no id, so it's name is the id
                        services = []
                        for svc in shlex.split(policy_value):
                            services.append(svc)
                        policy_elem["service"] = services
                    elif policy_key not in ['id', 'name']:
                        policy_elem['extra_info'][policy_key] = policy_value.strip("\"")
                    else:
                        policy_elem[policy_key] = policy_value.strip("\"")

                # We are done with the current policy id
                if p_policy_next.search(line):
                    policy_elem['source'] = policy_elem.pop('srcaddr')
                    policy_elem['destination'] = policy_elem.pop('dstaddr')
                    policy_list.append(policy_elem)
                    policy_elem = {'extra_info': {}}

            # We are exiting the policy block
            if p_exiting_policy_block.search(line):
                in_policy_block = False

        return policy_list

    def _get_all_group_names(self):
        groups_data = re.search("config firewall addrgrp[\s\S]+?end", self.backup_config)
        groups = re.findall("edit\s\"(.*?)\"", groups_data.group(0))
        return groups

    def _parse_groups(self):
        p_entering_group_block = re.compile('^\s*config firewall addrgrp$', re.IGNORECASE)
        p_exiting_group_block = re.compile('^end$', re.IGNORECASE)
        p_group_next = re.compile('^next$', re.IGNORECASE)
        p_group_name = re.compile('^\s*edit\s+"(?P<group_name>.*)"$', re.IGNORECASE)
        p_group_set = re.compile('^\s*set\s+(?P<group_key>\S+)\s+(?P<group_value>.*)$', re.IGNORECASE)

        in_group_block = False

        group_list = []
        group_elem = {'extra_info': {}}

        groups_names = []

        for line in self.backup_config.splitlines():
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

                # We match a setting
                if p_group_set.search(line):
                    group_key = p_group_set.search(line).group('group_key')

                    group_value = p_group_set.search(line).group('group_value').strip()
                    #group_value = re.sub('["]', '', group_value)

                    if group_key == 'uuid':
                        group_elem['id'] = group_value.strip("\"")
                    elif group_key == 'member':
                        group_key = 'members'
                        members = []
                        for member in shlex.split(group_value):
                            members.append(self._get_obj_id_by_name(member))
                        group_elem['members'] = members
                    else:
                        group_elem[group_key] = group_value.strip("\"")

                # We are done with the current group id
                if p_group_next.search(line):
                    group_elem['type'] = 'GROUP'
                    group_list.append(group_elem)
                    group_elem = {'extra_info': {}}

            # We are exiting the group block
            if p_exiting_group_block.search(line):
                in_group_block = False
        return group_list

    def _parse_services(self):
        p_entering_block = re.compile('^\s*config firewall service custom$', re.IGNORECASE)
        p_exiting_block = re.compile('^end$', re.IGNORECASE)
        p_service_name = re.compile('^\s*edit\s+"(?P<service_name>.*)"$', re.IGNORECASE)
        p_value_set = re.compile('^\s*set\s+(?P<key>\S+)\s+(?P<value>.*)$', re.IGNORECASE)
        p_next = re.compile('^next$', re.IGNORECASE)
        services_section = re.search("config firewall service custom[\s\S]+?end", self.backup_config).group(0)
        service_elem = {'extra_info': {}}
        service_list = []
        in_block = False
        for line in services_section.splitlines():
            line = line.lstrip().rstrip().strip()

            if p_entering_block.search(line):
                in_block = True
            if in_block:
                if p_service_name.search(line):
                    service_name = p_service_name.search(line).group('service_name')
                    service_elem['name'] = service_name
                    service_elem['id'] = service_name
                if p_value_set.search(line):
                    key = p_value_set.search(line).group('key')
                    value = p_value_set.search(line).group('value').strip()
                    value = re.sub('["]', '', value)

                    if key in ['tcp-portrange', 'udp-portrange']:
                        port_range_list = value.split(' ')
                        ports = []
                        for port_range in value.split(' '):
                            parsed_port_range = {}
                            if ':' in port_range:
                                source_port_range = port_range.split(':')[1]
                                if '-' not in source_port_range:
                                    parsed_port_range['src-port-min'] = int(source_port_range)
                                    parsed_port_range['src-port-max'] = int(source_port_range)
                                else:
                                    min_port, max_port = source_port_range.split('-')
                                    parsed_port_range['src-port-min'] = int(min_port)
                                    parsed_port_range['src-port-max'] = int(max_port)
                                port_range = port_range.split(':')[0]
                            if '-' not in port_range:
                                parsed_port_range['dst-port-min'] = int(port_range)
                                parsed_port_range['dst-port-max'] = int(port_range)
                            else:
                                min_port, max_port = port_range.split('-')
                                parsed_port_range['dst-port-min'] = int(min_port)
                                parsed_port_range['dst-port-max'] = int(max_port)
                            ports.append(parsed_port_range)
                        value = ports
                        service_elem[key] = value
                    else:
                        service_elem['extra_info'][key] = value

                if p_next.search(line):
                    service_list.append(service_elem)
                    service_elem = {'extra_info': {}}
            if p_exiting_block.search(line):
                in_group_block = False

        return service_list

    def _parse_misc(self):
        p_entering_interface_block = re.compile('^\s*config system interface$', re.IGNORECASE)
        p_entering_schedule_block = re.compile('^\s*config firewall schedule recurring$', re.IGNORECASE)
        p_exiting_block = re.compile('^end$', re.IGNORECASE)
        p_next = re.compile('^next$', re.IGNORECASE)
        p_name = re.compile('^\s*edit\s+"(?P<name>.*)"$', re.IGNORECASE)
        p_set = re.compile('^\s*set\s+(?P<key>\S+)\s+(?P<value>.*)$', re.IGNORECASE)
        in_block = False

        misc_list = []
        misc_elem = {}
        obj_type = ''

        for line in self.backup_config.splitlines():
            line = line.lstrip().rstrip().strip()

            if p_entering_interface_block.search(line):
                in_block = True
                obj_type = 'interface'
            elif p_entering_schedule_block.search(line):
                in_block = True
                obj_type = 'schedule'

            if in_block:
                if p_name.search(line):
                    address_name = p_name.search(line).group('name')
                    misc_elem['name'] = address_name
                    misc_elem['obj_type'] = obj_type

                if p_set.search(line):
                    key = p_set.search(line).group('key')
                    value = p_set.search(line).group('value').strip()

                    misc_elem[key] = value.strip("\"")

                # We are done with the current address id
                if p_next.search(line):
                    misc_list.append(misc_elem)
                    misc_elem = {}

            # We are exiting the address block
            if p_exiting_block.search(line):
                in_block = False

        return misc_list

    def _get_service_groups(self):
        pass

    def _get_obj_id_by_name(self, name):
        matches = re.search("edit\s\"{}\"[\s\S]+?set\suuid\s(.*)".format(name), self.backup_config)
        return matches.group(1)