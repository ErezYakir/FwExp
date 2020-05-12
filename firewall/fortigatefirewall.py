import shlex
import requests
import re
from .firewall import Firewall
import ipaddress
from globals import PROJECT_DIR


class FortigateFirewall(Firewall):

    def __init__(self, ip, user, pwd, db_path, db_name="Firewall_info"):
        super().__init__(ip, user, pwd, db_path, db_name=db_name)
        self.config_path = PROJECT_DIR + "/checkpoint_config_files/"
        self.backup_config = ''
        self.p_exiting_block = re.compile('^end$', re.IGNORECASE)
        self.p_next = re.compile('^next$', re.IGNORECASE)
        self.p_name = re.compile('^\s*edit\s+"(?P<name>.*)"$', re.IGNORECASE)
        self.p_set = re.compile('^\s*set\s+(?P<key>\S+)\s+(?P<value>.*)$', re.IGNORECASE)
        self.p_policy_number = re.compile('^\s*edit\s+(?P<policy_number>\d+)', re.IGNORECASE)

    def fetch(self, fetch_remotely=True):
        if fetch_remotely:
            ses = requests.Session()
            fetch_url = 'https://{}/api/v2/monitor/system/config/backup?destination=file&scope=global'.format(self.ip)
            login_url = 'https://{}/logincheck'.format(self.ip)
            # Login
            ses.post(url=login_url, data={'ajax': '1', 'username': self.user, 'secretkey': self.pwd}, verify=False)
            # Download file locally
            config_text = ses.get(fetch_url, verify=False).text
            with open(self.config_path + 'config.cache', 'w') as f:
                f.write(config_text)
            self.backup_config = config_text
        else:
            with open(self.config_path + 'config.cache', 'r') as f:
                self.backup_config = f.read()

        self.addresses_content = re.search('config\sfirewall\saddress([\s\S]+?)\nend',
                                           self.backup_config, re.IGNORECASE).group(1)
        self.policy_content = re.search('config\sfirewall\spolicy([\s\S]+?)\nend',
                                           self.backup_config, re.IGNORECASE).group(1)
        self.groups_content = re.search('config\sfirewall\saddrgrp([\s\S]+?)\nend',
                                           self.backup_config, re.IGNORECASE).group(1)
        self.services_content = re.search('config\sfirewall\sservice\scustom([\s\S]+?)\nend',
                                           self.backup_config, re.IGNORECASE).group(1)
        self.interface_content = re.search('config\ssystem\sinterfaces([\s\S]+?)\nend',
                                          self.backup_config, re.IGNORECASE).group(1)
        self.schedule_content = re.search('config\sfirewall\sschedule\srecurring([\s\S]+?)\nend',
                                           self.backup_config, re.IGNORECASE).group(1)

    def _parse_network_objects(self):
        address_list = []
        address_elem = {'extra_info': {}}

        for line in self.addresses_content.splitlines():
            line = line.lstrip().rstrip().strip()
            if self.p_name.search(line):
                address_name = self.p_name.search(line).group('name')
                address_elem['name'] = address_name

            # We match a setting
            if self.p_set.search(line):
                address_key = self.p_set.search(line).group('key')

                address_value = self.p_set.search(line).group('value').strip()
                address_value = re.sub('["]', '', address_value)

                if address_key not in ['uuid', 'type', 'fqdn', 'start-ip', 'end-ip', 'subnet']:
                    address_elem['extra_info'][address_key] = address_value
                else:
                    address_elem[address_key] = address_value

            # We are done with the current address id
            if self.p_next.search(line):
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

        address_list.extend(self._parse_groups())
        return address_list

    def _parse_policy(self):
        policy_list = []
        policy_elem = {'extra_info': {}}
        priority = 1
        for line in self.policy_content.splitlines():
            line = line.lstrip().rstrip().strip()
            if self.p_policy_number.search(line):
                policy_number = self.p_policy_number.search(line).group('policy_number')
                policy_elem['priority'] = priority
                policy_elem['enabled'] = 1
                priority += 1
            if self.p_set.search(line):
                policy_key = self.p_set.search(line).group('key')
                policy_value = self.p_set.search(line).group('value').strip()

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
            if self.p_next.search(line):
                policy_elem['source'] = policy_elem.pop('srcaddr')
                policy_elem['destination'] = policy_elem.pop('dstaddr')
                policy_list.append(policy_elem)
                policy_elem = {'extra_info': {}}

        return policy_list

    def _get_all_group_names(self):
        groups_data = re.search("config firewall addrgrp[\s\S]+?end", self.backup_config)
        groups = re.findall("edit\s\"(.*?)\"", groups_data.group(0))
        return groups

    def _parse_groups(self):
        group_list = []
        group_elem = {'extra_info': {}}
        groups_names = []

        for line in self.groups_content.splitlines():
            line = line.lstrip().rstrip().strip()
            if self.p_name.search(line):
                group_name = self.p_name.search(line).group('name')
                group_elem['name'] = group_name
                groups_names.append(group_name)

            # We match a setting
            if self.p_set.search(line):
                group_key = self.p_set.search(line).group('key')
                group_value = self.p_set.search(line).group('value').strip()

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
            if self.p_next.search(line):
                group_elem['type'] = 'GROUP'
                group_list.append(group_elem)
                group_elem = {'extra_info': {}}

        return group_list

    def _parse_services(self):
        service_elem = {'extra_info': {}}
        service_list = []
        for line in self.services_content.splitlines():
            line = line.lstrip().rstrip().strip()
            if self.p_name.search(line):
                service_name = self.p_name.search(line).group('name')
                service_elem['name'] = service_name
                service_elem['id'] = service_name
            if self.p_set.search(line):
                key = self.p_set.search(line).group('key')
                value = self.p_set.search(line).group('value').strip()
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

            if self.p_next.search(line):
                service_list.append(service_elem)
                service_elem = {'extra_info': {}}

        return service_list

    def _parse_misc(self):
        misc_list = []
        misc_elem = {}
        obj_type = ''

        for misc_content in [self.schedule_content, self.interface_content]:
            for line in misc_content.splitlines():
                line = line.lstrip().rstrip().strip()
                if self.p_name.search(line):
                    address_name = self.p_name.search(line).group('name')
                    misc_elem['name'] = address_name
                    misc_elem['obj_type'] = obj_type

                if self.p_set.search(line):
                    key = self.p_set.search(line).group('key')
                    value = self.p_set.search(line).group('value').strip()

                    misc_elem[key] = value.strip("\"")

                # We are done with the current address id
                if self.p_next.search(line):
                    misc_list.append(misc_elem)
                    misc_elem = {}

        return misc_list

    def _get_service_groups(self):
        pass

    def _get_obj_id_by_name(self, name):
        matches = re.search("edit\s\"{}\"[\s\S]+?set\suuid\s(.*)".format(name), self.backup_config)
        return matches.group(1)