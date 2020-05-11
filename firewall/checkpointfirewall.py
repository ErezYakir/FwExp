import requests
import uuid
from .firewall import Firewall
import ipaddress
import json


class CheckpointFirewall(Firewall):
    def __init__(self, ip, user, pwd, db_path, db_name="Firewall_info"):
        super().__init__(ip, user, pwd, db_path, db_name)
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
        policy_item = {'extra_info': {}}
        for rule in self.checkpoint_rules:
            for key in rule:
                if key == 'uid':
                    policy_item['id'] = rule[key]
                elif key == 'rule-number':
                    policy_item['priority'] = rule[key]
                elif key == 'action':
                    policy_item['action'] = (self._get_obj_by_uid(rule['action'])['name'] == 'Accept')
                elif key in ['source-negate', 'destination-negate', 'service-negate', 'destination', 'source', 'enabled', 'service', 'name']:
                    policy_item[key] = rule[key]
                else:
                    policy_item['extra_info'][key] = rule[key]
            policy_list.append(policy_item)
            policy_item = {'extra_info': {}}
        return policy_list

    def _parse_services(self):
        parsed_objs = []
        for obj in self.checkpoint_objects:
            if obj['type'] in ['service-udp0', 'service-dce-rpc', 'service-rpc', 'service-tcp', 'service-icmp', 'service-group']:
                new_svc = self._parse_single_service(obj)
                parsed_objs.append(new_svc)
            elif obj['type'] in self.known_obj_types:
                continue
            else:
                raise NotImplementedError()
        return parsed_objs

    def _parse_addresses(self):
        parsed_objs = []
        for obj in self.checkpoint_objects:
            if obj['type'] == 'host':
                # In checkpoint, host can contain subnets, so we'll consider it as a group
                new_network_objs = self._parse_host_as_group(obj)
                parsed_objs.extend(new_network_objs)
            elif obj['type'] in ['CpmiAnyObject', 'group', 'wildcard', 'network', 'address-range']:
                new_network_obj = self._parse_single_network_object(obj)
                parsed_objs.append(new_network_obj)
            elif obj['type'] in self.known_obj_types:
                continue
            else:
                print (obj['type'])
                raise NotImplementedError()
        return parsed_objs

    def _get_obj_by_uid(self, uid):
        item = list(filter(lambda obj: obj['uid'] == uid, self.checkpoint_objects))[0]
        return item

    def _parse_single_service(self, obj):
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
        """    
        obj_type = obj['type']
        if obj_type == 'service-udp':
            new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'],
                       'udp-port': obj['port'], 'protocol': obj.get('protocol'),
                       'match-signature': obj['match-by-protocol-signature'], 'match-for-any': obj['match-for-any']}
        elif obj_type == 'service-dce-rpc':
            new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'dce-rpc',
                       'interface-uuid': obj['interface-uuid']}
        elif obj_type == 'service-rpc':
            new_obj = {'name': obj['name'], 'id': obj['uid'], 'domain': obj['domain'], 'type': 'rpc',
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
                       'type': 'GROUP', 'members': obj['members']}
        """

    def _parse_single_network_object(self, obj):
        single_item = {'extra_info': {}}
        obj_type = obj['type']
        if obj_type == 'CpmiAnyObject':
            single_item['type'] = 'IP_RANGE'
            single_item['min_ip'] = int(ipaddress.IPv4Network('0.0.0.0/0', False)[0])
            single_item['max_ip'] = int(ipaddress.IPv4Network('0.0.0.0/0', False)[-1])
        elif obj_type == 'group':
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
            elif key in ['ipv4-address-first', 'ipv4-address-last', 'subnet4', 'mask-length4', 'ipv4-address', 'ipv4-mask-wildcard', 'type', 'subnet-mask']:
                pass
            else:
                single_item['extra_info'][key] = obj[key]

        return single_item

    def _parse_host_as_group(self, obj):
        parsed_objs = []
        members = []
        for interface in obj.get('interfaces', []):
            parsed_interface = self._parse_single_network_object(interface)
            members.append(parsed_interface['id'])
            parsed_objs.append(parsed_interface)
        # Creating a new object that is not in checkpoint so host can be a group
        ip = int(ipaddress.IPv4Address(obj['ipv4-address']))
        new_obj_uuid = str(uuid.uuid4())
        members.append(new_obj_uuid)
        new_obj = {'name': obj['name']+'_HOST_IP_OBJ', 'id': new_obj_uuid, 'type': 'IP_RANGE', 'min_ip': ip, 'max_ip': ip}
        parsed_objs.append(new_obj)

        # Now creating the group
        group_obj = {'type': 'GROUP', 'name': obj['name'], 'members': members, 'id': obj['uid'], 'extra_info': {}}
        for key in obj:
            if key not in ['type', 'name', 'interfaces', 'ipv4-address', 'uid']:
                group_obj['extra_info'][key] = obj[key]

        parsed_objs.append(group_obj)
        return parsed_objs

    def _parse_misc(self):
        objs = []
        for obj in self.checkpoint_objects:
            if obj['type'] in ['vpn-community-meshed', 'dns-domain', 'RulebaseAction',
                              'CpmiLogicalServer', 'security-zone', 'Track', 'threat-profile',
                              'ThreatExceptionRulebase', 'CpmiSrCommunity', 'CpmiVoipGwDomain', 'CpmiVoipSkinnyDomain',
                                'CpmiVoipSipDomain', 'dynamic-object', 'group-with-exclusion', 'multicast-address-range']:
                objs.append(obj)
        return objs
