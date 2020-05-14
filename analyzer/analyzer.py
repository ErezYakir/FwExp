import pymongo
from analyzer import utils
import logging
import ipaddress
import pql


class analyzer(object):
    def __init__(self, db_path, db_name="Firewall_info"):
        self.conn = pymongo.MongoClient(db_path)
        self.cursor = self.conn[db_name]
        self.policy_col = self.cursor['policy']
        self.address_objects_col = self.cursor['network_objects']
        self.service_objects_col = self.cursor['service_object']
        self.misc_objects_col = self.cursor['misc']
        self.last_result_col = self.cursor['last_result']

    # Not implemented yet
    def get_one_hop(self, src, dst):
        src_address_names = []
        if utils.determine_if_ip(src):
            src_address_names = self._get_address_name_of_ip(src)
        # if the input is not ip, it means the input is FQDN
        else:
            src_address_names = self._get_address_names_of_fqdn(src)
        pass

    def _get_address_names_of_fqdn(self, fqdn):
        pass

    def _get_iprange_query_by_operation(self, operation, ip_val):
        if operation == '$eq':
            return {'type': 'IP_RANGE', 'min_ip': {'$lte': ip_val}, 'max_ip': {'$gte': ip_val}}
        elif operation == '$gt':
            return {'type': 'IP_RANGE', 'max_ip': {'$gt': ip_val}}
        elif operation == '$gte':
            return {'type': 'IP_RANGE', 'max_ip': {'$gte': ip_val}}
        elif operation == '$lt':
            return {'type': 'IP_RANGE', 'min_ip': {'$lt': ip_val}}
        elif operation == '$lte':
            return {'type': 'IP_RANGE', 'min_ip': {'$lte': ip_val}}
        #       elif operation == '$not':

        else:
            raise NotImplementedError('Unrecognized operation for iprange query')

    def _is_wildcard_match_ip(self, ip_val, wildcard_ip, wildcard_mask, operation):
        wildcard_mask_not = int(ipaddress.IPv4Address("255.255.255.255")) - wildcard_mask
        max_wildcard_ip = wildcard_ip | wildcard_mask
        min_wildcard_ip = wildcard_ip & wildcard_mask_not
        if operation == '$eq':
            return wildcard_ip & wildcard_mask_not == ip_val & wildcard_mask
        elif operation == '$gt':
            # compare against the biggest possible ip of wildcard
            return max_wildcard_ip > ip_val
        elif operation == '$gte':
            return max_wildcard_ip >= ip_val
        elif operation == '$lt':
            return min_wildcard_ip < ip_val
        elif operation == '$lte':
            return min_wildcard_ip <= ip_val
        else:
            raise NotImplementedError('Unrecognized operation for iprange query')

    def _get_network_objects_ids_of_ip(self, ip, operation='$eq'):
        ip_val = utils.ipv4_to_int(ip)
        results = set()
        query = self._get_iprange_query_by_operation(operation, ip_val)

        # for ip_range object
        results.update([obj['id'] for obj in list(self.address_objects_col.find(query))])

        # for wildcard object
        for wildcard_obj in self.address_objects_col.find({'type': 'WILDCARD'}):
            wildcard_ip = int(ipaddress.IPv4Address(wildcard_obj['wildcard_ip']))
            wildcard_mask = int(ipaddress.IPv4Address(wildcard_obj['wildcard_mask']))
            if self._is_wildcard_match_ip(ip_val, wildcard_ip, wildcard_mask, operation):
                results.add(wildcard_obj['id'])

        # Go over each group object
        group_results = []
        for group in self.address_objects_col.find({'members.0': {"$exists": True}}):
            child_ids = self._get_all_child_ids_recursively(group)
            if any(child in results for child in child_ids):
                group_results.append(group['id'])

        results.update(group_results)
        return results

    def _get_all_child_ids_recursively(self, parent):
        members = parent.get('members')
        if not members:
            return [parent['id']]
        result = {parent['id']}
        for child in members:
            result.update(self._get_all_child_ids_recursively(self._get_obj_by_id(child)))
        return result

    def _get_obj_by_name(self, name, search_in_last_result=False):
        if search_in_last_result:
            collection = self.last_result_col
        else:
            collection = self.address_objects_col
        obj = collection.find_one({'name': name})
        if not obj:
            return None
        return obj

    def _get_obj_by_id(self, id, search_in_last_result=False):
        if search_in_last_result:
            collection = self.last_result_col
        else:
            collection = self.address_objects_col
        obj = collection.find_one({'id': id})
        if not obj:
            return None
        return obj

    def _find_rules_matching_address_in_column(self, ip_address, operation='$eq', column='source',
                                               search_in_last_result=False):
        if search_in_last_result:
            collection = self.last_result_col
        else:
            collection = self.policy_col
        results = []
        # Find rules for non-negated
        network_obj_ids = self._get_network_objects_ids_of_ip(ip_address, operation)
        results.extend(collection.find({column: {'$in': network_obj_ids}, column + '-negate': False}).distinct('id'))

        # Find rules for negated
        for rule in collection.find({column + '-negate': True}):
            if not any(i in rule[column] for i in network_obj_ids):
                # If network_obj_ids and rule['source'] do not share an element
                results.append(rule['id'])

        # self.last_result_col.drop()
        # self.last_result_col.insert(results)
        return results

    def _find_allowed_denied_rules(self, is_allowed=True):
        results = self.policy_col.find({'action': is_allowed}).distinct('id')
        return results

    def query(self, query_str):
        query_json = pql.find(query_str)  # Here we can also verify that the input types are correct #TODO
        query_json_parsed = self._parse_user_query_to_db_query(query_json)
        var1 = self.policy_col.find(query_json_parsed, {'_id': 0, 'dst_ip': 1, 'src_ip': 1, 'name': 1, 'service': 1})
        # return self._get_rules_by_id(var1)
        return list(var1)

    def _translate_ip_range_to_query(self, first_ip, last_ip, field):
        query = {'$or': [
            {'$and': [{
                field: {
                    '$elemMatch': {
                        '$and': [{
                            'min_ip': {'$lte': last_ip}
                        }, {
                            'max_ip': {'$gte': first_ip}
                        }]
                    }
                }},
                {self._get_negate_key_name_for_field(field): False}
            ]},
            {'$and': [
                {'$nor': [{
                    field: {
                        '$elemMatch': {
                            '$and': [{
                                'min_ip': {'$lte': first_ip}
                            }, {
                                'max_ip': {'$gte': last_ip}
                            }]
                        }
                    }}
                ]},
                {self._get_negate_key_name_for_field(field): True}
            ]}
        ]}  # TODO: wildcard ips
        return query

    def _translate_searched_ip_to_query(self, subnet_addr, subnet_negated, field):
        # Algorithm: (All objects where min_ip <= subnet) intersection (All objects where max_ip >= subnet)
        if '/' in subnet_addr:
            ipnet = ipaddress.IPv4Network(subnet_addr, False)
            first_ip = int(ipnet[0])
            last_ip = int(ipnet[-1])
        else:
            ipaddr = int(ipaddress.IPv4Address(subnet_addr))
            first_ip = int(ipaddr)
            last_ip = int(ipaddr)

        if subnet_negated:
            return {'$or': [
                self._translate_ip_range_to_query(0, first_ip - 1, field),
                self._translate_ip_range_to_query(last_ip + 1, (2 ** 32) - 1, field)
            ]}
        return self._translate_ip_range_to_query(first_ip, last_ip, field)

    # if subnet_negated:
    # not 1.1.1.0-1.1.1.254 is like 2.2.2.1-0.0.0.255 (wrapped around)
    #     first_ip, last_ip = last_ip + 1, first_ip - 1
    #     op = '$or'

    def _parse_user_query_to_db_query(self, query_json):
        if type(query_json) == dict:
            key = next(iter(query_json))
            translated_key = self._translate_user_gibrish_to_key(key)
            if translated_key in ['src_ip', 'dst_ip']:
                if type(query_json[key]) == dict and next(iter(query_json[key])) == '$not':
                    return self._translate_searched_ip_to_query(query_json[key]['$not'], True, translated_key)
                elif type(query_json[key]) == str:
                    return self._translate_searched_ip_to_query(query_json[key], False, translated_key)
                else:
                    raise NotImplementedError('Comparison operation Not recognized on source/destination object')
            elif translated_key in ['tcp-portrange', 'udp-portrange']:
                if type(query_json[key]) == str:
                    return self._translate_searched_port_to_query(query_json[key], translated_key)
                else:
                    raise NotImplementedError('This Comparison operation is Not recognized on service object currently')
            else:
                debug = {key: self._parse_user_query_to_db_query(query_json[key])}
                return debug
        elif type(query_json) == list:
            return [self._parse_user_query_to_db_query(elem) for elem in query_json]

    def _get_rules_by_id(self, id_list):
        return list(self.policy_col.find({'id': {'$in': id_list}}))

    def _get_negate_key_name_for_field(self, field):
        if field == 'src_ip':
            return 'source-negate'
        elif field == 'dst_ip':
            return 'destination-negate'
        else:
            raise NotImplementedError('Unrecognized rule field: ' + field)

    def _translate_user_gibrish_to_key(self, user_input):
        if user_input.lower() in ['source', 'src']:
            return 'src_ip'
        elif user_input.lower() in ['destination', 'dst']:
            return 'dst_ip'
        elif user_input.lower() in ['tcpport', 'tcp.port', 'tcp-service', 'tcp']:
            return 'tcp-portrange'
        elif user_input.lower() in ['udpport', 'udp.port', 'udp-service', 'udp']:
            return 'udp-portrange'
        return user_input

    def _translate_searched_port_to_query(self, port_comma_separated, field):
        ports = []
        for port in port_comma_separated.split(','):
            ports.append(int(port.strip()))

        # right now assuming single port. TODO: multi ports separated by ','

        query = {'$or': [
            {'$and': [{
                'ports.'+field: {
                    '$elemMatch': {
                        '$and': [{
                            'dst-port-min': {'$lte': ports[0]}
                        }, {
                            'dst-port-max': {'$gte': ports[0]}
                        }]
                    }
                }},
                {'service-negate': False}
            ]},
            {'$and': [
                {'$nor': [{
                    'ports.' + field: {
                        '$elemMatch': {
                            '$and': [{
                                'dst-port-min': {'$lte': ports[0]}
                            }, {
                                'dst-port-max': {'$gte': ports[0]}
                            }]
                        }
                    }}
                ]},
                {'service-negate': True}
            ]}
        ]}
        return query
