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
        self.address_objects_col = self.cursor['addresses']
        self.service_objects_col = self.cursor['services']
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

    def _find_allowed_denied_rules(self, is_allowed=True, search_in_last_result=False):
        if search_in_last_result:
            collection = self.last_result_col
        else:
            collection = self.policy_col
        results = collection.find({'action': is_allowed}).distinct('id')
        # self.last_result_col.drop()
        # self.last_result_col.insert(results)
        return results

    def _network_object_matches_address(self, obj, ip_address):
        if obj['type'] == 'IP_RANGE':
            return

    def query(self, query_str):
        query_json = pql.find(query_str)  # Here we can also verify that the input types are correct #TODO
        query_json_parsed = self._translate_query_ip_to_object_ids(query_json)
        var1 = self.policy_col.find(query_json_parsed).distinct('id')
        return self._get_rules_by_id(var1)

    def _get_network_objects_for_subnet(self, subnet_addr):
        # Algorithm: (All objects where min_ip <= subnet) intersection (All objects where max_ip >= subnet)
        if '/' in subnet_addr:
            ipnet = ipaddress.IPv4Network(subnet_addr, False)
            less_then_start_of_subnet = self._get_network_objects_ids_of_ip(ipnet[0], '$lte')
            more_then_end_of_subnet = self._get_network_objects_ids_of_ip(ipnet[-1], '$gte')
            objects_containing_addr = list(set(less_then_start_of_subnet).intersection(more_then_end_of_subnet))
        else:
            objects_containing_addr = list(self._get_network_objects_ids_of_ip(subnet_addr, '$eq'))
        return objects_containing_addr

    def _get_network_objects_for_not_subnet(self, subnet_addr):
        # Algorithm: (All objects where min_ip >= subnet) join (All objects where max_ip <= subnet)
        if '/' in subnet_addr:
            ipnet = ipaddress.IPv4Network(subnet_addr, False)
            objects_containing_addr = self._get_network_objects_ids_of_ip(ipnet[0], '$gte')
            objects_containing_addr.update(self._get_network_objects_ids_of_ip(ipnet[-1], '$lte'))
        else:
            ipaddr = ipaddress.IPv4Address(subnet_addr)
            objects_containing_addr = self._get_network_objects_ids_of_ip(ipaddr, '$gt')
            objects_containing_addr.update(self._get_network_objects_ids_of_ip(ipaddr, '$lt'))

        return list(objects_containing_addr)

    def _translate_query_ip_to_object_ids(self, query_json):
        if type(query_json) == dict:
            key = next(iter(query_json))
            if key.lower() in ['source', 'destination', 'src', 'dst']:
                if type(query_json[key]) == dict and next(iter(query_json[key])) == '$not':
                    objects_containing_addr = self._get_network_objects_for_not_subnet(query_json[key]['$not'])
                elif type(query_json[key]) == str:
                    objects_containing_addr = self._get_network_objects_for_subnet(query_json[key])
                else:
                    raise NotImplementedError('Comparison operation Not recognized on source/destination object')

                if key.lower() in ['source', 'src']:
                    return {'$or': [
                        {'source': {'$in': objects_containing_addr}, 'source-negate': False},
                        {'source': {'$nin': objects_containing_addr}, 'source-negate': True}
                    ]}
                else:
                    return {'$or': [
                        {'destination': {'$in': objects_containing_addr}, 'destination-negate': False},
                        {'destination': {'$nin': objects_containing_addr}, 'destination-negate': True}
                    ]}

            else:
                debug = {key: self._translate_query_ip_to_object_ids(query_json[key])}
                return debug
        elif type(query_json) == list:
            return [self._translate_query_ip_to_object_ids(elem) for elem in query_json]

    def _get_rules_by_id(self, id_list):
        return list(self.policy_col.find({'id': {'$in': id_list}}))
