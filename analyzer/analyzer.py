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
        results = []
        query = self._get_iprange_query_by_operation(operation, ip_val)

        # for ip_range object
        results.extend([obj['id'] for obj in list(self.address_objects_col.find(query))])

        # for wildcard object
        for wildcard_obj in self.address_objects_col.find({'type': 'WILDCARD'}):
            wildcard_ip = int(ipaddress.IPv4Address(wildcard_obj['wildcard_ip']))
            wildcard_mask = int(ipaddress.IPv4Address(wildcard_obj['wildcard_mask']))
            if self._is_wildcard_match_ip(ip_val, wildcard_ip, wildcard_mask, operation):
                results.append(wildcard_obj['id'])

        # Go over each group object
        group_results = []
        for group in self.address_objects_col.find({'members.0': {"$exists": True}}):
            child_ids = self._get_all_child_ids_recursively(group)
            if any(child in results for child in child_ids):
                group_results.append(group['id'])

        results.extend(group_results)
        return utils.remove_duplicates(results)

    def _get_all_child_ids_recursively(self, parent):
        members = parent.get('members')
        if not members:
            return [parent['id']]
        result = [parent['id']]
        for child in members:
            result.extend(self._get_all_child_ids_recursively(self._get_obj_by_id(child)))
        return utils.remove_duplicates(result)

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

    def _find_rules_matching_address_in_column(self, ip_address, operation='$eq', column='source', search_in_last_result=False):
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
        negated_query = {'source-negate': True}
        var1 = list(self.policy_col.find(query_json_parsed))
        var2 = list(self.policy_col.find(negated_query))
        return [i for i in var1+var2 if i not in var1 or i not in var2] # xor of two lists

    def _translate_query_ip_to_object_ids(self, query_json):
        if type(query_json) == dict:
            key = next(iter(query_json))
            if key.lower() in ['source', 'destination', 'src', 'dst']:
                if '/' in query_json[key]:
                    ipnet = ipaddress.IPv4Network(query_json[key], False)
                    less_then_start_of_subnet = self._get_network_objects_ids_of_ip(ipnet[0], '$lte')
                    more_then_end_of_subnet = self._get_network_objects_ids_of_ip(ipnet[-1], '$gte')
                    objects_containing_addr = list(set(less_then_start_of_subnet).intersection(more_then_end_of_subnet))
                else:
                    objects_containing_addr = self._get_network_objects_ids_of_ip(query_json[key], '$eq')
                if key.lower() in ['source', 'src']:
                    return {'source': {'$in': objects_containing_addr}}
                else:
                    return {'destination': {'$in': objects_containing_addr}}
            else:
                debug = {key: self._translate_query_ip_to_object_ids(query_json[key])}
                return debug
        elif type(query_json) == list:
            return [self._translate_query_ip_to_object_ids(elem) for elem in query_json]

    def _get_rules_by_id(self, id_list):
        return list(self.policy_col.find({'id': {'$in': id_list}}))

"""
    def parse_filter_expression(self, query_json):
        if '$and' in query_json:
            result_lists = []
            for element in query_json['$and']:
                single_result_list = self.parse_filter_expression(element)
                result_lists.append(single_result_list)
            return list(set(result_lists[0]).intersection(*result_lists))
        elif '$or' in query_json:
            result_set = set()
            for element in query_json['$or']:
                result_set.update(self.parse_filter_expression(element))
            return list(result_set)
        elif '$not' in query_json:
            result = self.parse_filter_expression(query_json['$not'])
            all_rules = self._get_all_rules_ids()
            # list subtraction: all_rules - result
            return [id for id in all_rules if id not in result]
        elif 'dst' in query_json:
            value = query_json['dst']
            if type(value) == str:
                ip_value = int(ipaddress.IPv4Address(value))
                return self._find_rules_matching_address_in_column(ip_value, '$eq', 'destination', False)
            elif type(value) == dict:
                op = next(iter(value))
                ip_value = int(ipaddress.IPv4Address(value[op]))
                return self._find_rules_matching_address_in_column(ip_value, op, 'destination', False)
        elif 'src' in query_json:
            value = query_json['src']
            if type(value) == str:
                ip_value = int(ipaddress.IPv4Address(query_json['src']))
                return self._find_rules_matching_address_in_column(ip_value, '$eq', 'source', False)
            elif type(value) == dict:
                op = next(iter(value))
                ip_value = int(ipaddress.IPv4Address(value[op]))
                return self._find_rules_matching_address_in_column(ip_value, op, 'source', False)
        elif 'action' in query_json:
            self._find_allowed_denied_rules(query_json['action'], False)
        else:
            raise NotImplementedError("Unknown dictionary key when parsing filter expression")

    def _get_all_rules_ids(self):
        return list(self.policy_col.find({}).distinct('id'))
"""


