import pymongo
from analyzer import utils
import logging
import ipaddress


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

    def _get_network_objects_ids_of_ip(self, ip):
        ip_val = utils.ipv4_to_int(ip)
        results = []
        # for ip_range object
        results.extend([obj['id'] for obj in list(self.address_objects_col.find({'type': 'IP_RANGE',
                                                                                 'min_ip': {'$lte': ip_val},
                                                                                 'max_ip': {'$gte': ip_val}}))])

        # for wildcard object
        for wildcard_obj in self.address_objects_col.find({'type': 'WILDCARD'}):
            wildcard_ip = int(ipaddress.IPv4Address(wildcard_obj['wildcard_ip']))
            wildcard_mask = \
                int(ipaddress.IPv4Address("255.255.255.255")) - int(
                    ipaddress.IPv4Address(wildcard_obj['wildcard_mask']))
            if wildcard_ip & wildcard_mask == ip_val & wildcard_mask:
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

    def _find_rules_containing_address_in_column(self, ip_address, column='source', search_in_last_result=False):
        if search_in_last_result:
            collection = self.last_result_col
        else:
            collection = self.policy_col
        results = []
        # Find rules for non-negated
        network_obj_ids = self._get_network_objects_ids_of_ip(ip_address)
        for obj_id in network_obj_ids:
            rules = collection.find({column: obj_id,
                                     column + '-negate': False,
                                     'id': {'$nin': [rule['id'] for rule in results]}})
            if rules:
                results.extend(list(rules))

        # Find rules for negated
        for rule in collection.find({column+'-negate': True}):
            if not any(i in rule[column] for i in network_obj_ids):
                # If network_obj_ids and rule['source'] do not share an element
                results.append(rule)

        self.last_result_col.drop()
        self.last_result_col.insert(results)
        return results

    def _find_allowed_denied_rules(self, is_allowed=True, search_in_last_result=False):
        if search_in_last_result:
            collection = self.last_result_col
        else:
            collection = self.policy_col
        results = list(collection.find({'action': is_allowed}))
        self.last_result_col.drop()
        self.last_result_col.insert(results)
        return results

    def _network_object_matches_address(self, obj, ip_address):
        if obj['type'] == 'IP_RANGE':
            return
