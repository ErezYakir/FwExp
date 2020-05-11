import pymongo
from analyzer import utils
import logging


class analyzer(object):
    def __init__(self, db_path, db_name="Firewall_info"):
        self.conn = pymongo.MongoClient(db_path)
        self.cursor = self.conn[db_name]
        self.policy_col = self.cursor['policy']
        self.address_objects_col = self.cursor['addresses']
        self.service_objects_col = self.cursor['services']

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

    def _get_newtork_objects_ids_of_ip(self, ip):
        ip_val = utils.ipv4_to_int(ip)
        results = []
        # Go over each object
        for address_obj in self.address_objects_col.find({'min_ip': {'$lte': ip_val}, 'max_ip': {'$gte': ip_val}}):
            results.append(address_obj['id'])

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

    def _get_obj_by_name(self, name):
        obj = self.address_objects_col.find_one({'name': name})
        if not obj:
            return None
        obj.pop('_id')
        return obj

    def _get_obj_by_id(self, id):
        obj = self.address_objects_col.find_one({'id': id})
        if not obj:
            return None
        obj.pop('_id')
        return obj


    def _find_rules_containing_address_in_source(self, ip_address):
        results = []
        network_obj = self._get_newtork_objects_ids_of_ip(ip_address)
        for obj_id in network_obj:
            rules = self.policy_col.find({'source': obj_id, 'id': {'$nin': [rule['id'] for rule in results]}})
            if rules:
                results.extend(list(rules))
        return results

    def _network_object_matches_address(self, obj, ip_address):
        if obj['type'] == 'IP_RANGE':
            return

