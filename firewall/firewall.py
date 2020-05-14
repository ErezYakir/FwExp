import pymongo


class Firewall(object):
    """
    A base class for firewall parser.
    This class should be able to take firewall configuration and convert it to a single format.
    """

    def __init__(self, ip, user, pwd, db_path, db_name="Firewall_info"):
        self.ip = ip
        self.user = user
        self.pwd = pwd
        self.conn = pymongo.MongoClient(db_path)
        self.cursor = self.conn[db_name]
        self.policy_col = self.cursor['policy']  # contains the rules
        self.network_objects_col = self.cursor['network_objects']  # contains objects that Source/Dest columns contains
        self.service_objects_col = self.cursor['service_object']  # contains the objects that service column contains
        self.misc_objects_col = self.cursor['misc']  # contains all the other objects

    def fetch(self):
        """
        Fetches the configuration of firewall for later parsing
        """
        raise NotImplementedError()

    def parseToDb(self):
        """
        parses objects and rules in configuration into single format and fills in mongodb.
        """
        # Clear any early data
        self.network_objects_col.drop()
        self.service_objects_col.drop()
        self.policy_col.drop()
        self.misc_objects_col.drop()

        results = self._parse_misc()
        self.misc_objects_col.insert_many(results)

        results = self._parse_network_objects()
        self.network_objects_col.insert_many(results)

        results = self._parse_services()
        self.service_objects_col.insert_many(results)

        results = self._parse_policy()
        self.policy_col.insert_many(results)

        self._resolve_ip_addresses_into_collection()
        self._resolve_services_into_collection()

    def _parse_misc(self):
        raise NotImplementedError()

    def _parse_services(self):
        raise NotImplementedError()

    def _parse_policy(self):
        raise NotImplementedError()

    def _parse_network_objects(self):
        raise NotImplementedError()

    def _resolve_ip_addresses_into_collection(self):
        src_ranges, dst_ranges = [], []
        for rule in self.policy_col.find({}):
            sources = rule['source']
            dests = rule['destination']
            for src_id in sources:
                list_of_min_max = self._resolve_object_id_to_ip(src_id)
                src_ranges.extend(list_of_min_max)
            for dst_id in dests:
                list_of_min_max = self._resolve_object_id_to_ip(dst_id)
                dst_ranges.extend(list_of_min_max)
            self.policy_col.update(
                {'id': rule['id']},
                {'$set': {
                    'src_ip': src_ranges,
                    'dst_ip': dst_ranges
                }}
            )
            src_ranges, dst_ranges = [], []

    def _resolve_object_id_to_ip(self, id):
        network_obj = self.network_objects_col.find_one({'id': id})
        if not network_obj:
            print('Object is not found in collection of network objects. could not recognize it\'s ip address')
            return [{'id': id, 'ip': 'Could Not Recognize'}]
        if network_obj['type'].lower() == 'ip_range':
            return [{'name': network_obj['name'], 'min_ip': network_obj['min_ip'], 'max_ip': network_obj['max_ip']}]
        elif network_obj['type'].lower() == 'wildcard':
            return [{'name': network_obj['name'], 'wildcard_ip': network_obj['wildcard_ip'],
                     'wildcard_mask': network_obj['wildcard_mask']}]
        elif network_obj['type'].lower() == 'group':
            result = [{'name': network_obj['name'] + ' (GROUP)'}]
            for elem in network_obj.get('members', []):
                result.extend(self._resolve_object_id_to_ip(elem))
            return result
        else:
            raise NotImplementedError('No such object network type: ' + network_obj['type'])

    def _resolve_object_id_to_ports(self, id):
        service_obj = self.service_objects_col.find_one({'id': id}, {'_id': 0, 'name': 1, 'type': 1, 'tcp-portrange': 1,
                                                                     'udp-portrange': 1})
        if not service_obj:
            print('Object is not found in collection of service objects. could not recognize it\'s port numbers')
            return [{'id': id, 'ports': 'Could Not Recognize'}]
        if service_obj['type'].lower() == 'service-tcp-udp':
            service_obj.pop('type')
            return [service_obj]
        elif service_obj['type'].lower() == 'group':
            result = [{'name': service_obj['name'] + ' (GROUP)'}]
            for elem in service_obj.get('members', []):
                result.extend(self._resolve_object_id_to_ports(elem))
            return result
        else:
            return [{'name': service_obj['name'], 'ports': 'Could not recognize ports. Use name and actual '
                                                           'Firewall configuration to draw conclusions'}]

    def _resolve_services_into_collection(self):
        ports = []
        for rule in self.policy_col.find({}, {'_id': 0, 'service': 1, 'id': 1}):
            for svc_id in rule['service']:
                ports.extend(self._resolve_object_id_to_ports(svc_id))
            self.policy_col.update(
                {'id': rule['id']},
                {'$set': {'ports': ports}})
            ports = []
