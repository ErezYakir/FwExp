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
        self.network_objects_col = self.cursor['network_objects'] # contains objects that Source/Dest columns contains
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

    def _parse_misc(self):
        raise NotImplementedError()

    def _parse_services(self):
        raise NotImplementedError()

    def _parse_policy(self):
        raise NotImplementedError()

    def _parse_network_objects(self):
        raise NotImplementedError()
