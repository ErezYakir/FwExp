from enum import Enum
import sqlite3
import pymongo


class Vendor(Enum):
    CHECKPOINT = 1
    FORTIGATE = 2
    PALOALTO = 3


class AddressType(Enum):
    FQDN = 'FQDN'
    IP_RANGE = 'IP_RANGE'


class Firewall(object):
    """
    Reprensents a Firewall list of rules. should at the end contain a DB that represents the whole DB
    The DB tables, fields will be:
    Table 1 - Policy
    * Name - not necesarily relevant for parsing but for later looking at the DB for exact Rule
    * Source - Taken 1 for 1 from Backup file
    * Dest - Taken 1 for 1 from Backup file
    * Schedule - seen it on fortigate, should look in other Firewalls XXX
    * Service - taken 1 for 1 from Backup file
    * Ports - taken 1 for 1 from Backup file, added from Service list
    * Action - taken 1 for 1 from Backup file
    * NAT - seen it on fortigate, should look in other Firewalls XXX
    * Security Profile - seen it on fortigate, should look in other Firewalls XXX

    Table 2 - Addresses
    * Name
    * Type - Subnet / ip range / FQDN
    * Value

    Table 3 - Services (Translation of service to its default port)
    * Service Name
    * Ports value


    """

    def __init__(self, ip, user, pwd, db_path, db_name="Firewall_info"):
        self.ip = ip
        self.user = user
        self.pwd = pwd
        self.conn = pymongo.MongoClient(db_path)
        self.cursor = self.conn[db_name]
        self.policy_col = self.cursor['policy']
        self.address_objects_col = self.cursor['addresses']
        self.service_objects_col = self.cursor['services']
        self.misc_objects_col = self.cursor['misc']

    def fetch(self):
        raise NotImplementedError()

    def parseToDb(self):
        """
        Reads temp\bkp.tmp and updates mongodb accordingly
        :return:
        """
        self.address_objects_col.drop()
        self.service_objects_col.drop()
        self.policy_col.drop()
        self.misc_objects_col.drop()

        results = self._parse_misc()
        self.misc_objects_col.insert_many(results)

        results = self._parse_addresses()
        self.address_objects_col.insert_many(results)

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

    def _parse_addresses(self):
        raise NotImplementedError()

    def _parse_groups(self):
        raise NotImplementedError()
