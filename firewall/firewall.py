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

    def __init__(self, ip, user, pwd, db_name):
        self.ip = ip
        self.user = user
        self.pwd = pwd
        self.conn = sqlite3.connect('example.db')
        self.cursor = self.conn.cursor()
        self.conn2 = pymongo.MongoClient("mongodb://localhost:27017/")
        self.cursor2 = self.conn2[db_name]
        self.policy_col = self.cursor2['policy']
        self.address_objects_col = self.cursor2['addresses']
        self.service_objects_col = self.cursor2['services']

    def __del__(self):
        self.conn.commit()
        self.conn.close()

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

        results = self._parse_address_objects()
        self.address_objects_col.insert_many(results)

        results = self._parse_service_objects()
        self.service_objects_col.insert_many(results)

        results = self._parse_policy()
        self.policy_col.insert_many(results)

    def _parse_address_objects(self):
        raise NotImplementedError()
    def _parse_service_objects(self):
        raise NotImplementedError()

    def _parse_policy(self):
        """
        returns an array of objects out of the firewall configuration which looks like:
        [{
        'name':'example', 'id':'123', 'srcintf':['interface1'],
        'dstintf':['interface2', 'interface3'], 'srcaddr':[{'type':'ADDRESS', 'name':'ALL_IPS'}],
        'dstaddr':[{'type':'ADDRESS', 'name':'MY_IP'}, {'type':'GROUP', 'name':'GRP1'}],
         'service':['SMB','TCP\123','UDP\53'],
        'priority': 15, 'action': 1(ALLOW), 'enabled':0(not enabled)
        }]
        pay attention to the types of each value and to the name of each key. it's important to return
        it fully with every parameter, if needed, calculate yourself a value if not given in configuration.
        It is possible to enlarge the returned object to allow for more features, but those are the required params.
        """
        raise NotImplementedError()

    def _parse_addresses(self):
        """
        returns an array of objects out of the firewall configuration which looks like:
        [{
        'name':'my_address', 'id':'123', 'value': {'type':'FQDN', 'fqdn':'www.google.com'}
        },
        {
        'name':'my_second_address', 'id':'145', 'value': {'type':'IP_RANGE', 'MIN_IP':'192.168.0.1', 'MAX_IP':'192.168.0.128'}
        }
        ]
        pay attention to the types of each value and to the name of each key. it's important to return
        it fully with every parameter, if needed, calculate yourself a value if not given in configuration.
        It is possible to enlarge the returned object to allow for more features, but those are the required params.
        """
        raise NotImplementedError()

    def _parse_groups(self):
        """
        returns an array of objects out of the firewall configuration which looks like:
        [{
        'name':'my_group', 'id':'123', 'value': [{'type':'address', 'name':'my_address'}, {'type':'group', name:'grp1'}]
        }
        ]
        pay attention to the types of each value and to the name of each key. it's important to return
        it fully with every parameter, if needed, calculate yourself a value if not given in configuration.
        It is possible to enlarge the returned object to allow for more features, but those are the required params.
        """
        raise NotImplementedError()
