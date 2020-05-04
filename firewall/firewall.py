from enum import Enum
import sqlite3

class Vendor(Enum):
    CHECKPOINT = 1
    FORTIGATE = 2
    PALOALTO = 3

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
    def __init__(self, ip, user, pwd):
        self.ip = ip
        self.user = user
        self.pwd = pwd
        self.conn = sqlite3.connect('example.db')
        self.cursor = self.conn.cursor()
        c.execute('''CREATE TABLE policy
                     (date name, srcip text, symbol text, qty real, price real)''')

    def __del__(self):
        self.conn.close()

    def fetch(self):
        """
        Writes backup file of firewall to temp\bkp.tmp
        :return:
        """
        raise NotImplementedError()

    def convertToJson(self):
        """
        Reads temp\bkp.tmp and converts to json file, write to out.json
        :return:
        """
        raise NotImplementedError()