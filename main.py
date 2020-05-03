from enum import Enum
import urllib.request
import ssl
import requests
import re


class Vendon(Enum):
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

class FortigateFirewall(Firewall):
    def __init__(self, ip, user, pwd):
        super().__init__(ip, user, pwd)
        # -- Entering policy definition block
        self.p_entering_policy_block = re.compile('^\s*config firewall policy$', re.IGNORECASE)
        # -- Exiting policy definition block
        self.p_exiting_policy_block = re.compile('^end$', re.IGNORECASE)
        # -- Commiting the current policy definition and going to the next one
        self.p_policy_next = re.compile('^next$', re.IGNORECASE)
        # -- Policy number
        self.p_policy_number = re.compile('^\s*edit\s+(?P<policy_number>\d+)', re.IGNORECASE)
        # -- Policy setting
        self.p_policy_set = re.compile('^\s*set\s+(?P<policy_key>\S+)\s+(?P<policy_value>.*)$', re.IGNORECASE)


    def fetch(self):
        ses = requests.Session()
        fetch_url = 'https://{}/api/v2/monitor/system/config/backup?destination=file&scope=global'.format(self.ip)
        login_url = 'https://{}/logincheck'.format(self.ip)
        # Login
        ses.post(url=login_url, data={'ajax':'1', 'username':self.user, 'secretkey':self.pwd}, verify=False)
        # Download file locally
        with open("bkp.tmp", 'w') as f:
            f.write(ses.get(fetch_url, verify=False).text)

    def convertToJson(self):
        results, keys = self._parse()
        print(results)
        print(keys)

    def _parse(self):
        in_policy_block = False

        policy_list = []
        policy_elem = {}

        order_keys = []

        with open("bkp.tmp", 'r') as fd_input:
            for line in fd_input:
                line = line.lstrip().rstrip().strip()

                # We match a policy block
                if self.p_entering_policy_block.search(line):
                    in_policy_block = True

                # We are in a policy block
                if in_policy_block:
                    if self.p_policy_number.search(line):
                        policy_number = self.p_policy_number.search(line).group('policy_number')
                        policy_elem['id'] = policy_number
                        if not ('id' in order_keys): order_keys.append('id')

                    # We match a setting
                    if self.p_policy_set.search(line):
                        policy_key = self.p_policy_set.search(line).group('policy_key')
                        if not (policy_key in order_keys): order_keys.append(policy_key)

                        policy_value = self.p_policy_set.search(line).group('policy_value').strip()
                        policy_value = re.sub('["]', '', policy_value)

                        policy_elem[policy_key] = policy_value

                    # We are done with the current policy id
                    if self.p_policy_next.search(line):
                        policy_list.append(policy_elem)
                        policy_elem = {}

                # We are exiting the policy block
                if self.p_exiting_policy_block.search(line):
                    in_policy_block = False

        return (policy_list, order_keys)



try:
    f = FortigateFirewall("13.77.200.222", "yakir", "Aa123456123456")
    f.fetch()
    f.convertToJson()
except  Exception as e:
    print(e)