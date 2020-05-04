import sqlite3
from firewall.firewall import AddressType
from analyzer import utils

class analyzer(object):
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()

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
        address_names = []
        for name, details in self.cursor.execute('SELECT name, details FROM addresses WHERE type={}'.format(int(AddressType.FQDN))):
            if details == fqdn:
                address_names.append(name)
        return address_names

    def _get_address_name_of_ip(self, ip):
        address_names = []
        # Get from IP Range
        for name, range in self.cursor.execute('SELECT name, details FROM addresses WHERE type={}'.format(int(AddressType.IP_RANGE))):
            min, max = range.split(' ')
            if utils.check_ipv4_in_range(ip, min, max):
                address_names.append(name)

        # Get from Subnet
        for name, subnet in self.cursor.execute('SELECT name, details FROM addresses WHERE type={}'.format(int(AddressType.SUBNET))):
            network, mask = subnet.split(' ')
            if utils.check_ipv4_in_subnet(ip, network, mask):
                address_names.append(name)

        return address_names


