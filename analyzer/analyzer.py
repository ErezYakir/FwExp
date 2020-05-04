import sqlite3
from firewall.firewall import AddressType
from analyzer import utils
import ipaddress

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
        return self.cursor.execute('SELECT name FROM addresses WHERE type="FQDN" AND fqdn={}'.format(fqdn)).fetchall()

    def _get_address_name_of_ip(self, ip):
        ip_val = int(ipaddress.IPv4Address(ip))
        return self.cursor.execute('SELECT name FROM addresses WHERE type="IP_RANGE" AND min_addr<={0}'
                                   ' AND max_addr>={0}'.format(ip_val)).fetchall()


