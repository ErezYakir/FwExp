import re
import ipaddress


def determine_if_ip(data):
    return re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", data)

def check_ipv4_in_range(ip, min, max):
    return ipaddress.IPv4Address(min) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(max)

def check_ipv4_in_subnet(ip, network, mask):
    return ipaddress.IPv4Address(ip) in ipaddress.IPv4Network('{}/{}'.format(network, mask))

def ipv4_to_int(ip):
    return int(ipaddress.IPv4Address(ip))

def remove_duplicates(x):
  return list(dict.fromkeys(x))