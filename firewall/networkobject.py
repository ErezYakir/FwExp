from enum import IntEnum

class NetworkObjectType(IntEnum):
    IP_RANGE = 1
    NETWORK_GROUP = 2
    FQDN = 3
    WILDCARD = 4


class NetworkObject(object):
    def __init__(self, id, name, vdom, type, extra_info):
        self.id = id
        self.name = name
        self.vdom = vdom
        self.type = type
        self.extra_info = extra_info