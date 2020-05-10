from enum import IntEnum

class ServiceObjectType(IntEnum):
    TCP_UDP = 1
    DCE_RPC = 2
    RPC = 3
    ICMP = 4
    SERVICE_GROUP = 5


class ServiceObject(object):
    def __init__(self, id, name, vdom, type, extra_info):
        self.id = id
        self.name = name
        self.vdom = vdom
        self.type = type
        self.extra_info = extra_info