from enum import IntEnum

class RuleAction(IntEnum):
    ALLOW = 1
    BLOCK = 2

class RuleObject(object):
    def __init__(self, id, name, vdom, priority, service=[], vpn=[], source=[], destination=[]):
        self.id = id
        self.name = name
        self.vdom = vdom
        self.destination = destination
        self.source = source
        self.vpn = vpn
        self.service = service
        self.priority = priority
        self.source_negate = False
        self.destination_negate = False
        self.service_negate = False
        self.is_enabled = True
        self.Action = RuleAction.ALLOW