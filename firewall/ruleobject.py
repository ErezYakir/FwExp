
class RuleObject(object):
    def __init__(self, id, name, vdom, priority, extra_info, service=[], vpn=[], source=[], destination=[]):
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
        self.Action = True
        self.extra_info = extra_info