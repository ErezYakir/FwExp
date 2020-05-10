
class NetworkObject(object):
    def __init__(self, id='', name='', vdom='', type='', extra_info=''):
        self.id = id
        self.name = name
        self.vdom = vdom
        self.type = type
        self.extra_info = extra_info