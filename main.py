from firewall import fortigatefirewall, checkpointfirewall
from analyzer.analyzer import analyzer
from firewall.networkobject import NetworkObject

try:
    f = fortigatefirewall.FortigateFirewall("52.161.93.194", "yakir", "Aa123456123456", "mongodb://localhost:27017/", "Fortigate")
    f.fetch()
    f.parseToDb()


    m_analyzer = analyzer("mongodb://localhost:27017/")
    m_obj = NetworkObject('143', 'name1', {'1': 1, '2': '2'}, ['IP_RANGE'], {'extra': {'1': '2'}})
    print(m_obj.__dict__)
    #m_analyzer.get_one_hop('1.1.1.1', '2.2.2.2')

except  Exception as e:
    print(e)