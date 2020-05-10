from firewall import fortigatefirewall, checkpointfirewall
from analyzer.analyzer import analyzer

try:
    f = checkpointfirewall.CheckpointFirewall("52.161.22.180", "yakir", "Aa123456123456", "mongodb://localhost:27017/")
    f.fetch()
    f.parseToDb()


    m_analyzer = analyzer("mongodb://localhost:27017/")
    #my_obj = m_analyzer._get_obj_by_name("ipgroup3")
    #childs = m_analyzer._get_all_child_ids_recursively(my_obj)
    a = m_analyzer._get_address_objects_of_ip("1.1.1.1")
    m_analyzer._get_rules_sorted()
    print('a')
    #m_analyzer.get_one_hop('1.1.1.1', '2.2.2.2')

except  Exception as e:
    print(e)