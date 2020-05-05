from firewall import fortigatefirewall, checkpointfirewall
from analyzer.analyzer import analyzer

try:
    f = fortigatefirewall.FortigateFirewall("52.161.22.180", "yakir", "Aa123456123456")
    f.fetch()
    f.parseToDb()

    m_analyzer = analyzer('example.db')
    print(m_analyzer._get_address_name_of_ip('5.6.7.8'))
    #m_analyzer.get_one_hop('1.1.1.1', '2.2.2.2')

except  Exception as e:
    print(e)