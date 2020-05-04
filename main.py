from firewall import fortigatefirewall

try:
    f = FortigateFirewall("13.77.200.222", "yakir", "Aa123456123456")
    f.fetch()
    f.convertToJson()
except  Exception as e:
    print(e)