from firewall import fortigatefirewall

try:
    f = fortigatefirewall.FortigateFirewall("52.161.101.23", "yakir", "Aa123456123456")
    f.fetch()
    f.parseToDb()
    #del f
except  Exception as e:
    print(e)