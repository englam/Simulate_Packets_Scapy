'''

Usage:
python config_ip.py 192.168.1.30 3002::30 192.168.1.60 3002::60

'''

import json,sys


lan_ip		= sys.argv[1]
lan_ip6		= sys.argv[2]
wlan_ip		= sys.argv[3]
wlan_ip6	= sys.argv[4]
Wireless_Card	= sys.argv[5]

with open('config.json') as json_data:
    d = json.load(json_data)


d["lan_ip"]             = str(lan_ip)
d["lan_ip6"]            = str(lan_ip6)
d["wlan_ip"]            = str(wlan_ip)
d["wlan_ip6"]           = str(wlan_ip6)
d["Wireless_Card"]      = str(Wireless_Card)

with open('config.json', 'w') as outfile:
    json.dump(d, outfile)
