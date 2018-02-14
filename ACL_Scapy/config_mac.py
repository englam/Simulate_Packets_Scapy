'''

Usage:
python config_mac.py "Intel(R) PRO/1000 MT Desktop Adapter #2" "08:00:27:D1:D8:DB" "NETGEAR A6210 WiFi USB3.0 Adapter" "B0:39:56:90:61:40" "00:eb:d5:60:1a:20"

'''


import json,sys


local_interface		= sys.argv[1]
local_mac		= sys.argv[2]
wifi_interface		= sys.argv[3]
wifi_mac	        = sys.argv[4]
dut_mac	                = sys.argv[5]

with open('config.json') as json_data:
    d = json.load(json_data)


d["local_interface"]    = str(local_interface)
d["local_mac"]          = str(local_mac)
d["wifi_interface"]     = str(wifi_interface)
d["wifi_mac"]           = str(wifi_mac)
d["dut_mac"]            = str(dut_mac)

with open('config.json', 'w') as outfile:
    json.dump(d, outfile)
