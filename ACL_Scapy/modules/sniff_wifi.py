from scapy.all import *
conf.verb = 0



wifi_interface = 'NETGEAR A6210 WiFi USB3.0 Adapter'
local_interface = 'Intel(R) PRO/1000 MT Desktop Adapter #2'

wifi_mac = 'B0:39:56:90:61:40'
local_mac = '08:00:27:D1:D8:DB'
dut_mac = '00:eb:d5:60:1a:20'

 
## Create a Packet Counter
counter = 0
 
## Define our Custom Action function
def custom_action(packet):
    global counter
    counter += 1
    print (packet.show())
    #if packet[0][2].type == 0:
    #return 'Packet #{}: {} ==> {}'.format(counter, packet[0][1].src, packet[0][1].dst)
    #return True

def custom_action_wifi(packet):
    global counter
    counter += 1
    print (packet.summary())
    #if packet[0][2].type == 0:
    #return 'Packet #{}: {} ==> {}'.format(counter, packet[0][1].psrc, packet[0][1].pdst)
    #return True
 
## Setup sniff, filtering for IP traffic
#sniff(filter="ip", prn=custom_action,iface=local_interface)

sniff(filter="host 192.168.1.30",prn=custom_action_wifi,iface=wifi_interface)

#print (b.summary())

"""
for i in b:
    print (i[0][1].src)"""







