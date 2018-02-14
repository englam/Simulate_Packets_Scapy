from scapy.all import *
conf.verb = 0

'''
p = IP(dst="github.com")/TCP()
r = sr1(p)
print(r.summary())
'''

wifi_interface = 'NETGEAR A6210 WiFi USB3.0 Adapter'
local_interface = 'Intel(R) PRO/1000 MT Desktop Adapter'

wifi_mac = 'B0:39:56:90:61:40'
local_mac = '08:00:27:D1:D8:DB'
dut_mac = '00:eb:d5:60:1a:20'


def get_mac(ip_address):
    responses, unanswered = srp(Ether(src=local_mac,dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)

    # return the MAC address from a response
    for s, r in responses:
        return r[Ether].src

    return None


#ip = Ether(src="B0:39:56:90:61:40",dst="08:00:27:D1:D8:DB")/IP(src="192.168.1.60", dst="192.168.1.30")/ICMP()/"Englam"
#ip = Ether(src=local_mac,dst=wifi_mac)/IP(src="192.168.1.30", dst="192.168.1.60")/ICMP()/"Englam"
#ip2 = IP(src="192.168.1.30", dst="192.168.1.50")/ICMP()

#print (ip.show())
#sendp(ip,iface=local_interface)

#print (ip2.show())
#a = send(ip2)



#responses, unanswered = srp(Ether(src=local_mac,dst=dut_mac) /IP(src="192.168.1.30", dst="192.168.1.245"),timeout=5)
#responses2, unanswered2 = srp(Ether(src=local_mac,dst=wifi_mac) /IP(src="192.168.1.30", dst="192.168.1.50")/ICMP(),timeout=5)
#responses3, unanswered3 = srp(Ether(src=wifi_mac,dst=local_mac) /IP(src="192.168.1.60", dst="192.168.1.30")/ICMP(),timeout=5)

#from wifi to local
#srp(Ether(src=wifi_mac,dst=local_mac) /IP(src="192.168.1.60", dst="192.168.1.30")/ICMP(),timeout=5)
sendp(Ether(src=wifi_mac,dst=local_mac) /IP(src="192.168.1.60", dst="192.168.1.30")/ICMP(),count=10)


#from local to wifi
#srp(Ether(src=local_mac,dst=wifi_mac) /IP(src="192.168.1.30", dst="192.168.1.60")/ICMP(),timeout=5)
#sendp(Ether(src=local_mac,dst=wifi_mac) /IP(src="192.168.1.30", dst="192.168.1.60")/ICMP(),count=5)
#print (responses)


#from local to dut
#srp(Ether(src=local_mac,dst=dut_mac) /IP(src="192.168.1.30", dst="192.168.1.245")/ICMP(),timeout=5)
#sendp(Ether(src=local_mac,dst=dut_mac) /IP(src="192.168.1.30", dst="192.168.1.245")/ICMP(),count=5)


"""
for s, r in responses:
    print("s",s)
    print ("r",r)"""
