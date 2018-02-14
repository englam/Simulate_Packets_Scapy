'''

packet.summary()
packet.show()


DSCP = Traffic Class
AF11 = 0x28
AF12 = 0x30
AF13 = 0x38
AF21 = 0x48
AF22 = 0x50
AF23 = 0x58
AF31 = 0x68
AF32 = 0x70
AF33 = 0x78
AF41 = 0x88
AF42 = 0x90
AF43 = 0x98

CS0 = 0x00
CS1 = 0x20
CS2 = 0x40
CS3 = 0x60
CS4 = 0x80
CS5 = 0xA0
CS6 = 0xC0
CS7 = 0xE0


IP Precedence
0x20 = IP Precedence 1
0x40 = IP Precedence 2
0x60 = IP Precedence 3
0x80 = IP Precedence 4
0xA0 = IP Precedence 5
0xC0 = IP Precedence 6
0xE0 = IP Precedence 7
'''


from scapy.all import *
from threading import Thread
from queue import Queue



wifi_interface = 'NETGEAR A6210 WiFi USB3.0 Adapter'
local_interface = 'Intel(R) PRO/1000 MT Desktop Adapter #2'

wifi_mac = 'B0:39:56:90:61:40'
local_mac = '08:00:27:D1:D8:DB'
dut_mac = '00:eb:d5:60:1a:20'


class Packets_Receive_Test:
    def __init__(self,wifi_interface,local_interface,wifi_mac,local_mac,dut_mac):
        self.wifi_interface = wifi_interface
        self.local_interface = local_interface

        self.wifi_mac = wifi_mac
        self.local_mac = local_mac
        self.dut_mac = dut_mac

 
    def Packet_Check_Src_MAC(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if packet[0][0].src == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_Dst_MAC(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if packet[0][0].dst == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_Src_IP(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if packet[0][1].src == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)
    
    def Packet_Check_Dst_IP(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if packet[0][1].dst == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_EtherType(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if hex(packet[0][0].type) == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_ToS(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if hex(packet[0][0].tos) == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_Dst_IP(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if packet[0][1].dst == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_EtherType(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if hex(packet[0][0].type) == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_ToS(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if hex(packet[0][0].tos) == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_DSCP_TC(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if hex(packet[0][1].tc) == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_UDP_TCP(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if packet[0][2].dport == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_DSCP_TOS(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if hex(packet[0][1].tos) == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_ARP(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        try:
            for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
                if packet[0][1].psrc == target_stop:
                    out_queue.put(True)
            out_queue.put(False)
        except:
            out_queue.put(False)

    def Packet_Check_test(self,filter_parameter,pc_interface,packet_counts,captured_timeout,target_stop,out_queue):
        for packet in sniff(filter=filter_parameter, iface=pc_interface,count=packet_counts,timeout=captured_timeout):
            print(packet[0][1].psrc)





if __name__ == '__main__':
    #print (Packet_Check_EtherType("icmp and host 192.168.1.245",local_interface,10,10,"0x800"))
    TX_IP = "192.168.1.60"
    RX_IP = "192.168.1.30"
    RX_INTERFACE = 'Intel(R) PRO/1000 MT Desktop Adapter #2'
    
    myqueue = Queue()
    Capture_Packets = Packets_Receive_Test(wifi_interface, local_interface, wifi_mac, local_mac, dut_mac)
    src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP, args=("src %s and dst %s"%(TX_IP, RX_IP), RX_INTERFACE, 50, 30, TX_IP, myqueue,))

    print ("src_ip_check start")
    src_ip_check.start()
    print ("src_ip_check join")
    src_ip_check.join(3)

    fun_value = myqueue.get()
    print (fun_value)

    #sniff(iface=wifi_interface)




