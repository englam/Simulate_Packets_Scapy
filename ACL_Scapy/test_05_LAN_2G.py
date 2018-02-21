import unittest, os, json, time
from modules.Parse_Test_Plan import get_excel_cell, write_excel_cell
from modules.Browser_Wireless import Wireless_Test
from modules.Case_Client_QoS import *
from modules.Browser_ACL import *
from modules.Browser_System_Configuration import System_Configuration_Test
from selenium import webdriver
from modules.Packets_Receive import Packets_Receive_Test
from queue import Queue
from threading import Thread
from scapy.all import *
from scapy.contrib.igmp import IGMP


with open('config.json') as json_data:
    d = json.load(json_data)


test_plan_file      = d['test_plan_file']
test_plan_sheet     = d['lan_sheet']
Wireless_Card       = d['Wireless_Card']
test_version        = d['test_version']

windows_wifi_connection      = "Windows_WLAN_Profiles\wifi_2g_wpa2_connect.bat"
windows_wifi_disconnection   = "Windows_WLAN_Profiles\wifi_2g_disconnect.bat"


RX_IP       = d['lan_ip']
TX_IP       = d['wlan_ip']
RX_IP6      = d['lan_ip6']
TX_IP6      = d['wlan_ip6']
RX_MAC      = d['local_mac']
TX_MAC      = d['wifi_mac']
dut_mac     = d['dut_mac']
RX_INTERFACE    = d['local_interface']
TX_INTERFACE    = d['wifi_interface']

Bind_Interface  = '2G'
Result_Pass     = 'Pass 2.4G'
Result_Fail     = 'Fail 2.4G'

capture_timeout = 20
capture_packets = 20
Test_Plan_FW_Cell       = 'H'
Test_Plan_Result_Cell   = 'L'

class LAN_Client_QoS_2G(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        IPv6 = System_Configuration_Test(webdriver.Firefox())
        IPv6.IPv6_Static_IP("3002::1", "64")
        Wireless1 = Wireless_Test(webdriver.Firefox())
        Wireless1.SSID_Modify_2G("802.11b/g/n","40 MHz","11","wifi_automation_testing_py_2g","wpa","12345678",pri_channels="Upper")
        time.sleep(5)


    def test_LAN_Client_QoS_00(self):
        '''Check Initial traffic between LAN and WLAN'''
        os.system(windows_wifi_connection)
        time.sleep(5)
        packet_queue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE,RX_INTERFACE,TX_MAC,RX_MAC,dut_mac)
        WiFi_To_Local_check = Thread(target=Capture_Packets.Packet_Check_Src_IP, args=("icmp and host %s"%(TX_IP),RX_INTERFACE,capture_timeout,capture_packets,TX_IP,packet_queue,))
        WiFi_To_Local_check.start()
        WiFi_To_Local_check.join(3)
        
        conf.verb = 0
        sendp(Ether(src=TX_MAC,dst=RX_MAC) /IP(src=TX_IP, dst=RX_IP)/ICMP(),count=20,iface=TX_INTERFACE)
        filtered_result = packet_queue.get()
        
        #ICMP Packets from WLAN to LAN
        self.assertTrue(filtered_result)


    def test_LAN_Client_QoS_01(self):
        '''Verify that QoS policy "Send" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Send" is workable.'
        _col,_row=get_excel_cell(test_plan_file,test_plan_sheet,search_keyword)
        self.assertNotEqual(0,_row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_01(Bind_Interface, TX_IP, RX_IP)
        os.system(windows_wifi_connection)
        time.sleep(5)
        
        #Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("icmp and host %s"%(TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        #Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP) / ICMP(), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version, Test_Plan_Result_Cell+str(_row),Result_Pass)

    def test_LAN_Client_QoS_02(self):
        '''Verify that QoS policy "Drop ICMPv4" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop ICMPv4" is workable.'
        _col,_row=get_excel_cell(test_plan_file,test_plan_sheet,search_keyword)
        self.assertNotEqual(0,_row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_02(Bind_Interface, TX_IP, RX_IP)
        os.system(windows_wifi_connection)
        time.sleep(5)
        
        #Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("icmp and host %s"%(TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        #Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP) / ICMP(), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version, Test_Plan_Result_Cell+str(_row),Result_Pass)


    def test_LAN_Client_QoS_03(self):
        '''Verify that QoS policy "IPv6 Mark DSCP" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "IPv6 Mark DSCP" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_03(Bind_Interface, TX_IP6, RX_IP6)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_DSCP_TC,args=("src %s"%(TX_IP6), RX_INTERFACE, 50, 30, "0x28", myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)


    def test_LAN_Client_QoS_04(self):
        '''Verify that QoS policy "ICMPv6 Mark DSCP" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "ICMPv6 Mark DSCP" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_04(Bind_Interface, TX_IP6, RX_IP6)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_DSCP_TC,args=("src %s"%(TX_IP6), RX_INTERFACE, 50, 30, "0x58", myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6) / ICMPv6EchoRequest(), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_05(self):
        '''Verify that QoS policy "IGMP Mark DSCP" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "IGMP Mark DSCP" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_05(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_DSCP_TOS,args=("src %s"%(TX_IP), RX_INTERFACE, 50, 30, 0x48, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0

        sendp(Ether(src=TX_MAC, dst="01:00:5e:00:00:01") / IP(src=TX_IP, dst="224.0.0.1") / IGMP(type=0x11,gaddr="0.0.0.0"),count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_06(self):
        '''Verify that QoS policy "TCP Mark IP Precedence" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "TCP Mark IP Precedence" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_06(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_DSCP_TOS,args=("tcp and src %s"%(TX_IP), RX_INTERFACE, 50, 30, 0x40, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP) / TCP(dport=12345), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_07(self):
        '''Verify that QoS policy "UDP Mark DSCP" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "UDP Mark DSCP" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_07(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_DSCP_TC,args=("udp and src %s"%(TX_IP), RX_INTERFACE, 50, 30, 0x68, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP) / UDP(dport=12345), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_08(self):
        '''Verify that QoS policy "Drop IPv6 TCP" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop IPv6 TCP" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_08(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s"%(TX_IP6), RX_INTERFACE, 50, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6) / TCP(sport=25555,dport=25556), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_09(self):
        '''Verify that QoS policy "Mark IPv6 UDP DSCP" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Mark IPv6 UDP DSCP" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_09(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_DSCP_TC,args=("udp and src %s"%(TX_IP6), RX_INTERFACE, 50, 30, 0x88, myqueue,))

        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6) / UDP(sport=27777,dport=28888), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_10(self):
        '''Verify that QoS policy "Drop IPv6 Flow Label" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop IPv6 Flow Label" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_10(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s"%(TX_IP6,RX_IP6), RX_INTERFACE, 50, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6, fl=0x00001), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_11(self):
        '''Verify that QoS policy "Drop EtherType AppleTalk" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop EtherType AppleTalk" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_11(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_MAC, args=("ether proto 0x809b", RX_INTERFACE, 50, 30, RX_MAC, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC, type=0x809b) / IP(src=TX_IP, dst=RX_IP), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_12(self):
        '''Verify that QoS policy "Drop EtherType ARP" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop EtherType ARP" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_12(Bind_Interface,RX_MAC,TX_MAC)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_ARP, args=("ether src %s"%(TX_MAC), RX_INTERFACE, 50, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=TX_IP, pdst=RX_IP, hwsrc=TX_MAC), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_13(self):
        '''Verify that QoS policy "Drop EtherType IPv4" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop EtherType IPv4" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_13(Bind_Interface,TX_MAC,RX_MAC)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP, args=("src %s and dst %s"%(TX_IP, RX_IP), RX_INTERFACE, 50, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP,dst=RX_IP) , count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_14(self):
        '''Verify that QoS policy "Drop EtherType IPv6" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop EtherType IPv6" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_14(Bind_Interface,TX_MAC,RX_MAC)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP, args=("src %s and dst %s"%(TX_IP6, RX_IP6), RX_INTERFACE, 50, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6,dst=RX_IP6) , count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_15(self):
        '''Verify that QoS policy "Drop EtherType NetBios" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop EtherType NetBios" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_15(Bind_Interface,TX_MAC,RX_MAC)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_MAC, args=("ether proto 0x8191", RX_INTERFACE, 50, 30, RX_MAC, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC, type=0x8191) / IP(src=TX_IP, dst=RX_IP), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_16(self):
        '''Verify that QoS policy "Drop EtherType IPX" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop EtherType IPX" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_16(Bind_Interface,TX_MAC,RX_MAC)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_MAC, args=("ether proto 0x8037", RX_INTERFACE, 50, 30, RX_MAC, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC, type=0x8037) / IP(src=TX_IP, dst=RX_IP), count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    @unittest.skip('LAN PC should enable vlan tag')
    def test_LAN_Client_QoS_17(self):
        '''Verify that QoS policy "Mark of Class Of Service" is workable..(Only supports WLAN to Ethernet.)'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Mark of Class Of Service" is workable..(Only supports WLAN to Ethernet.)'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_17(Bind_Interface,TX_MAC,RX_MAC)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP, args=("src %s and dst %s"%(TX_IP, RX_IP), RX_INTERFACE, 50, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC)/Dot1Q(vlan=1,prio=1) / IP(src=TX_IP,dst=RX_IP) , count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_18(self):
        '''Verify that QoS policy "Drop Mark IP Precedence" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop Mark IP Precedence" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_18(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s"%(TX_IP,RX_IP), RX_INTERFACE, 50, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP,tos=0x60), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_Client_QoS_19(self):
        '''Verify that QoS policy "Drop TOS" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Drop TOS" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_19(Bind_Interface)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s"%(TX_IP,RX_IP), RX_INTERFACE, 50, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP,tos=0xfe), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    @unittest.skip('LAN PC should enable vlan tag')
    def test_LAN_Client_QoS_20(self):
        '''Verify that QoS policy "Mark of Class Of Service with VLAN ID" is workable.'''

        # Test Objectives
        search_keyword = 'Verify that QoS policy "Mark of Class Of Service with VLAN ID" is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Fail)

        Client_QoS_Case_20(Bind_Interface,TX_MAC,RX_MAC)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP, args=("src %s and dst %s"%(TX_IP, RX_IP), RX_INTERFACE, 50, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC)/Dot1Q(vlan=1,prio=1) / IP(src=TX_IP,dst=RX_IP) , count=30,iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)


    @classmethod
    def tearDownClass(cls):
        os.system(windows_wifi_disconnection)


class LAN_ACL_2G(unittest.TestCase):

    """
    @classmethod
    def setUpClass(cls):
        IPv6 = System_Configuration_Test(webdriver.Firefox())
        IPv6.IPv6_Static_IP("3002::1", "64")
        Wireless1 = Wireless_Test(webdriver.Firefox())
        Wireless1.SSID_Modify_2G("802.11b/g/n", "40 MHz", "11", "wifi_automation_testing_py_2g", "wpa", "12345678",
                                 pri_channels="Upper")
        time.sleep(5)
    """

    def test_LAN_ACL_00(self):
        '''Check Initial traffic between LAN and WLAN'''
        os.system(windows_wifi_connection)
        time.sleep(5)
        packet_queue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        WiFi_To_Local_check = Thread(target=Capture_Packets.Packet_Check_Src_IP, args=(
        "icmp and host %s" % (TX_IP), RX_INTERFACE, capture_timeout, capture_packets, TX_IP, packet_queue,))
        WiFi_To_Local_check.start()
        WiFi_To_Local_check.join(3)

        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP) / ICMP(), count=20, iface=TX_INTERFACE)
        filtered_result = packet_queue.get()

        # ICMP Packets from WLAN to LAN
        self.assertTrue(filtered_result)

    def test_LAN_ACL_01(self):
        '''Verify that IPv4 deny src IP to dest IP is workable.'''

        # Test Objectives
        search_keyword = 'Verify that IPv4 deny src IP to dest IP is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_IP_Permit_All(Bind_Interface, 'ipv4',TX_IP,RX_IP)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP,RX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_02(self):
        '''Verify that ICMP deny src IP to dest IP is workable.'''

        # Test Objectives
        search_keyword = 'Verify that ICMP deny src IP to dest IP is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_ICMP_SIP_DIP_Permit_All(Bind_Interface, 'ipv4',TX_IP,RX_IP)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("icmp and src %s" % (TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP)/ICMP(), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_03(self):
        '''Verify that IGMP deny src IP to dest multicast address is workable.'''

        # Test Objectives
        search_keyword = 'Verify that IGMP deny src IP to dest multicast address is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_IGMP_SIP_DIP_Permit_All(Bind_Interface, 'ipv4',TX_IP)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("igmp and src %s" % (TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst="01:00:5e:00:00:01") / IP(src=TX_IP, dst="224.0.0.1") / IGMP(type=0x11,gaddr="0.0.0.0"),count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_04(self):
        '''Verify that IGMP permit src IP to dest multicast address is workable.'''

        # Test Objectives
        search_keyword = 'Verify that IGMP permit src IP to dest multicast address is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Permit_IGMP_SIP_DIP_Deny_All(Bind_Interface, 'ipv4',TX_IP)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("igmp and src %s" % (TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst="01:00:5e:00:00:01") / IP(src=TX_IP, dst="230.0.0.1") / IGMP(type=0x12,gaddr="0.0.0.0"),count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_05(self):
        '''Verify that TCP permit src port to dest port is workable.'''

        # Test Objectives
        search_keyword = 'Verify that TCP permit src port to dest port is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Permit_TCP_SPort_DPort_Deny_All(Bind_Interface, 'ipv4','20000','20001')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("tcp and src %s" % (TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP)/TCP(sport=20000,dport=20001), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_06(self):
        '''Verify that TCP deny src port to dest port is workable.'''

        # Test Objectives
        search_keyword = 'Verify that TCP deny src port to dest port is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_TCP_SPort_DPort_Permit_All(Bind_Interface, 'ipv4','30000','30001')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("tcp and src %s" % (TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP)/TCP(sport=30000,dport=30001), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_07(self):
        '''Verify that UDP permit src port to dest port is workable.'''

        # Test Objectives
        search_keyword = 'Verify that UDP permit src port to dest port is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Permit_UDP_SPort_DPort_Deny_All(Bind_Interface, 'ipv4','50000','50001')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("udp and src %s" % (TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP)/UDP(sport=50000,dport=50001), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_08(self):
        '''Verify that UDP deny src port to dest port is workable.'''

        # Test Objectives
        search_keyword = 'Verify that UDP deny src port to dest port is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_UDP_SPort_DPort_Permit_All(Bind_Interface, 'ipv4','60000','60001')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("udp and src %s" % (TX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP)/UDP(sport=60000,dport=60001), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_09(self):
        '''Verify that DSCP permit any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that DSCP permit any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Permit_DSCP_List_Deny_All(Bind_Interface, 'ipv4','af33')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP,RX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP,tos=0x78), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_10(self):
        '''Verify that DSCP deny any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that DSCP deny any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_DSCP_List_Permit_All(Bind_Interface, 'ipv4','af32')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP,RX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP,tos=0x70), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_11(self):
        '''Verify that deny IP Precedence any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that deny IP Precedence any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_IP_Precedence_Permit_All(Bind_Interface, 'ipv4','7')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP,RX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP,tos=0xe0), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_12(self):
        '''Verify that permit IP Precedence any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that permit IP Precedence any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Permit_IP_Precedence_Deny_All(Bind_Interface, 'ipv4','3')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP,RX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP,tos=0x60), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_13(self):
        '''Verify that permit TOS any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that permit TOS any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Permit_TOS_Deny_All(Bind_Interface, 'ipv4','ff','00')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP,RX_IP), RX_INTERFACE, 30, 30, TX_IP, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IP(src=TX_IP, dst=RX_IP,tos=0xfe), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_14(self):
        '''Verify that permit IPv6 IP to IP is workable.'''

        # Test Objectives
        search_keyword = 'Verify that permit IPv6 IP to IP is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Permit_IPv6_Deny_All(Bind_Interface, 'ipv6', TX_IP6, RX_IP6)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_15(self):
        '''Verify that deny IPv6 IP to IP is workable.'''

        # Test Objectives
        search_keyword = 'Verify that deny IPv6 IP to IP is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_IPv6_Permit_All(Bind_Interface, 'ipv6', TX_IP6, RX_IP6)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_16(self):
        '''Verify that permit ICMPv6 IP to IP is workable.'''

        # Test Objectives
        search_keyword = 'Verify that permit ICMPv6 IP to IP is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Permit_ICMPv6_Deny_All(Bind_Interface, 'ipv6', TX_IP6, RX_IP6)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6)/ ICMPv6EchoRequest(), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_17(self):
        '''Verify that deny ICMPv6 IP to IP is workable.'''

        # Test Objectives
        search_keyword = 'Verify that deny ICMPv6 IP to IP is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_Deny_ICMPv6_Permit_All(Bind_Interface, 'ipv6', TX_IP6, RX_IP6)
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6)/ ICMPv6EchoRequest(), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_18(self):
        '''Verify that deny TCP any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that deny TCP any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_IPv6_Deny_TCP_SPort_DPort_Permit_All(Bind_Interface, 'ipv6', '20001', '20002')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6)/ TCP(sport=20001,dport=20002), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_19(self):
        '''Verify that permit TCP any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that permit TCP any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_IPv6_Permit_TCP_SPort_DPort_Deny_All(Bind_Interface, 'ipv6', '10001', '10002')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6)/ TCP(sport=10001,dport=10002), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_20(self):
        '''Verify that permit UDP any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that permit UDP any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_IPv6_Permit_UDP_SPort_DPort_Deny_All(Bind_Interface, 'ipv6', '30001', '30002')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6)/ UDP(sport=30001,dport=30002), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_21(self):
        '''Verify that deny UDP any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that deny UDP any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_IPv6_Deny_UDP_SPort_DPort_Permit_All(Bind_Interface, 'ipv6', '40001', '40002')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6)/ UDP(sport=40001,dport=40002), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_22(self):
        '''Verify that permit flow label any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that permit flow label any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_IPv6_Permit_Flow_Label_Deny_All(Bind_Interface, 'ipv6', '12345')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6, fl=0x12345), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_23(self):
        '''Verify that deny flow label any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that deny flow label any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_IPv6_Deny_Flow_Label_Permit_All(Bind_Interface, 'ipv6', '23456')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6, fl=0x23456), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_24(self):
        '''Verify that deny DSCP any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that deny DSCP any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_IPv6_Deny_DSCP_Value_Permit_All(Bind_Interface, 'ipv6', 'af43')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6,tc=0x98), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_ACL_25(self):
        '''Verify that permit DSCP any to any is workable.'''

        # Test Objectives
        search_keyword = 'Verify that permit DSCP any to any is workable.'
        _col, _row = get_excel_cell(test_plan_file, test_plan_sheet, search_keyword)
        self.assertNotEqual(0, _row)

        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Fail)

        ACL = ACL_Test(webdriver.Firefox())
        ACL.Add_ACL_Rules_IPv6_Permit_DSCP_Value_Deny_All(Bind_Interface, 'ipv6', 'af32')
        os.system(windows_wifi_connection)
        time.sleep(5)

        # Received Packets
        myqueue = Queue()
        Capture_Packets = Packets_Receive_Test(TX_INTERFACE, RX_INTERFACE, TX_MAC, RX_MAC, dut_mac)
        src_ip_check = Thread(target=Capture_Packets.Packet_Check_Src_IP,args=("src %s and dst %s" % (TX_IP6,RX_IP6), RX_INTERFACE, 30, 30, TX_IP6, myqueue,))
        src_ip_check.start()
        src_ip_check.join(2)
        # Send Packets
        conf.verb = 0
        sendp(Ether(src=TX_MAC, dst=RX_MAC) / IPv6(src=TX_IP6, dst=RX_IP6,tc=0x70), count=30, iface=TX_INTERFACE)

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,
                         Test_Plan_Result_Cell + str(_row), Result_Pass)


    """
    @classmethod
    def tearDownClass(cls):
        os.system(windows_wifi_disconnection)
    """

if __name__=="__main__":
    unittest.main()
