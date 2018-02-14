import unittest, os, json, time
from modules.Parse_Test_Plan import get_excel_cell, write_excel_cell
from modules.Browser_Wireless import Wireless_Test
from modules.Case_Client_QoS import *
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

class LAN_2G(unittest.TestCase):

    """
    @classmethod
    def setUpClass(cls):
        IPv6 = System_Configuration_Test(webdriver.Firefox())
        IPv6.IPv6_Static_IP("3002::1", "64")
        Wireless1 = Wireless_Test(webdriver.Firefox())
        Wireless1.SSID_Modify_2G("802.11b/g/n","40 MHz","11","wifi_automation_testing_py_2g","wpa","12345678",pri_channels="Upper")
        time.sleep(5)
    """

    def test_LAN_2G_00(self):
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


    def test_LAN_2G_01(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version, Test_Plan_Result_Cell+str(_row),Result_Pass)

    def test_LAN_2G_02(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version, Test_Plan_Result_Cell+str(_row),Result_Pass)


    def test_LAN_2G_03(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)


    def test_LAN_2G_04(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_05(self):
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

        #Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertTrue(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_06(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_07(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_08(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_09(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_10(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_11(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_12(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_13(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_14(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_15(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)

    def test_LAN_2G_16(self):
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

        Client_QoS_Del_01()

        filtered_Packets = myqueue.get()
        self.assertFalse(filtered_Packets)
        write_excel_cell(test_plan_file, test_plan_sheet, Test_Plan_FW_Cell + str(_row), test_version,Test_Plan_Result_Cell + str(_row), Result_Pass)


    """
    @classmethod
    def tearDownClass(cls):
        os.system(windows_wifi_disconnection)
    """
    
if __name__=="__main__":
    unittest.main()
