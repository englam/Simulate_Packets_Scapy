from Browser_Client_QoS import Client_QoS_Test
from selenium import webdriver

def Client_QoS_Case_01(select_interface,select_ip1,select_ip2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv4_Protocol_UDP_SIP_Mask_DIP_Mask("1", select_ip1, "255.255.255.255", select_ip2,
                                                                        "255.255.255.255")
    Client_QoS3.Add_QoS_Policy_COS("1", "send", "policy_1", "1","1")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_02(select_interface,select_ip1,select_ip2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv4_Protocol_ICMP_SIP_Mask_DIP_Mask("1", select_ip1, "255.255.255.255", select_ip2,
                                                                        "255.255.255.255")
    Client_QoS3.Add_QoS_Policy_COS("1", "drop", "policy_1", "1","1")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_03(select_interface,select_ip1,select_ip2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv6_Protocol_IP_DHCP_List_SIP_Mask_DIP_Mask("1", select_ip1, "128", select_ip2,
                                                                        "128")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "send", "policy_1", "1","af11")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_04(select_interface,select_ip1,select_ip2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv6_Protocol_ICMPv6_DHCP_List_SIP_Mask_DIP_Mask("1", select_ip1, "128", select_ip2,"128")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "send", "policy_1", "1","af23")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_05(select_interface):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv4_Protocol_IGMP_Any("1")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "send", "policy_1", "1","af21")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_06(select_interface):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv4_Protocol_TCP_Any("1")
    Client_QoS3.Add_QoS_Policy_IP_Precedence("1", "send", "policy_1", "1","2")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_07(select_interface):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv4_Protocol_UDP_Any("1")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "send", "policy_1", "1", "af31")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_08(select_interface):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv6_Protocol_TCP_SPort_DPort("1","25555","25556")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "drop", "policy_1", "1", "af31")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_09(select_interface):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv6_Protocol_UDP_SPort_DPort("1","27777","28888")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "send", "policy_1", "1", "af41")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_10(select_interface):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv6_Protocol_Flow_Label_Any("1","00001")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "drop", "policy_1", "1", "af41")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_11(select_interface):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_MAC_Ethertype_List_Any("1","appletalk","0","0","1")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "drop", "policy_1", "1", "af41")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_12(select_interface,sel_mac1,sel_mac2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_MAC_Ethertype_List_SMAC_DMAC("1","arp",sel_mac1,sel_mac2)
    Client_QoS3.Add_QoS_Policy_DSCP("1", "drop", "policy_1", "1", "af41")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_13(select_interface,sel_mac1,sel_mac2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_MAC_Ethertype_List_SMAC_SMask_DMAC_DMask("1","ipv4",sel_mac1,"ff:ff:ff:ff:ff:ff",sel_mac2,"ff:ff:ff:ff:ff:ff")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "drop", "policy_1", "1", "af41")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_14(select_interface,sel_mac1,sel_mac2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_MAC_Ethertype_List_SMAC_SMask_DMAC_DMask("1","ipv6",sel_mac1,"ff:ff:ff:ff:ff:ff",sel_mac2,"ff:ff:ff:ff:ff:ff")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "drop", "policy_1", "1", "af41")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_15(select_interface,sel_mac1,sel_mac2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_MAC_Ethertype_List_SMAC_SMask_DMAC_DMask("1","netbios",sel_mac1,"ff:ff:ff:ff:ff:ff",sel_mac2,"ff:ff:ff:ff:ff:ff")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "drop", "policy_1", "1", "af41")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Case_16(select_interface,sel_mac1,sel_mac2):
    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_MAC_Ethertype_List_SMAC_SMask_DMAC_DMask("1","ipx",sel_mac1,"ff:ff:ff:ff:ff:ff",sel_mac2,"ff:ff:ff:ff:ff:ff")
    Client_QoS3.Add_QoS_Policy_DSCP("1", "drop", "policy_1", "1", "af41")
    Client_QoS3.Add_QoS_Association(select_interface)

def Client_QoS_Del_01():
    Client_QoS99 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS99.Del_QoS_Association_1()
    Client_QoS99.Del_Policy_1()
    Client_QoS99.Del_Traffic_Classes_1()


if __name__ == '__main__':
    wlan_ip6 = "3002::60"
    lan_ip6 = "3002::30"
    mac1 = "00:00:00:00:00:01"
    mac2 = "00:00:00:00:00:02"
    #Client_QoS_Case_04("2G", wlan_ip6, lan_ip6)
    Client_QoS_Case_15("2G", mac1, mac2)
