'''
For WAP581 ACL Browser
Author : Englam
Date : 2018/02/02


Usage:

acl_action : deny, permit
acl_type : ipv4, ipv6, mac


ACL_Add_rule(self,acl_name_bind='1',acl_detail_bind='1',acl_name ='acl_1',acl_type='ipv4,sel_interface ='5G',acl_action = 'deny',acl_protocol='1',acl_sip = '1',acl_sport = '1',acl_dip='1',acl_dport='1',acl_tos_type='1')




'''

import time, os, threading, os.path,re
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.common.exceptions import NoSuchElementException
from selenium.common.exceptions import NoAlertPresentException
from selenium.webdriver.support.select import Select
import subprocess as sp
import time, datetime
from selenium.webdriver.support.ui import Select
from bs4 import BeautifulSoup


class Run_Browser(object):
    def __init__(self, select_webdriver):
        self.driver = select_webdriver
        self.driver.implicitly_wait(15)

        self.username = "cisco"
        self.password = "cisco"
        self.url = "https://192.168.1.245"
        

    def login(self):
        self.driver.get(self.url)
        time.sleep(10)
        self.driver.find_element_by_id("login-name").send_keys(self.username)
        self.driver.find_element_by_id("i_password_1").send_keys(self.password)
        self.driver.find_element_by_id("login_button").click()
        time.sleep(3)


    def Access_Control(self):
        time.sleep(3)
        self.driver.find_element_by_xpath('//*[@id="access_control"]/i').click()
        time.sleep(3)
        self.driver.find_element_by_id("acl_rule").click()
        time.sleep(1)

        self.driver.switch_to.frame("basefrm")
        bs4 = BeautifulSoup(self.driver.page_source)
        if bs4.find(id='acl1'):
            self.driver.find_element_by_xpath('//*[@id="aaa"]/th[1]/label').click()
            time.sleep(1)
            self.driver.find_element_by_xpath('//*[@id="viewDeleteButton"]').click()
            time.sleep(1)
            self.driver.find_element_by_xpath('//*[@id="update-container-id"]/table/tbody/tr/td/input').click()
        time.sleep(5)
        self.driver.switch_to.default_content()
        time.sleep(1)

    def ACL_Add_rule(self,acl_name_bind,acl_name,acl_type,sel_interface):
        self.acl_name_bind = acl_name_bind
        self.driver.switch_to.frame("basefrm")
        time.sleep(2)
        self.driver.find_element_by_id('addButton').click()
        time.sleep(2)
        self.driver.find_element_by_id('acl_name%s'%(acl_name_bind)).send_keys(acl_name)
        time.sleep(1)
        select = Select(self.driver.find_element_by_id('acl_type%s'%(acl_name_bind)))
        select.select_by_value(acl_type)
        time.sleep(1)
        self.driver.find_element_by_xpath('//*[@id="addv%s"]/i'%(acl_name_bind)).click()
        time.sleep(2)

        if sel_interface == '5G':
            self.driver.find_element_by_xpath('//*[@id="allvap"]/tbody/tr[1]/td[2]/div/label').click()
        if sel_interface == '2G':
            self.driver.find_element_by_xpath('//*[@id="allvap"]/tbody/tr[2]/td[2]/div/label').click()
        if sel_interface == 'LAN':
            self.driver.find_element_by_xpath('//*[@id="allvap"]/tbody/tr[3]/td[2]/div/label').click()

        time.sleep(2)
        self.driver.find_element_by_id('YesBtn').click()
        time.sleep(1)

        #ACL Detail
        self.driver.find_element_by_id('acl_button%s'%(acl_name_bind)).click()
        time.sleep(2)
        self.driver.switch_to.default_content()
        time.sleep(1)

    def ACL_Detail(self,acl_detail_bind,acl_action,acl_protocol,list_protocol=None,customer_protocol=None,acl_sip=None,sip_single=None,sip_add=None,sip_mask=None,acl_sport=None,sport_list=None,sport_customer=None,acl_dip=None,dip_single=None,dip_add=None,dip_mask=None,acl_dport=None,dport_list=None,dport_customer=None,acl_tos_type=None,dscp_list=None,dscp_value=None,precedence_value=None,tos_value=None,tos_mask=None):
        self.driver.switch_to.frame("basefrm")
        self.driver.find_element_by_xpath('//*[@id="addButton%s"]'%(self.acl_name_bind)).click()
        time.sleep(2)
        #Action, deny, permit
        select = Select(self.driver.find_element_by_id('new_actionipv41_%s'%(acl_detail_bind)))
        select.select_by_value(acl_action)
        time.sleep(2)
        #Protocol, 1 All, 2 list, 3 customer
        select = Select(self.driver.find_element_by_id('ipv4proto_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_protocol)
        time.sleep(2)

        if acl_protocol == '2':
            select = Select(self.driver.find_element_by_id('new_proto_list1_1'))
            select.select_by_value(list_protocol)

        if acl_protocol == '3':
            self.driver.find_element_by_id('new_proto_match1_2').send_keys(customer_protocol)

        time.sleep(1)
        #Source IPv4 Address, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('srcipv4_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_sip)

        if acl_sip == '2':
            self.driver.find_element_by_id('new_src_ip_addr_gingle1_1').send_keys(sip_single)
        if acl_sip == '3':
            self.driver.find_element_by_id('new_src_ip_addr1_1').send_keys(sip_add)
            self.driver.find_element_by_id('new_src_ip_mask1_1').send_keys(sip_mask)
        time.sleep(1)

        #Source Port, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('ipv4port_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_sport)

        if acl_sport == '2':
            self.driver.find_element_by_id('new_src_port_list1_1').send_keys(sport_list)
        if acl_sport == '3':
            self.driver.find_element_by_id('new_src_port_match1_1').send_keys(sport_customer)
        time.sleep(1)

        #Destination IPv4 Address, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('ipv4dst_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_dip)

        if acl_dip == '2':
            self.driver.find_element_by_id('new_dst_ip_addr_single1_1').send_keys(dip_single)
        if acl_dip == '3':
            self.driver.find_element_by_id('new_dst_ip_addr1_1').send_keys(dip_add)
            self.driver.find_element_by_id('new_dst_ip_mask1_1').send_keys(dip_mask)
        time.sleep(1)

        #Destination Port, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('ipv4dstport_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_dport)

        if acl_sport == '2':
            self.driver.find_element_by_id('new_dst_port_list1_1').send_keys(dport_list)
        if acl_sport == '3':
            self.driver.find_element_by_id('new_dst_port_match1_1').send_keys(dport_customer)
        time.sleep(1)

        #ToS Type, 1. Any, 2. list, 3. DSCP, 4. Precedence, 5. ToS Mask
        select = Select(self.driver.find_element_by_id('ipv4type_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_tos_type)

        if acl_tos_type == '2':
            select = Select(self.driver.find_element_by_id('dscp_list1_1'))
            select.select_by_value(dscp_list)
        if acl_tos_type == '3':
            self.driver.find_element_by_id('dscp_value1_1').send_keys(dscp_value)
        if acl_tos_type == '4':
            self.driver.find_element_by_id('precedence_value1_1').send_keys(precedence_value)
        if acl_tos_type == '5':
            self.driver.find_element_by_id('ipTos_value1_1').send_keys(tos_value)
            self.driver.find_element_by_id('ipMask_value1_1').send_keys(tos_mask)
        time.sleep(2)
        self.driver.switch_to.default_content()

    def ACL_Detail_ipv6(self,acl_detail_bind,acl_action,acl_protocol,list_protocol=None,customer_protocol=None,acl_sip=None,sip_single=None,sip_add=None,sip_prefix=None,acl_sport=None,sport_list=None,sport_customer=None,acl_dip=None,dip_single=None,dip_add=None,dip_prefix=None,acl_dport=None,dport_list=None,dport_customer=None,acl_tos_type=None,dscp_list=None,dscp_value=None,flow_label=None,flow_label_dscp=None):
        self.driver.switch_to.frame("basefrm")
        self.driver.find_element_by_xpath('//*[@id="addButton%s"]'%(self.acl_name_bind)).click()
        time.sleep(2)
        #Action, deny, permit
        select = Select(self.driver.find_element_by_id('new_actionipv61_%s'%(acl_detail_bind)))
        select.select_by_value(acl_action)
        time.sleep(2)
        #Protocol, 1 All, 2 list, 3 customer
        select = Select(self.driver.find_element_by_id('ipv6proto_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_protocol)
        time.sleep(2)

        if acl_protocol == '2':
            select = Select(self.driver.find_element_by_id('new_proto_list1_1'))
            select.select_by_value(list_protocol)

        if acl_protocol == '3':
            self.driver.find_element_by_id('new_proto_match1_1').send_keys(customer_protocol)

        time.sleep(1)
        #Source IPv6 Address, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('srcipv6_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_sip)

        if acl_sip == '2':
            self.driver.find_element_by_id('new_src_ipv6_addr_gingle1_1').send_keys(sip_single)
        if acl_sip == '3':
            self.driver.find_element_by_id('new_src_ipv6_addr1_1').send_keys(sip_add)
            self.driver.find_element_by_id('new_src_ipv6_prefix1_1').send_keys(sip_prefix)
        time.sleep(1)

        #Source Port, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('srcipv6por_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_sport)

        if acl_sport == '2':
            self.driver.find_element_by_id('new_src_port_listipv61_1').send_keys(sport_list)
        if acl_sport == '3':
            self.driver.find_element_by_id('new_src_port_matchipv61_1').send_keys(sport_customer)
        time.sleep(1)

        #Destination IPv6 Address, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('dstipv6_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_dip)

        if acl_dip == '2':
            self.driver.find_element_by_id('new_dst_ipv6_addr_single1_1').send_keys(dip_single)
        if acl_dip == '3':
            self.driver.find_element_by_id('new_dst_ipv6_addr1_1').send_keys(dip_add)
            self.driver.find_element_by_id('new_dst_ipv6_prefix1_1').send_keys(dip_prefix)
        time.sleep(1)

        #Destination Port, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('dstipv6port_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_dport)

        if acl_sport == '2':
            self.driver.find_element_by_id('new_dst_port_listipv61_1').send_keys(dport_list)
        if acl_sport == '3':
            self.driver.find_element_by_id('new_dst_port_matchipv61_1').send_keys(dport_customer)
        time.sleep(1)

        #Flow Label, 1 Any, 2, DSCP
        select = Select(self.driver.find_element_by_id('ipv6flow_select1_%s'%(acl_detail_bind)))
        select.select_by_value(flow_label)

        if flow_label == '2':
            self.driver.find_element_by_id('new_ipv6_flow_label1_1').send_keys(flow_label_dscp)


        #ToS Type, 1. Any, 2. list, 3. Customer
        select = Select(self.driver.find_element_by_id('ipv6dscp_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_tos_type)

        if acl_tos_type == '2':
            select = Select(self.driver.find_element_by_id('dscp_listipv61_1'))
            select.select_by_value(dscp_list)
        if acl_tos_type == '3':
            self.driver.find_element_by_id('dscp_valueipv61_1').send_keys(dscp_value)

        time.sleep(2)
        self.driver.switch_to.default_content()

    def ACL_Detail_MAC(self,acl_detail_bind,acl_action,acl_protocol,list_protocol=None,customer_protocol=None,acl_sip=None,sip_single=None,sip_add=None,sip_mask=None,acl_dip=None,dip_single=None,dip_add=None,dip_mask=None,acl_vlan=None,vlan_value=None,acl_cos_type=None,cos_value=None):
        self.driver.switch_to.frame("basefrm")
        self.driver.find_element_by_xpath('//*[@id="addButton%s"]'%(self.acl_name_bind)).click()
        time.sleep(2)
        #Action, deny, permit
        select = Select(self.driver.find_element_by_id('new_actionmac1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_action)
        time.sleep(2)
        #Protocol, 1 All, 2 list, 3 customer
        select = Select(self.driver.find_element_by_id('maceth_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_protocol)
        time.sleep(2)

        if acl_protocol == '2':
            select = Select(self.driver.find_element_by_id('ether_list1_1'))
            select.select_by_value(list_protocol)

        if acl_protocol == '3':
            self.driver.find_element_by_id('ether_match1_1').send_keys(customer_protocol)

        time.sleep(1)
        #Source MAC Address, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('macsrc_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_sip)

        if acl_sip == '2':
            self.driver.find_element_by_id('srcmac_value_gingle1_1').send_keys(sip_single)
        if acl_sip == '3':
            self.driver.find_element_by_id('srcmac_value1_1').send_keys(sip_add)
            self.driver.find_element_by_id('srcmacMask_value1_1').send_keys(sip_mask)
        time.sleep(1)


        #Destination MAC Address, 1 Any, 2 Single Address, 3 Address / Mask
        select = Select(self.driver.find_element_by_id('macdst_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_dip)

        if acl_dip == '2':
            self.driver.find_element_by_id('destmac_value_gingle1_1').send_keys(dip_single)
        if acl_dip == '3':
            self.driver.find_element_by_id('destmac_value1_1').send_keys(dip_add)
            self.driver.find_element_by_id('destmacMask_value1_1').send_keys(dip_mask)
        time.sleep(1)

        #VLAN, 1 Any, 2 Customer
        select = Select(self.driver.find_element_by_id('maclid_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_vlan)

        if acl_vlan == '2':
            self.driver.find_element_by_id('vlan_value1_1').send_keys(vlan_value)

        #COS Type, 1. Any, 2. list, 3. DSCP, 4. Precedence, 5. ToS Mask
        select = Select(self.driver.find_element_by_id('macos_select1_%s'%(acl_detail_bind)))
        select.select_by_value(acl_cos_type)

        if acl_cos_type == '2':
            self.driver.find_element_by_id('cos_value1_1').send_keys(cos_value)

        time.sleep(2)
        self.driver.switch_to.default_content()




    def ACL_Detail_OK_button(self):
        time.sleep(2)
        self.driver.switch_to.frame("basefrm")
        time.sleep(2)
        self.driver.find_element_by_xpath('/html/body/div/form/div/div/div[2]/div/div/div/div[2]/button[1]').click()
        time.sleep(2)
        self.driver.find_element_by_xpath('//*[@id="update-container-id"]/table/tbody/tr/td/input').click()
        time.sleep(5)
        self.driver.switch_to.default_content()
        time.sleep(1)

    def logout(self,close_browser=None):
        self.driver.switch_to.default_content()
        time.sleep(2)
        if not close_browser:
            self.driver.find_element_by_xpath('//*[@id="right"]/a[3]/span[1]').click()
        time.sleep(2)

        self.driver.close()
        self.driver.quit()



class ACL_Test(Run_Browser):
    
    def Add_ACL_Rules_Deny_IP_Permit_All(self,sel_interfaces,acl_types,sip_adds,dip_adds):
        #Test Case 1
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='deny',acl_protocol='1',acl_sip = '3',sip_add=sip_adds,sip_mask='0.0.0.0',acl_sport = '1',acl_dip='3',dip_add=dip_adds,dip_mask='0.0.0.0',acl_dport='1',acl_tos_type='1')
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Deny_ICMP_SIP_DIP_Permit_All(self,sel_interfaces,acl_types,sip_adds,dip_adds):
        #Test Case 2
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='deny',acl_protocol='2',list_protocol='icmp',acl_sip = '3',sip_add=sip_adds,sip_mask='0.0.0.255',acl_sport = '1',acl_dip='3',dip_add=dip_adds,dip_mask='0.0.0.255',acl_dport='1',acl_tos_type='1')
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Deny_IGMP_SIP_DIP_Permit_All(self,sel_interfaces,acl_types,sip_adds):
        #Test Case 3
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='deny',acl_protocol='2',list_protocol='igmp',acl_sip = '3',sip_add=sip_adds,sip_mask='0.0.0.0',acl_sport = '1',acl_dip='3',dip_add='224.0.0.1',dip_mask='0.0.0.0',acl_dport='1',acl_tos_type='1')
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Permit_IGMP_SIP_DIP_Deny_All(self,sel_interfaces,acl_types,sip_adds):
        #Test Case 4
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='permit',acl_protocol='2',list_protocol='igmp',acl_sip = '3',sip_add=sip_adds,sip_mask='0.0.0.0',acl_sport = '1',acl_dip='3',dip_add='230.0.0.1',dip_mask='0.0.0.0',acl_dport='1',acl_tos_type='1')
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Permit_TCP_SPort_DPort_Deny_All(self,sel_interfaces,acl_types,sport_customers,dport_customers):
        #Test Case 5
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='permit',acl_protocol='2',list_protocol='tcp',acl_sip = '1',acl_sport = '3',sport_customer=sport_customers,acl_dip='1',acl_dport='3',dport_customer=dport_customers,acl_tos_type='1')
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Deny_TCP_SPort_DPort_Permit_All(self,sel_interfaces,acl_types,sport_customers,dport_customers):
        #Test Case 6
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='deny',acl_protocol='2',list_protocol='tcp',acl_sip = '1',acl_sport = '3',sport_customer=sport_customers,acl_dip='1',acl_dport='3',dport_customer=dport_customers,acl_tos_type='1')
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Permit_UDP_SPort_DPort_Deny_All(self,sel_interfaces,acl_types,sport_customers,dport_customers):
        #Test Case 7
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='permit',acl_protocol='2',list_protocol='udp',acl_sip = '1',acl_sport = '3',sport_customer=sport_customers,acl_dip='1',acl_dport='3',dport_customer=dport_customers,acl_tos_type='1')
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Deny_UDP_SPort_DPort_Permit_All(self,sel_interfaces,acl_types,sport_customers,dport_customers):
        #Test Case 8
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='deny',acl_protocol='2',list_protocol='udp',acl_sip = '1',acl_sport = '3',sport_customer=sport_customers,acl_dip='1',acl_dport='3',dport_customer=dport_customers,acl_tos_type='1')
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Permit_DSCP_List_Deny_All(self,sel_interfaces,acl_types,dscp_lists):
        #Test Case 9
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='permit',acl_protocol='1',acl_sip = '1',acl_sport = '1',acl_dip='1',acl_dport='1',acl_tos_type='2',dscp_list=dscp_lists)
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Deny_DSCP_List_Permit_All(self,sel_interfaces,acl_types,dscp_lists):
        #Test Case 10
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='deny',acl_protocol='1',acl_sip = '1',acl_sport = '1',acl_dip='1',acl_dport='1',acl_tos_type='2',dscp_list=dscp_lists)
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Deny_IP_Precedence_Permit_All(self,sel_interfaces,acl_types,precedence_values):
        #Test Case 11
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='deny',acl_protocol='1',acl_sip = '1',acl_sport = '1',acl_dip='1',acl_dport='1',acl_tos_type='4',precedence_value=precedence_values)
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Permit_IP_Precedence_Deny_All(self,sel_interfaces,acl_types,precedence_values):
        #Test Case 12
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='permit',acl_protocol='1',acl_sip = '1',acl_sport = '1',acl_dip='1',acl_dport='1',acl_tos_type='4',precedence_value=precedence_values)
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Permit_TOS_Deny_All(self,sel_interfaces,acl_types,tos_values,tos_masks):
        #Test Case 13
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self,acl_name_bind='1',acl_name ='acl_1',acl_type=acl_types,sel_interface =sel_interfaces)
        Run_Browser.ACL_Detail(self,acl_detail_bind='1',acl_action='permit',acl_protocol='1',acl_sip = '1',acl_sport = '1',acl_dip='1',acl_dport='1',acl_tos_type='5',tos_value=tos_values,tos_mask=tos_masks)
        Run_Browser.ACL_Detail(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)


    def Add_ACL_Rules_Permit_IPv6_Deny_All(self, sel_interfaces, acl_types, sip_adds, dip_adds):
        # Test Case 14
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='permit', acl_protocol='1', acl_sip='3',sip_add=sip_adds, sip_prefix='128', acl_sport='1', acl_dip='3', dip_add=dip_adds,dip_prefix='128', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Deny_IPv6_Permit_All(self, sel_interfaces, acl_types, sip_adds, dip_adds):
        # Test Case 15
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='deny', acl_protocol='1', acl_sip='3',sip_add=sip_adds, sip_prefix='128', acl_sport='1', acl_dip='3', dip_add=dip_adds,dip_prefix='128', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Permit_ICMPv6_Deny_All(self, sel_interfaces, acl_types, sip_adds, dip_adds):
        # Test Case 16
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='permit', acl_protocol='2',list_protocol='icmpv6', acl_sip='3',sip_add=sip_adds, sip_prefix='128', acl_sport='1', acl_dip='3', dip_add=dip_adds,dip_prefix='128', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_Deny_ICMPv6_Permit_All(self, sel_interfaces, acl_types, sip_adds, dip_adds):
        # Test Case 17
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='deny', acl_protocol='2',list_protocol='icmpv6', acl_sip='3',sip_add=sip_adds, sip_prefix='128', acl_sport='1', acl_dip='3', dip_add=dip_adds,dip_prefix='128', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_IPv6_Deny_TCP_SPort_DPort_Permit_All(self, sel_interfaces, acl_types, sport_customers, dport_customers):
        # Test Case 18
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='deny', acl_protocol='2',list_protocol='tcp', acl_sip='1', acl_sport='3',sport_customer=sport_customers, acl_dip='1',acl_dport='3',dport_customer=dport_customers, acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_IPv6_Permit_TCP_SPort_DPort_Deny_All(self, sel_interfaces, acl_types, sport_customers, dport_customers):
        # Test Case 19
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='permit', acl_protocol='2',list_protocol='tcp', acl_sip='1', acl_sport='3',sport_customer=sport_customers, acl_dip='1',acl_dport='3',dport_customer=dport_customers, acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_IPv6_Permit_UDP_SPort_DPort_Deny_All(self, sel_interfaces, acl_types, sport_customers, dport_customers):
        # Test Case 20
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='permit', acl_protocol='2',list_protocol='udp', acl_sip='1', acl_sport='3',sport_customer=sport_customers, acl_dip='1',acl_dport='3',dport_customer=dport_customers, acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_IPv6_Deny_UDP_SPort_DPort_Permit_All(self, sel_interfaces, acl_types, sport_customers, dport_customers):
        # Test Case 21
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='deny', acl_protocol='2',list_protocol='udp', acl_sip='1', acl_sport='3',sport_customer=sport_customers, acl_dip='1',acl_dport='3',dport_customer=dport_customers, acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_IPv6_Permit_Flow_Label_Deny_All(self, sel_interfaces, acl_types, flow_label_dscps):
        # Test Case 22
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='permit', acl_protocol='1', acl_sip='1', acl_sport='1', acl_dip='1',acl_dport='1', acl_tos_type='1', flow_label='2',flow_label_dscp=flow_label_dscps)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_IPv6_Deny_Flow_Label_Permit_All(self, sel_interfaces, acl_types, flow_label_dscps):
        # Test Case 23
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='deny', acl_protocol='1', acl_sip='1', acl_sport='1', acl_dip='1',acl_dport='1', acl_tos_type='1', flow_label='2',flow_label_dscp=flow_label_dscps)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_IPv6_Deny_DSCP_Value_Permit_All(self, sel_interfaces, acl_types, dscp_lists):
        # Test Case 24
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='deny', acl_protocol='1', acl_sip='1', acl_sport='1', acl_dip='1',acl_dport='1', acl_tos_type='2',dscp_list=dscp_lists, flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='permit', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)

    def Add_ACL_Rules_IPv6_Permit_DSCP_Value_Deny_All(self, sel_interfaces, acl_types, dscp_lists):
        # Test Case 25
        Run_Browser.login(self)
        Run_Browser.Access_Control(self)
        Run_Browser.ACL_Add_rule(self, acl_name_bind='1', acl_name='acl_1', acl_type=acl_types,sel_interface=sel_interfaces)
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='1', acl_action='permit', acl_protocol='1', acl_sip='1', acl_sport='1', acl_dip='1',acl_dport='1', acl_tos_type='2',dscp_list=dscp_lists, flow_label='1')
        Run_Browser.ACL_Detail_ipv6(self, acl_detail_bind='2', acl_action='deny', acl_protocol='1', acl_sip='1',acl_sport='1', acl_dip='1', acl_dport='1', acl_tos_type='1', flow_label='1')
        Run_Browser.ACL_Detail_OK_button(self)
        Run_Browser.logout(self)
        time.sleep(2)


if __name__ == '__main__':

    ACL = ACL_Test(webdriver.Firefox())
    ACL.Add_ACL_Rules_Deny_IP_Permit_All('2G','ipv4')



