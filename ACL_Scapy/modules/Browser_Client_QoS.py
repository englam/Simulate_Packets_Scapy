'''
For Client QoS Browser
Author : Englam
Date : 2018/02/02

Traffic Classes Usage:

For Protocol

protocol:any, source port: any, des port: any
sel_pro_type="0",sel_src_port="0",sel_des_port="0"

protocol: list -> udp, source port: list, http, des port: list, http
sel_pro_type="1", sel_pro_list="udp",sel_src_port="1",sel_des_port="1",sel_src_port_list="http",sel_des_port_list="http"

protocol: customer, 255, source port: any, des port: any, service type: dscp , value 63
sel_pro_type="2",protocol_customer="255",sel_src_port="0",sel_des_port="0",sel_service_type="2",input_dscp_value="63"


For IP

IP: any
sel_src_addr_type="0",sel_dest_addr_type="0"

Single IP:
sel_src_addr_type="1",sel_dest_addr_type="1",input_src_ip_addr="192.168.1.30",input_dest_ip_addr="192.168.1.60"

Ip Mask:
sel_src_addr_type="2",sel_dest_addr_type="2",input_src_ip_addr3="192.168.1.30",input_src_mask_addr="255.255.255.0",input_dest_ip_addr3="192.168.1.60",input_dest_mask_addr="255.255.255.0"




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


    def Client_QoS(self):
        time.sleep(3)
        self.driver.find_element_by_xpath('//*[@id="access_control"]/i').click()
        time.sleep(3)
        self.driver.find_element_by_id("client_qos").click()
        time.sleep(1)

        self.driver.switch_to.frame("basefrm")
        bs4 = BeautifulSoup(self.driver.page_source)

        #QoS Association
        if bs4.find(id="ass_row_1"):

            time.sleep(2)
            self.driver.find_element_by_id('qos_ass').click()
            time.sleep(2)
            self.driver.find_element_by_xpath('//*[@id="ass_theader"]/tr[1]/th[1]/label').click()
            time.sleep(3)
            self.driver.find_element_by_xpath('//*[@id="deleteButton"]').click()
            time.sleep(3)
            self.driver.find_element_by_id('button').click()
            time.sleep(5)

        #QoS Policy
        if bs4.find(id="policymap_row_1"):
            time.sleep(2)
            self.driver.find_element_by_id('qos_policy').click()
            time.sleep(2)
            self.driver.find_element_by_xpath('//*[@id="policymap_row_1"]/td[1]/label').click()
            time.sleep(3)
            self.driver.find_element_by_xpath('//*[@id="policy_map_table"]/div[2]/div/span/div/i[5]').click()
            time.sleep(3)
            self.driver.find_element_by_id('button').click()
            time.sleep(5)

        #QoS classmap
        if bs4.find(id="classmap_row_1"):
            time.sleep(2)
            self.driver.find_element_by_id('qos_class').click()
            time.sleep(2)
            self.driver.find_element_by_xpath('//*[@id="classmap_row_1"]/td[1]/label').click()
            time.sleep(3)
            self.driver.find_element_by_xpath('//*[@id="classes_map_table"]/div[2]/div/span/div/i[5]').click()
            time.sleep(3)
            self.driver.find_element_by_id('button').click()
            time.sleep(5)

        self.driver.switch_to.default_content()

    def Client_QoS_Traffic_Classes_Add_detail(self,class_number,classname,sel_protocol,sel_pro_type,sel_pro_list=None,protocol_customer=None,sel_src_port=None,sel_src_port_list=None,src_port_customer=None,sel_des_port=None,sel_des_port_list=None,des_port_customer=None,sel_service_type=None,sel_dscp_list=None,input_dscp_value=None,input_precedence_value=None,input_ipTos_value=None,input_ipMask_value=None,sel_ipv6_flow_label=None,ipv6_flow_label_customer=None,sel_cos_type=None,mac_cos_value=None,sel_vlan_type=None,mac_vlan_value=None):

        self.driver.switch_to.frame("basefrm")
        time.sleep(2)
        self.driver.find_element_by_id('qos_class').click()
        time.sleep(2)
        self.driver.find_element_by_id('classAddButton').click()
        time.sleep(2)
        self.driver.find_element_by_id('class_name_%s'%(class_number)).send_keys(classname)
        time.sleep(2)

        #select protocol: ipv4, ipv6, mac
        select = Select(self.driver.find_element_by_id('l3_protocol_1'))
        select.select_by_value(sel_protocol)
        time.sleep(2)

        self.driver.find_element_by_id('services_btn_1').click()
        time.sleep(2)
        
        #Protocol select proto type: 0= select all, 1=select from list, 2= custom
        select = Select(self.driver.find_element_by_id('proto_type'))
        select.select_by_value(sel_pro_type)
        time.sleep(2)

        #Source Port
        if sel_pro_type == '1' or sel_pro_type =='2':

            #select protocol, 1=select from list, 2= custom
            if sel_pro_type == '1':
                #sel_pro_list, ip, icmp, igmp, tcp, udp
                select = Select(self.driver.find_element_by_id('proto_list'))
                select.select_by_value(sel_pro_list)
                time.sleep(2)

            if sel_pro_type == '2':
                self.driver.find_element_by_id('proto_match').send_keys(protocol_customer)
                time.sleep(2)

            if sel_protocol != 'mac':
                ###Source Port
                # src port, 0=all , 1=select from list, 2=customer
                select = Select(self.driver.find_element_by_id('src_port_type'))
                select.select_by_value(sel_src_port)
                time.sleep(2)

                ###dest Port
                # des port, 0=all , 1=select from list, 2=customer
                select = Select(self.driver.find_element_by_id('dest_port_type'))
                select.select_by_value(sel_des_port)
                time.sleep(2)

                ###service_type
                # service_type, 0=any , 1=IP DSCP Select from List, 2=IP DSCP Match to Value, 3=IP Precedence, 4=IP TOS Bits/IP TOS Mask
                select = Select(self.driver.find_element_by_id('service_type'))
                select.select_by_value(sel_service_type)
                time.sleep(2)

            #src port list, ftp, ftpdata, http, smtp, snmp, telnet, tftp, www
            if sel_src_port == '1':
                select = Select(self.driver.find_element_by_id('src_port_list'))
                select.select_by_value(sel_src_port_list)
                time.sleep(2)

            #src port customer
            if sel_src_port == '2':
                self.driver.find_element_by_id('src_port_match').send_keys(src_port_customer)
                time.sleep(2)



            #src port list, ftp, ftpdata, http, smtp, snmp, telnet, tftp, www
            if sel_des_port == '1':
                select = Select(self.driver.find_element_by_id('dest_port_list'))
                select.select_by_value(sel_des_port_list)
                time.sleep(2)

            #src port customer
            if sel_des_port == '2':
                self.driver.find_element_by_id('dest_port_match').send_keys(des_port_customer)
                time.sleep(2)

            ###Flow Label
            if sel_protocol == 'ipv6':
                if sel_ipv6_flow_label == '1':
                    select = Select(self.driver.find_element_by_id('ipv6_flow_label'))
                    select.select_by_value(sel_ipv6_flow_label)
                    time.sleep(2)
                    self.driver.find_element_by_id('new_ipv6_flow_label').send_keys(ipv6_flow_label_customer)
                    time.sleep(2)

            ###MAC Ethertype
            if sel_protocol == 'mac':
                if sel_cos_type == '1':
                    select = Select(self.driver.find_element_by_id('cos_type'))
                    select.select_by_value(sel_cos_type)
                    time.sleep(2)
                    self.driver.find_element_by_id('cos_value').send_keys(mac_cos_value) #0-7
                    time.sleep(2)
                if sel_vlan_type == '1':
                    select = Select(self.driver.find_element_by_id('vlanid_type'))
                    select.select_by_value(sel_vlanid_type)
                    time.sleep(2)
                    self.driver.find_element_by_id('vlan_value').send_keys(mac_vlan_value) #1-4094
                    time.sleep(2)




            #service type = 1=IP DSCP Select from List
            if sel_service_type == '1':
                # af11 check GUI
                select = Select(self.driver.find_element_by_id('dscp_list'))
                select.select_by_value(sel_dscp_list)
                time.sleep(2)

            #service type = 2=IP DSCP Match to Value
            if sel_service_type == '2':
                self.driver.find_element_by_id('dscp_value').send_keys(input_dscp_value)
                time.sleep(2)

            #service type = 3=IP Precedence
            if sel_service_type == '3':
                self.driver.find_element_by_id('precedence_value').send_keys(input_precedence_value)
                time.sleep(2)

            #service type = 4=IP TOS Bits/IP TOS Mask
            if sel_service_type == '4':
                self.driver.find_element_by_id('ipTos_value').send_keys(input_ipTos_value)
                time.sleep(1)
                self.driver.find_element_by_id('ipMask_value').send_keys(input_ipMask_value)
                time.sleep(1)




        self.driver.find_element_by_id('YesBtn').click()
        time.sleep(2)

    def Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type,sel_dest_addr_type,input_src_ip_addr=None,input_src_ip_addr3=None,input_src_mask_addr=None,input_dest_ip_addr=None,input_dest_ip_addr3=None,input_dest_mask_addr=None):
        ## Source Address
        # 0 = any, 1=single, 2=address mask
        if not sel_dest_addr_type == '0':
            select = Select(self.driver.find_element_by_id('src_addr_type_1'))
            select.select_by_value(sel_src_addr_type)
            
        if sel_src_addr_type == '1':
            self.driver.find_element_by_id('src_ip_addr2_1').send_keys(input_src_ip_addr)
            time.sleep(2)

        if sel_src_addr_type == '2':
            self.driver.find_element_by_id('src_ip_addr3_1').send_keys(input_src_ip_addr3)
            time.sleep(2)
            self.driver.find_element_by_id('src_mask_addr_1').send_keys(input_src_mask_addr)
            time.sleep(2)

        ## Destination Address
        # 0 = any, 1=single, 2=address mask
        if not sel_dest_addr_type == '0':
            select = Select(self.driver.find_element_by_id('dest_addr_type_1'))
            select.select_by_value(sel_dest_addr_type)

        if sel_dest_addr_type == '1':
            self.driver.find_element_by_id('dest_ip_addr2_1').send_keys(input_dest_ip_addr)
            time.sleep(2)

        if sel_dest_addr_type == '2':
            self.driver.find_element_by_id('dest_ip_addr3_1').send_keys(input_dest_ip_addr3)
            time.sleep(2)
            self.driver.find_element_by_id('dest_mask_addr_1').send_keys(input_dest_mask_addr)
            time.sleep(2)

        self.driver.find_element_by_id('button').click()
        time.sleep(3)
        self.driver.switch_to.default_content()



    def Client_QoS_Policy_Add(self,policy_number,policyname,policy_interface,send_action,remark_traffic,cos_value=None,dscp_value=None,ip_precedence_value=None):
        self.driver.switch_to.frame("basefrm")
        self.driver.find_element_by_id('qos_policy').click()
        time.sleep(2)
        self.driver.find_element_by_xpath('//*[@id="policyAddButton"]').click()
        time.sleep(2)
        self.driver.find_element_by_id('policy_name_%s'%(policy_number)).send_keys(policyname)
        time.sleep(2)
        select = Select(self.driver.find_element_by_id('class_list_1_0'))
        select.select_by_value("c%s"%(policy_interface))
        time.sleep(1)
        self.driver.find_element_by_id('rate_1_0').send_keys("1000")
        time.sleep(1)
        self.driver.find_element_by_id('burst_1_0').send_keys("1000000")
        time.sleep(1)

        #send_action = send , drop
        select = Select(self.driver.find_element_by_id('action_list_1_0'))
        select.select_by_value(send_action)

        #remark traffic = cos, dscp, ip-precedence
        if send_action =="send":
            select = Select(self.driver.find_element_by_id('remark_list_1_0'))
            select.select_by_value(remark_traffic)

            if remark_traffic =="cos":
                self.driver.find_element_by_id('remark_cos_1_0').send_keys(cos_value)

            if remark_traffic =="dscp":
                select = Select(self.driver.find_element_by_id('remark_dscp_1_0'))
                select.select_by_value(dscp_value)
                
            if remark_traffic =="ip-precedence":
                self.driver.find_element_by_id('remark_pre_1_0').send_keys(ip_precedence_value)


        self.driver.find_element_by_id('button').click()
        time.sleep(3)
        self.driver.switch_to.default_content()


    def Client_QoS_Association_Add(self,sel_interface):
        self.driver.switch_to.frame("basefrm")
        self.driver.find_element_by_id('qos_ass').click()
        time.sleep(2)
        self.driver.find_element_by_xpath('//*[@id="assAddButton"]').click()
        time.sleep(2)

        #interface,  5G = wlan0vap0, 2G = wlan1vap0, LAN = eth0
        select = Select(self.driver.find_element_by_id('interface_4'))
        select.select_by_value(sel_interface)
        time.sleep(1)
        if sel_interface != 'eth0':
            self.driver.find_element_by_id('def_bwmax_down_4').send_keys("1000")
            time.sleep(1)
            self.driver.find_element_by_id('def_bwmax_up_4').send_keys("1000")
            time.sleep(1)

        self.driver.find_element_by_id('button').click()
        time.sleep(3)
        self.driver.switch_to.default_content()

    def logout(self,close_browser=None):
        self.driver.switch_to.default_content()
        time.sleep(2)
        if not close_browser:
            self.driver.find_element_by_xpath('//*[@id="right"]/a[3]/span[1]').click()
        time.sleep(2)

        self.driver.close()
        self.driver.quit()





class Client_QoS_Test(Run_Browser):
    
    def Add_Traffic_Classes_IPv4_AllTraffic(self,class_numbers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)
        
    def Add_Traffic_Classes_IPv4_Protocol_IP_Any(self,class_numbers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="1",sel_pro_list="ip",sel_src_port="0",sel_des_port="0",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)

    def Add_Traffic_Classes_IPv4_Protocol_IGMP_Any(self,class_numbers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="1",sel_pro_list="igmp",sel_src_port="0",sel_des_port="0",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)

    def Add_Traffic_Classes_IPv4_Protocol_TCP_Any(self,class_numbers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="1",sel_pro_list="tcp",sel_src_port="0",sel_des_port="0",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)

    def Add_Traffic_Classes_IPv4_Protocol_UDP_Any(self,class_numbers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="1",sel_pro_list="udp",sel_src_port="0",sel_des_port="0",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)

    def Add_Traffic_Classes_IPv4_Protocol_ICMP_Src_Port_http_Des_Port_http(self,class_numbers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="1",sel_pro_list="icmp",sel_src_port="1",sel_des_port="1",sel_src_port_list="http",sel_des_port_list="http",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)


    def Add_Traffic_Classes_IPv4_Protocol_UDP_Src_Port_http_Des_Port_http_SIP_DIP(self,class_numbers,input_src_ip,input_dest_ip):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="1",sel_pro_list="udp",sel_src_port="1",sel_des_port="1",sel_src_port_list="http",sel_des_port_list="http",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="1",sel_dest_addr_type="1",input_src_ip_addr=input_src_ip,input_dest_ip_addr=input_dest_ip)
        time.sleep(5)


    def Add_Traffic_Classes_IPv4_Protocol_Customer_DHCP_Value_SIP_Mask_DIP_Mask(self,class_numbers,input_src_ip,input_src_mask,input_dest_ip,input_dest_mask):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="2",protocol_customer="255",sel_src_port="0",sel_des_port="0",sel_service_type="2",input_dscp_value="63")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="2",sel_dest_addr_type="2",input_src_ip_addr3=input_src_ip,input_src_mask_addr=input_src_mask,input_dest_ip_addr3=input_dest_ip,input_dest_mask_addr=input_dest_mask)
        time.sleep(5)

    def Add_Traffic_Classes_IPv4_Protocol_UDP_SIP_Mask_DIP_Mask(self,class_numbers,input_src_ip,input_src_mask,input_dest_ip,input_dest_mask):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="1",sel_pro_list="udp",sel_src_port="0",sel_des_port="0",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="2",sel_dest_addr_type="2",input_src_ip_addr3=input_src_ip,input_src_mask_addr=input_src_mask,input_dest_ip_addr3=input_dest_ip,input_dest_mask_addr=input_dest_mask)
        time.sleep(5)

    def Add_Traffic_Classes_IPv4_Protocol_ICMP_SIP_Mask_DIP_Mask(self,class_numbers,input_src_ip,input_src_mask,input_dest_ip,input_dest_mask):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv4",sel_pro_type="1",sel_pro_list="icmp",sel_src_port="0",sel_des_port="0",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="2",sel_dest_addr_type="2",input_src_ip_addr3=input_src_ip,input_src_mask_addr=input_src_mask,input_dest_ip_addr3=input_dest_ip,input_dest_mask_addr=input_dest_mask)
        time.sleep(5)

    def Add_Traffic_Classes_IPv6_Protocol_TCP_SPort_DPort(self,class_numbers,src_port_customers,des_port_customers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv6",sel_pro_type="1",sel_pro_list="tcp",sel_src_port="2",src_port_customer=src_port_customers,sel_des_port="2",des_port_customer=des_port_customers,sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)

    def Add_Traffic_Classes_IPv6_Protocol_Flow_Label_Any(self,class_numbers,ipv6_flow_label_customers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv6",sel_pro_type="1",sel_pro_list="ipv6",sel_src_port="0",sel_des_port="0",sel_service_type="0",sel_ipv6_flow_label="1",ipv6_flow_label_customer=ipv6_flow_label_customers)
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)

    def Add_Traffic_Classes_IPv6_Protocol_UDP_SPort_DPort(self,class_numbers,src_port_customers,des_port_customers):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv6",sel_pro_type="1",sel_pro_list="udp",sel_src_port="2",src_port_customer=src_port_customers,sel_des_port="2",des_port_customer=des_port_customers,sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)

    def Add_Traffic_Classes_IPv6_Protocol_IP_DHCP_List_SIP_Mask_DIP_Mask(self,class_numbers,input_src_ip,input_src_mask,input_dest_ip,input_dest_mask):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv6",sel_pro_type="1",sel_pro_list="ipv6",sel_src_port="0",sel_des_port="0",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="2",sel_dest_addr_type="2",input_src_ip_addr3=input_src_ip,input_src_mask_addr=input_src_mask,input_dest_ip_addr3=input_dest_ip,input_dest_mask_addr=input_dest_mask)
        time.sleep(5)

    def Add_Traffic_Classes_IPv6_Protocol_ICMPv6_DHCP_List_SIP_Mask_DIP_Mask(self,class_numbers,input_src_ip,input_src_mask,input_dest_ip,input_dest_mask):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="ipv6",sel_pro_type="1",sel_pro_list="icmpv6",sel_src_port="0",sel_des_port="0",sel_service_type="0")
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="2",sel_dest_addr_type="2",input_src_ip_addr3=input_src_ip,input_src_mask_addr=input_src_mask,input_dest_ip_addr3=input_dest_ip,input_dest_mask_addr=input_dest_mask)
        time.sleep(5)

    def Add_Traffic_Classes_MAC_Ethertype_List_Any(self,class_numbers,sel_pro_lists,mac_cos_values,sel_vlan_types,mac_vlan_values):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="mac",sel_pro_type="1",sel_pro_list=sel_pro_lists,sel_cos_type='1',mac_cos_value=mac_cos_values,sel_vlan_type=sel_vlan_types,mac_vlan_value=mac_vlan_values)
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="0",sel_dest_addr_type="0")
        time.sleep(5)

    def Add_Traffic_Classes_MAC_Ethertype_List_SMAC_DMAC(self,class_numbers,sel_pro_lists,input_src_mac,input_dest_mac):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="mac",sel_pro_type="1",sel_pro_list=sel_pro_lists)
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="1",sel_dest_addr_type="1",input_src_ip_addr=input_src_mac,input_dest_ip_addr=input_dest_mac)
        time.sleep(5)

    def Add_Traffic_Classes_MAC_Ethertype_List_SMAC_SMask_DMAC_DMask(self,class_numbers,sel_pro_lists,input_src_mac,input_src_mac_mask,input_dest_mac,input_dest_mac_mask):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        Run_Browser.Client_QoS_Traffic_Classes_Add_detail(self,class_number=class_numbers,classname="class_1",sel_protocol="mac",sel_pro_type="1",sel_pro_list=sel_pro_lists)
        Run_Browser.Client_QoS_Traffic_Classes_Add_address(self,sel_src_addr_type="2",sel_dest_addr_type="2",input_src_ip_addr3=input_src_mac,input_src_mask_addr=input_src_mac_mask,input_dest_ip_addr3=input_dest_mac,input_dest_mask_addr=input_dest_mac_mask)
        time.sleep(5)

    def Add_QoS_Policy_COS(self,policy_numbers,send_actions,policynames,policy_interfaces,cos_values):
        Run_Browser.Client_QoS_Policy_Add(self,policy_number=policy_numbers,policyname=policynames,policy_interface=policy_interfaces,send_action=send_actions,remark_traffic="cos",cos_value=cos_values)
        time.sleep(2)

    def Add_QoS_Policy_DSCP(self,policy_numbers,send_actions,policynames,policy_interfaces,dscp_values):
        Run_Browser.Client_QoS_Policy_Add(self,policy_number=policy_numbers,policyname=policynames,policy_interface=policy_interfaces,send_action=send_actions,remark_traffic="dscp",dscp_value=dscp_values)
        time.sleep(2)

    def Add_QoS_Policy_IP_Precedence(self,policy_numbers,send_actions,policynames,policy_interfaces,ip_precedence_values):
        Run_Browser.Client_QoS_Policy_Add(self,policy_number=policy_numbers,policyname=policynames,policy_interface=policy_interfaces,send_action=send_actions,remark_traffic="ip-precedence",ip_precedence_value=ip_precedence_values)
        time.sleep(2)

    def Add_QoS_Association(self,select_interface):
        #interface,  5G = wlan0vap0, 2G = wlan1vap0, LAN = eth0
        if select_interface == "5G":
            select_interface = "wlan0vap0"
            
        if select_interface == "2G":
            select_interface = "wlan1vap0"
            
        if select_interface == "LAN":
            select_interface = "eth0"
            
        Run_Browser.Client_QoS_Association_Add(self,select_interface)
        Run_Browser.logout(self)
        time.sleep(2)

    def Del_Traffic_Classes_1(self):
        self.driver.switch_to.frame("basefrm")
        time.sleep(2)
        self.driver.find_element_by_id('qos_class').click()
        time.sleep(2)
        self.driver.find_element_by_xpath('//*[@id="classmap_row_1"]/td[1]/label').click()
        time.sleep(3)
        self.driver.find_element_by_xpath('//*[@id="classes_map_table"]/div[2]/div/span/div/i[5]').click()
        time.sleep(3)
        self.driver.find_element_by_id('button').click()
        time.sleep(5)

        self.driver.switch_to.default_content()
        Run_Browser.logout(self)
        time.sleep(2)


    def Del_Policy_1(self):
        self.driver.switch_to.frame("basefrm")
        time.sleep(2)
        self.driver.find_element_by_id('qos_policy').click()
        time.sleep(2)
        self.driver.find_element_by_xpath('//*[@id="policymap_row_1"]/td[1]/label').click()
        time.sleep(3)
        self.driver.find_element_by_xpath('//*[@id="policy_map_table"]/div[2]/div/span/div/i[5]').click()
        time.sleep(3)
        self.driver.find_element_by_id('button').click()
        time.sleep(5)

        self.driver.switch_to.default_content()

        
    def Del_QoS_Association_1(self):
        Run_Browser.login(self)
        Run_Browser.Client_QoS(self)
        self.driver.switch_to.frame("basefrm")
        time.sleep(2)
        self.driver.find_element_by_id('qos_ass').click()
        time.sleep(2)
        self.driver.find_element_by_xpath('//*[@id="ass_theader"]/tr[1]/th[1]/label').click()
        time.sleep(3)
        self.driver.find_element_by_xpath('//*[@id="deleteButton"]').click()
        time.sleep(3)
        self.driver.find_element_by_id('button').click()
        time.sleep(5)

        self.driver.switch_to.default_content()









if __name__ == '__main__':

    #Client_QoS = Client_QoS_Test(webdriver.Firefox())
    #Client_QoS.Add_Traffic_Classes_IPv4_AllTraffic()

    #Client_QoS2 = Client_QoS_Test(webdriver.Firefox())
    #Client_QoS2.Add_Traffic_Classes_IPv4_IP("1")
    #Client_QoS2.Add_Traffic_Classes_IPv4_AllTraffic("1")
    #Client_QoS2.Add_QoS_Policy("1","drop","policy_1","1")
    #Client_QoS2.Add_QoS_Association("2G")

    Client_QoS3 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS3.Add_Traffic_Classes_IPv4_Protocol_ICMP_Src_Port_http_Des_Port_http("1")
    Client_QoS3.Add_QoS_Policy("1","send","policy_1","1")
    Client_QoS3.Add_QoS_Association("5G")
    #Add_Traffic_Classes_IPv4_Protocol_UDP_SIP_Mask_DIP_Mask
    #Client_QoS4 = Client_QoS_Test(webdriver.Firefox())
    #Client_QoS4.Add_Traffic_Classes_IPv4_Protocol_UDP_Src_Port_http_Des_Port_http_SIP_DIP()

    #Client_QoS5 = Client_QoS_Test(webdriver.Firefox())
    #Client_QoS5.Add_Traffic_Classes_IPv4_Protocol_Customer_DHCP_Value_SIP_Mask_DIP_Mask()

    #Client_QoS6 = Client_QoS_Test(webdriver.Firefox())
    #Client_QoS6.Add_Traffic_Classes_IPv4_AllTraffic("1")
    #Client_QoS6.Add_QoS_Policy("1","drop","policy_1","1")
    #Client_QoS6.Add_QoS_Association("2G")


    Client_QoS99 = Client_QoS_Test(webdriver.Firefox())
    Client_QoS99.Del_QoS_Association_1()
    Client_QoS99.Del_Policy_1()
    Client_QoS99.Del_Traffic_Classes_1()
