'''
For Wireless Browser
Author : Englam
Date : 2018/02/02


Usage:


# 5G, No Security, Channel 36, 802.11a, 20 MHz
Wireless1 = Wireless_Test(webdriver.Firefox())
Wireless1.SSID_Modify_5G("802.11a","20 MHz","36","wifi_automation_testing_5g")

# 5G, WPA, 12345678, Channel 36, 802.11a/n/ac, 40 MHz
Wireless2 = Wireless_Test(webdriver.Firefox())
Wireless2.SSID_Modify_5G("802.11a/n/ac","40 MHz","36","wifi_automation_testing_5g","wpa","12345678",pri_channels="Lower")

Wireless3 = Wireless_Test(webdriver.Firefox())
Wireless3.SSID_Modify_2G("802.11b/g/n","40 MHz","1","wifi_automation_testing_2g","wpa","12345678",pri_channels="Lower")

Wireless4 = Wireless_Test(webdriver.Firefox())
Wireless4.SSID_Modify_2G("802.11b/g","40 MHz","Auto","wifi_automation_testing_2g")


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


    def System_Configuration(self):
        time.sleep(3)
        self.driver.find_element_by_xpath('/html/body/form/div[2]/div[2]/div[2]/div[1]/a').click()
        time.sleep(3)
        
    def LAN_Static_IPv6(self,ipv6_address,ipv6_mask):
        self.driver.find_element_by_id("lan").click()
        time.sleep(10)
        self.driver.switch_to.frame("basefrm")
        time.sleep(1)
        self.driver.find_element_by_xpath('//*[@id="ipv6_sets"]/tbody/tr[2]/td[2]/span/div[2]/label').click()
        time.sleep(2)
        self.driver.find_element_by_id("ip6addr").clear()
        time.sleep(1)
        self.driver.find_element_by_id("ip6addr").send_keys(ipv6_address)
        time.sleep(1)
        self.driver.find_element_by_id("ip6addr-prefix").clear()
        time.sleep(1)
        self.driver.find_element_by_id("ip6addr-prefix").send_keys(ipv6_mask)
        time.sleep(1)
        self.driver.find_element_by_id("button").click()
        self.driver.switch_to.default_content()
        try:
            self.driver.find_element_by_id('YesBtn').click()
        except:
            pass

        time.sleep(30)

    def logout(self,close_browser=None):
        self.driver.switch_to.default_content()
        time.sleep(2)
        if not close_browser:
            self.driver.find_element_by_xpath('//*[@id="right"]/a[3]/span[1]').click()
        time.sleep(2)

        self.driver.close()
        self.driver.quit()


class System_Configuration_Test(Run_Browser):
    
    def IPv6_Static_IP(self,ipv6_addresss,ipv6_masks):
        Run_Browser.login(self)
        Run_Browser.System_Configuration(self)
        Run_Browser.LAN_Static_IPv6(self,ipv6_addresss,ipv6_masks)
        time.sleep(2)
        Run_Browser.logout(self)
        time.sleep(2)













if __name__ == '__main__':

    IPv6 = System_Configuration_Test(webdriver.Firefox())
    IPv6.IPv6_Static_IP("3002::2","64")


