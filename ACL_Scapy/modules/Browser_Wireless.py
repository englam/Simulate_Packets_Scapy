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


    def Wireless(self):
        time.sleep(3)
        self.driver.find_element_by_xpath('//*[@id="wireless"]/i').click()
        
    def Wireless_Radio_5G(self,wifi_mode,wifi_band,wifi_channel,pri_channel=None):
        self.driver.find_element_by_id("radio").click()
        time.sleep(10)
        self.driver.switch_to.frame("basefrm")
        time.sleep(1)
        self.driver.find_element_by_id('wlan_tab_1').click()
        time.sleep(2)
        
        #wifi mode, 802.11a , 802.11a/n/ac, 802.11n/ac
        select = Select(self.driver.find_element_by_id('radio.wlan0.mode'))
        select.select_by_value(wifi_mode)

        #wifi band, 20 MHz , 40 MHz, 80 MHz
        if wifi_mode != "802.11a":
            select = Select(self.driver.find_element_by_id('radio.wlan0.n-bandwidth'))
            select.select_by_value(wifi_band)

        #primary channel
        if wifi_mode =="802.11a/n/ac":

            GUI_Primary_Channel = self.driver.find_element_by_id('radio.wlan0.n-primary-channel').get_attribute('value')
            time.sleep(1)
            if GUI_Primary_Channel == "Lower":
                select = Select(self.driver.find_element_by_id('radio.wlan0.channel'))
                select.select_by_value("36")

            if GUI_Primary_Channel == "Upper":
                select = Select(self.driver.find_element_by_id('radio.wlan0.channel'))
                select.select_by_value("40")
                
            time.sleep(3)
            
            select = Select(self.driver.find_element_by_id('radio.wlan0.n-primary-channel'))
            select.select_by_value(pri_channel)

        #wifi Channels, Auto, 36, 40...
        select = Select(self.driver.find_element_by_id('radio.wlan0.channel'))
        select.select_by_value(wifi_channel)

        self.driver.find_element_by_id('button').click()
        time.sleep(2)
        self.driver.switch_to.default_content()
        try:
            self.driver.find_element_by_id('YesBtn').click()
        except:
            pass

        time.sleep(30)
        



    def Wireless_Radio_2G(self,wifi_mode,wifi_band,wifi_channel,pri_channel=None):
        self.driver.find_element_by_id("radio").click()
        time.sleep(10)
        self.driver.switch_to.frame("basefrm")
        time.sleep(1)
        self.driver.find_element_by_id('wlan_tab_2').click()
        time.sleep(2)

        #wifi mode, 802.11b/g , 802.11b/g/n, 2.4 GHz 802.11n
        select = Select(self.driver.find_element_by_id('radio.wlan1.mode'))
        select.select_by_value(wifi_mode)

        #wifi band, 20 MHz , 40 MHz
        if wifi_mode != "802.11b/g":
            select = Select(self.driver.find_element_by_id('radio.wlan1.n-bandwidth'))
            select.select_by_value(wifi_band)

        #primary channel
        if wifi_mode =="802.11b/g/n":

            GUI_Primary_Channel = self.driver.find_element_by_id('radio.wlan1.n-primary-channel').get_attribute('value')
            time.sleep(1)
            if GUI_Primary_Channel == "Lower":
                select = Select(self.driver.find_element_by_id('radio.wlan1.channel'))
                select.select_by_value("5")

            if GUI_Primary_Channel == "Upper":
                select = Select(self.driver.find_element_by_id('radio.wlan1.channel'))
                select.select_by_value("5")
                
            time.sleep(3)
            
            select = Select(self.driver.find_element_by_id('radio.wlan1.n-primary-channel'))
            select.select_by_value(pri_channel)

        #wifi Channels, Auto, 1, 2...
        select = Select(self.driver.find_element_by_id('radio.wlan1.channel'))
        select.select_by_value(wifi_channel)
        time.sleep(2)
        self.driver.find_element_by_id('button').click()
        time.sleep(2)
        self.driver.switch_to.default_content()
        try:
            self.driver.find_element_by_id('YesBtn').click()
        except:
            pass
        time.sleep(30)



    def Wireless_Network_5G_default_SSID_Modify(self,ssid,wifi_security,key_string=None):
        self.driver.find_element_by_id("vwn").click()

        try:
            time.sleep(1)
            self.driver.find_element_by_id('YesBtn').click()
        except:
            pass
        
        time.sleep(5)
        self.driver.switch_to.frame("basefrm")
        self.driver.find_element_by_id('interface_2_4').click()
        time.sleep(3)
        self.driver.find_element_by_xpath('//*[@id="wlan0_row_0"]/td[1]/div/label').click()
        time.sleep(1)
        self.driver.find_element_by_id("editButton").click()
        time.sleep(1)
        self.driver.find_element_by_id("vwn_ssid_0").clear()
        time.sleep(1)
        self.driver.find_element_by_id("vwn_ssid_0").send_keys(ssid)

        if wifi_security == "no":
            wifi_security = "plain-text"
        if wifi_security == "wpa":
            wifi_security = "wpa-personal"
        if wifi_security == "enterprise":
            wifi_security = "wpa-enterprise"


        #Wifi security, no = plain-text, wpa-personal = wpa-personal, wpa-enterprise = wpa-enterprise
        select = Select(self.driver.find_element_by_id('security-mode-id0'))
        select.select_by_value(wifi_security)
        time.sleep(1)

        if wifi_security == "wpa-personal":
            self.driver.find_element_by_id("show_details0").click()
            time.sleep(1)
            #show key
            self.driver.find_element_by_xpath('//*[@id="wpa-settings-panel0"]/table/tbody/tr[3]/td[2]/div/label').click()
            time.sleep(3)
            self.driver.find_element_by_id("wpavlans0wpa-personal-key").clear()
            time.sleep(1)
            self.driver.find_element_by_id("wpavlans0wpa-personal-key").send_keys(key_string)
            time.sleep(3)
            self.driver.find_element_by_id("YesBtn").click()


        if wifi_security == "wpa-enterprise":
            #20180202, not finish
            pass


        self.driver.find_element_by_id('button').click()
        time.sleep(1)
        self.driver.switch_to.default_content()
        try:
            self.driver.find_element_by_id('YesBtn').click()
        except:
            pass
        time.sleep(30)

    def Wireless_Network_2G_default_SSID_Modify(self,ssid,wifi_security,key_string=None):
        self.driver.find_element_by_id("vwn").click()

        try:
            time.sleep(1)
            self.driver.find_element_by_id('YesBtn').click()
        except:
            pass
        
        time.sleep(5)
        self.driver.switch_to.frame("basefrm")
        self.driver.find_element_by_id('interface_5').click()
        time.sleep(3)
        self.driver.find_element_by_xpath('//*[@id="wlan1_row_0"]/td[1]/div/label').click()
        time.sleep(1)
        self.driver.find_element_by_id("editButton").click()
        time.sleep(1)
        self.driver.find_element_by_id("wlan1vwn_ssid_0").clear()
        time.sleep(1)
        self.driver.find_element_by_id("wlan1vwn_ssid_0").send_keys(ssid)

        if wifi_security == "no":
            wifi_security = "plain-text"
        if wifi_security == "wpa":
            wifi_security = "wpa-personal"
        if wifi_security == "enterprise":
            wifi_security = "wpa-enterprise"


        #Wifi security, no = plain-text, wpa-personal = wpa-personal, wpa-enterprise = wpa-enterprise
        select = Select(self.driver.find_element_by_id('wlan1security-mode-id0'))
        select.select_by_value(wifi_security)
        time.sleep(1)

        if wifi_security == "wpa-personal":
            self.driver.find_element_by_id("wlan1show_details0").click()
            time.sleep(1)
            #show key
            self.driver.find_element_by_xpath('//*[@id="wlan1wpa-settings-panel0"]/table/tbody/tr[3]/td[2]/div/label').click()
            time.sleep(3)
            self.driver.find_element_by_id("wlan1wpavlans0wpa-personal-key").clear()
            time.sleep(1)
            self.driver.find_element_by_id("wlan1wpavlans0wpa-personal-key").send_keys(key_string)
            time.sleep(3)
            self.driver.find_element_by_xpath("/html/body/div/form/div/div/div/div[2]/div/div[2]/table[2]/tbody/tr[1]/td[8]/div[3]/div/div/div/div[3]/button[1]").click()


        if wifi_security == "wpa-enterprise":
            #20180202, not finish
            pass


        self.driver.find_element_by_id('button').click()
        time.sleep(1)
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





class Wireless_Test(Run_Browser):
    
    def SSID_Modify_5G(self,wifi_modes,wifi_bands,wifi_channels,ssid_5g,security_5g="no",security_string=None,pri_channels=None):
        ## pri channel ,default is None, parameters = Upper , Lower . if mode is 802.11a/n/ac.
        ## security_5g defailt is no (No Security), if wpa enable , must plus security string
        Run_Browser.login(self)
        Run_Browser.Wireless(self)
        Run_Browser.Wireless_Radio_5G(self,wifi_mode=wifi_modes,wifi_band=wifi_bands,wifi_channel=wifi_channels,pri_channel=pri_channels)
        Run_Browser.Wireless_Network_5G_default_SSID_Modify(self,ssid_5g,security_5g,key_string=security_string)
        Run_Browser.logout(self)
        time.sleep(2)


    def SSID_Modify_2G(self,wifi_modes,wifi_bands,wifi_channels,ssid_2g,security_2g="no",security_string=None,pri_channels=None):
        ## pri channel ,default is None, parameters = Upper , Lower . if mode is 802.11b/g/n
        ## security_2g defailt is no (No Security), if wpa enable , must plus security string
        Run_Browser.login(self)
        Run_Browser.Wireless(self)
        Run_Browser.Wireless_Radio_2G(self,wifi_mode=wifi_modes,wifi_band=wifi_bands,wifi_channel=wifi_channels,pri_channel=pri_channels)
        Run_Browser.Wireless_Network_2G_default_SSID_Modify(self,ssid_2g,security_2g,key_string=security_string)
        Run_Browser.logout(self)
        time.sleep(2)












if __name__ == '__main__':

    #Wireless = Wireless_Test(webdriver.Firefox())
    #Wireless.SSID_Modify_5G("802.11a","20 MHz","36","wifi_automation_testing_py_5g")

    #Wireless3 = Wireless_Test(webdriver.Firefox())
    #Wireless3.SSID_Modify_5G("802.11a/n/ac","40 MHz","40","wifi_automation_testing_py_5g","wpa","12345678",pri_channels="Upper")

    Wireless1 = Wireless_Test(webdriver.Firefox())
    Wireless1.SSID_Modify_2G("802.11b/g/n","40 MHz","11","wifi_automation_testing_py_2g","wpa","12345678",pri_channels="Upper")

    #Wireless4 = Wireless_Test(webdriver.Firefox())
    #Wireless4.SSID_Modify_2G("802.11b/g","40 MHz","Auto","wifi_automation_testing_py_2g")

