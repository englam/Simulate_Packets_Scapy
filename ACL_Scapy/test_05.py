import unittest, os, json, time
from modules.Parse_Test_Plan import get_excel_cell


with open('config.json') as json_data:
    d = json.load(json_data)


test_plan_file = d['test_plan_file']
test_plan_sheet = d['lan_sheet']

windows_wifi_2g_connection = "Windows_WLAN_Profiles\wifi_2g_wpa2_connect.bat"
windows_wifi_2g_disconnection = "Windows_WLAN_Profiles\wifi_2g_disconnect.bat"

class LAN(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        print("a1")

    def setUp(self):
        #os.system(windows_wifi_2g_connection)
        print (1)
        pass

    def test_lan_01(self):
        '''tttt'''

        # Test Objectives
        search_keyword = "Verify that IPv4 deny src IP to dest IP is workable."
        #search_keyword = "englam"
        #_col,_row=get_excel_cell(test_plan_file,test_plan_sheet,search_keyword)
        #self.assertNotEqual(0,_row)
        print ("e1")

    def test_lan_02(self):
        '''tttt'''

        # Test Objectives
        search_keyword = "Verify that IPv4 deny src IP to dest IP is workable."
        #search_keyword = "englam"
        #_col,_row=get_excel_cell(test_plan_file,test_plan_sheet,search_keyword)
        #self.assertNotEqual(0,_row)
        print ("e2")

    def tearDown(self):
        #os.system(windows_wifi_2g_disconnection)
        print (2)
        pass

    @classmethod
    def tearDownClass(cls):
        print("a2")

    
if __name__=="__main__":
    unittest.main()
