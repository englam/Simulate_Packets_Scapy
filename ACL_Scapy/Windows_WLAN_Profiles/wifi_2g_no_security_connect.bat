cd C:\Automation_Test\Cisco\AP\Chambersbay\WAP581\Windows_WLAN_Profiles
netsh wlan add profile filename="wifi_automation_testing_py_2g_no_security.xml"
ping 127.0.0.1 -n 5
netsh wlan connect name="wifi_automation_testing_py_2g"
ping 127.0.0.1 -n 10