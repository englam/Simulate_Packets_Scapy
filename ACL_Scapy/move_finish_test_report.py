import unittest, os, json, time, os.path



with open('config.json') as json_data:
    d = json.load(json_data)


test_version = d["test_version"]
test_plan_file = d['test_plan_file']
test_start_time = d[ "start_test_time"]

if os.path.exists(test_plan_file):
    copy_plan_command = "move %s test_report/Chambers_Bay_WAP581_Regression_Test_Report_%s_%s.xlsx"%(test_plan_file,test_version,test_start_time)
    time.sleep(2)
    os.system(copy_plan_command)
    time.sleep(2)



