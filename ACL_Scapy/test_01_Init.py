import unittest, os, json, time



with open('config.json') as json_data:
    d = json.load(json_data)


test_plan_file = d['test_plan_file']
test_plan_sheet = d['lan_sheet']
test_version = d["test_version"]
#test_report = "Chambers_Bay_WAP581_Regression_Test_Report_%s_%s.xlsx"%(test_version,time.strftime("%Y%m%d%H%M"))

create_plan_command = "copy test_plan\Chambers_Bay_WAP581_Regression_Test_Report.xlsx %s"%(test_plan_file)

time.sleep(2)
os.system(create_plan_command)
time.sleep(2)

d["start_test_time"] = time.strftime("%Y%m%d%H%M")

with open('config.json', 'w') as outfile:
    json.dump(d, outfile)

time.sleep(2)

