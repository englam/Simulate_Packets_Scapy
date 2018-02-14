'''

Usage:
python config.py "1.0.1.0a"

'''

import json,sys


test_version		= sys.argv[1]


with open('config.json') as json_data:
    d = json.load(json_data)


d["test_version"]             = str(test_version)


with open('config.json', 'w') as outfile:
    json.dump(d, outfile)
