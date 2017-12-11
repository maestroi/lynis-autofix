import json
from pprint import pprint

with open('json/Tools.json') as data_file:
    data = json.load(data_file)

for id in data:
    pprint(data['command'])