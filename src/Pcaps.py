import re

import requests

s = requests.Session()
a = s.get('https://ddosdb.org/login')
token = re.search('name="csrfmiddlewaretoken".*?value="(.+?)"', a.content.decode('utf-8'))
if token is not None:
    token = token.group(1)
    b = s.post('https://ddosdb.org/login', headers={'referer': 'https://ddosdb.org/login'},
               data={'username': 'd.koelewijn@student.utwente.nl', 'password': 'vRgD3WBqnA',
                     'csrfmiddlewaretoken': token})
    c = s.get('https://ddosdb.org/attack-trace/02a3a3fc266b09b7645e538efbc1ea11')
    print()
