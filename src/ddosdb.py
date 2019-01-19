import re
from os.path import isfile

import requests


def download_pcap(u, p, attack_id: str, check_exists):
    """
    Downloads a pcap file from DDoSDB.org to pcap/

    :param u: Username
    :param p: Password
    :param attack_id: Attack identifier/key
    """
    file = 'pcaps/%s.pcap' % attack_id

    if check_exists and isfile(file):
        print('%s already exists. Download skipped.' % file)
        return

    s = requests.Session()
    login_page = s.get('https://ddosdb.org/login')
    token = re.search('name="csrfmiddlewaretoken".*?value="(.+?)"', login_page.content.decode('utf-8'))
    if token is not None:
        token = token.group(1)
        resp = s.post('https://ddosdb.org/login', headers={'referer': 'https://ddosdb.org/login'},
                      data={'username': u, 'password': p, 'csrfmiddlewaretoken': token})
        if 'Invalid password' in resp.content.decode('utf-8'):
            raise AssertionError("Username or password incorrect")
    else:
        raise AssertionError("Could not find token on page")

    r_pcap = s.get('https://ddosdb.org/attack-trace/%s' % attack_id)
    if r_pcap.status_code == 200:

        with open(file, 'wb') as file:
            file.write(r_pcap.content)
