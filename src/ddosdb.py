import re

import requests


def login(u, p):
    """
    Logs in to DDoSDB.org

    :param u: Username
    :param p: Password
    :return: Session that can be used to access DDoSDB.org
    """
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
    return s


def download_pcap(s, attack_id: str):
    """
    Downloads a pcap file from DDoSDB.org to pcap/

    :param s: Logged in session
    :param attack_id: Attack identifier/key
    """
    r_pcap = s.get('https://ddosdb.org/attack-trace/%s' % attack_id)
    if r_pcap.status_code == 200:
        with open('pcaps/%s.pcap' % attack_id, 'wb') as file:
            file.write(r_pcap.content)
