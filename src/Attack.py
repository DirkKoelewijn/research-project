from time import sleep

from Attacker import Attacker
from Defender import Defender

if __name__ == '__main__':
    port1 = 2000
    # u = input('DDOSDB user:')
    u = 'd.koelewijn@student.utwente.nl'
    # p = input('DDOSDB pass:')
    p = 'vRgD3WBqnA'
    r = Attacker(u, p, '192.168.1.148', 2000, '192.168.1.145', 2000)
    print('Listening')
    r.run()
