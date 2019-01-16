from time import sleep

from Attacker import Attacker
from Defender import Defender

if __name__ == '__main__':
    port1 = 2000
    port2 = 2001
    u = input('DDOSDB user:')
    p = input('DDOSDB pass:')
    r = Attacker(u, p, 'localhost', port1, 'localhost', port2)
    s = Defender('defender', 'localhost', port2, 'localhost', port1)
    r.start()
    s.start()
    sleep(1)
    message = ''
    message = input("Message?").strip()
    s.send(message)
    r.join()
    s.join()
