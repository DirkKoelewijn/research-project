from Attacker import Attacker

if __name__ == '__main__':
    port = 1025
    # u = input('DDOSDB user:')
    u = 'd.koelewijn@student.utwente.nl'
    # p = input('DDOSDB pass:')
    p = 'vRgD3WBqnA'
    r = Attacker(u, p, '192.168.1.148', port, '192.168.1.145', port)
    print('Listening')
    r.run()
