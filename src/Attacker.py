import subprocess
from time import sleep

import ddosdb
from Communication import Communicator


class Attacker(Communicator):
    INTERN_WAIT = 3
    EXTERN_WAIT = INTERN_WAIT + 2
    NORMAL_DATA = 'rw_bigflows'

    def __init__(self, ddosdb_user, ddosdb_pass, host, port, other_host, other_port):
        super().__init__('attacker', host, port, other_host, other_port)
        self.user = ddosdb_user
        self.password = ddosdb_pass

    def handle_request(self, data):
        print('%-10s IN : %s' % (self.name, data))
        parts = data.split(' ')
        if parts[0] == 'DOWNLOAD':
            self.download_pcap(parts[1])
            self.send(data + ' OK')
        elif parts[0] == 'RUN':
            self.send(data + (' IN %s SECONDS' % Attacker.EXTERN_WAIT))
            self.run_pcap(parts[1], parts[2])
        else:
            print('Invalid message:', data)

        return True

    def download_pcap(self, name):
        s = ddosdb.login(self.user, self.password)
        ddosdb.download_pcap(s, name)
        self.rewrite(name, 10)

    def run_pcap(self, name, seconds):
        sleep(Attacker.INTERN_WAIT)
        a = 'rw_%s' % name
        self.attack(a, Attacker.NORMAL_DATA, seconds)

    @staticmethod
    def rewrite(name, ttl):
        """
        Rewrites a PCAP file for sending

        :param name: Name of the file (excluding extension, e.g: 'bigflows')
        :param ttl: TTL to mark packets
        """
        subprocess.call(['sudo', 'pcaps/autorewrite.sh', 'pcaps/%s.pcap' % name, '%s' % str(ttl)])

    @staticmethod
    def attack(a, n, s, r=0.8):
        """
        Launches an attack

        :param a: Attack pcap (rewritten)
        :param n: Normal pcap (rewritten)
        :param s: Seconds to run attack
        :param r: Optional. Attack to total traffic rate, defaults to 0.8
        """
        subprocess.call(
            ['sudo', 'pcaps/attack.sh', 'pcaps/%s.pcap' % a, 'pcaps/%s.pcap' % n, str(r), str(s)])


if __name__ == '__main__':
    port1 = 2000
    # u = input('DDOSDB user:')
    u = 'd.koelewijn@student.utwente.nl'
    # p = input('DDOSDB pass:')
    p = 'vRgD3WBqnA'
    r = Attacker(u, p, '192.168.1.148', 2000, '192.168.1.145', 2000)
    print('Listening')
    r.run()
