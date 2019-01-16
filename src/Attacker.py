import subprocess

import ddosdb
from Communication import Communicator


class Attacker(Communicator):
    WAIT = 3
    NORMAL_DATA = 'rw_bigflows'

    def __init__(self, ddosdb_user, ddosdb_pass, host, port, other_host, other_port):
        super().__init__('attacker', host, port, other_host, other_port)
        self.user = ddosdb_user
        self.password = ddosdb_pass

    @staticmethod
    def handle_request(self, data):
        print('%-10s IN : %s' % (self.name, data))
        parts = data.split(' ')
        if parts[0] == 'DOWNLOAD':
            self.download_pcap(parts[1])
            self.send(data + ' OK')
        elif parts[0] == 'RUN':
            self.run_pcap(parts[1], parts[2])
            self.send(data + ' IN 1 SECOND')
        else:
            self.send('BOGUS')

        return True

    def download_pcap(self, name):
        print('Downloading')
        s = ddosdb.login(self.user, self.password)
        ddosdb.download_pcap(s, name)
        print('Rewriting')
        self.rewrite(name, 10)
        print('Done')

    def run_pcap(self, name, seconds):
        print('Running %s.pcap in %s seconds' % (name, seconds))

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
