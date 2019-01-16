import subprocess


def rewrite(name, ttl):
    """
    Rewrites a PCAP file for sending

    :param name: Name of the file (excluding extension, e.g: 'bigflows')
    :param ttl: TTL to mark packets
    """
    subprocess.call(['sudo', 'pcaps/autorewrite.sh', 'pcaps/%s.pcap' % name, '%s' % str(ttl)])


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
    attack('rw_10c774e657315ee95dc8501cdfb7f3fa', 'rw_bigflows', 1)
