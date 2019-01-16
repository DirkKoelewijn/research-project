import socket
import subprocess
import threading
from time import sleep

ENCODING = 'utf-8'
BUFFER_SIZE = 10


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


class Communicator(threading.Thread):

    def __init__(self, name, host, port, other_host, other_port, func=None):
        threading.Thread.__init__(self, name="messenger_receiver")
        self.name = name
        self.host = host
        self.port = port
        self.other_host = other_host
        self.other_port = other_port
        if func is None:
            func = Communicator.handle_request
        self.func = func

    def send(self, data: str):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.other_host, self.other_port))
        s.sendall(data.encode(ENCODING))
        s.shutdown(2)
        s.close()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(10)
        try:
            while Communicator.handle_client(self, sock.accept()):
                pass
        finally:
            print('SHUTTING DOWN')
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    @staticmethod
    def handle_client(self, accept):
        connection, client_address = accept
        cont = True
        try:
            full_message = ""
            while True:
                data = connection.recv(64)
                full_message = full_message + data.decode(ENCODING)
                if not data:
                    full_message = full_message.strip()
                    self.func(self, full_message)
                    cont = full_message != 'exit'
                    break
        finally:
            connection.shutdown(2)
            connection.close()
            return cont

    @staticmethod
    def handle_request(self, data):
        print('{}: {}'.format(self.name, data))


def attacker_func(self: Communicator, data: str):
    print('{}: {}'.format(self.name, data))
    parts = data.split(' ')
    if parts[0] == 'DOWNLOAD':
        sleep(1)
        self.send(data + ' OK')
    elif parts[0] == 'RUN':
        sleep(1)
        self.send(data + ' IN 1 SECOND')
    elif data == 'exit':
        self.send('exit')
    else:
        self.send('BOGUS')


def defender_func(self: Communicator, data: str):
    print('{}: {}'.format(self.name, data))
    parts = data.split(' ')
    if parts[0] == 'DOWNLOAD' and parts[-1] == 'OK':
        sleep(1)  # Wait until downloads are done
        self.send(data.replace('DOWNLOAD', 'RUN').replace(' OK', ''))
    elif parts[0] == 'RUN' and parts[-1] == 'SECOND':
        sleep(1)
        self.send('exit')
    elif data == 'exit':
        return
    else:
        self.send('BOGUS')


if __name__ == '__main__':
    port1 = 2000
    port2 = 2001
    r = Communicator('receiver', 'localhost', port1, 'localhost', port2, attacker_func)
    s = Communicator('sender', 'localhost', port2, 'localhost', port1, defender_func)
    r.start()
    s.start()
    sleep(1)
    message = ''
    message = input("Message?").strip()
    s.send(message)
    r.join()
    s.join()
