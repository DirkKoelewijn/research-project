from time import sleep

from Communication import Communicator
from Program import Program


class Defender(Communicator):
    RUN_SECONDS = 10

    def __init__(self, fingerprint, host, port, other_host, other_port):
        super().__init__('defender', host, port, other_host, other_port)
        self.__fingerprints = fingerprint
        self.__program = Program.load(fingerprint)
        self.__result = None

    def start(self) -> None:
        super().start()
        sleep(1)
        self.send('DOWNLOAD %s' % self.__program.name)

    def handle_request(self, data):
        print('%-10s IN : %s' % (self.name, data))
        parts = data.split(' ')
        if parts[0] == 'DOWNLOAD' and parts[-1] == 'OK':
            self.send(data.replace('DOWNLOAD', 'RUN').replace('OK', str(Defender.RUN_SECONDS)))
        elif parts[0] == 'RUN' and parts[-1] == 'SECONDS':
            self.run_defense(parts[1], parts[2], parts[4])
            return False
        else:
            print('Invalid message:', data, flush=True)
        return True

    def run_defense(self, name, seconds, start_seconds):
        s = int(seconds) + int(start_seconds)
        if self.__program.name == name:
            print('Starting test run for %s seconds' % s, flush=True)
            self.__result = self.__program.test_run(s, save=True)
        else:
            raise AssertionError('Expected program %s to be loaded, got %s instead' % (name, self.__program.name))
        print('Printing analysis', flush=True)
        self.__program.print_analysis(self.__result)

    def result(self):
        return self.__result


class DefenderFactory:
    def __init__(self, ip, port, other_ip, other_port=None):
        self.ip = ip
        self.port = port
        self.other_ip = other_ip
        if other_port is None:
            other_port = port
        self.other_port = other_port

    def launch(self, fingerprint):
        d = Defender(fingerprint, self.ip, self.port, self.other_ip, self.other_port)
        d.start()
        return d


if __name__ == '__main__':
    factory = DefenderFactory('192.168.1.145', 1025, '192.168.1.148')
    fingerprints = ['2ea180355c6612d69993431075783e86', '1a2e433cfed7bde38732f0892fbbff27']
    defender = None
    for f in fingerprints:
        defender = factory.launch(f)
        defender.join()
        print(defender.result())

    if defender is not None:
        defender.send_exit()
