from time import sleep

from Communication import Communicator
from Program import Program


class Defender(Communicator):
    RUN_SECONDS = 10

    def __init__(self, fingerprints, host, port, other_host, other_port):
        super().__init__('defender', host, port, other_host, other_port)
        self.__fingerprints = fingerprints
        self.__index = -1
        self.__current_program = None

    def start(self) -> None:
        super().start()
        sleep(1)
        self.next_program()

    def next_program(self):
        self.__index += 1
        if self.__index < len(self.__fingerprints):
            self.__current_program = Program.load(self.__fingerprints[self.__index])

        self.send('DOWNLOAD %s' % self.__current_program.name)

    def program(self) -> Program:
        return self.__current_program

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
        if self.program().name == name:
            print('Starting test run for %s seconds' % s, flush=True)
            res = self.program().test_run(s)
        else:
            raise AssertionError('Expected program %s to be loaded, got %s instead' % (name, self.program().name))
        print('Printing analysis', flush=True)
        self.program().print_analysis(res)


if __name__ == '__main__':
    f = ['2ea180355c6612d69993431075783e86']
    port = 1025
    defender = Defender(f, '192.168.1.145', port, '192.168.1.148', port)
    defender.start()
    print('started')
    defender.join()
