from time import sleep

from Communication import Communicator
from Fingerprints import Fingerprint
from Program import Program
from Util import files_in_folder


class Defender(Communicator):
    RUN_SECONDS = 25

    def __init__(self, fingerprint, host, port, other_host, other_port, match_all_but=0):
        super().__init__('defender', host, port, other_host, other_port)
        self.__fingerprints = fingerprint
        self.__program = Program.load(fingerprint, match_all_but=match_all_but)
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
    def __init__(self, ip, port, other_ip, other_port=None, match_all_but=0):
        self.ip = ip
        self.port = port
        self.other_ip = other_ip
        if other_port is None:
            other_port = port
        self.other_port = other_port
        self.all_but = match_all_but

    def launch(self, fingerprint):
        d = Defender(fingerprint, self.ip, self.port, self.other_ip, self.other_port, match_all_but=self.all_but)
        d.start()
        return d


if __name__ == '__main__':
    factory = DefenderFactory('192.168.1.145', 1025, '192.168.1.148', match_all_but=1)
    # Get all json all_files
    all_files = files_in_folder('fingerprints/', '.json')
    all_files.remove('empty')

    results = []

    # Get all all_files that can be used without reducing
    files = []
    for file in all_files:
        try:
            fingerprint = Fingerprint.parse('fingerprints/%s.json' % file)
            if Fingerprint.rule_size(fingerprint) > Program.MaxPropCount:
                raise AssertionError('Fingerprint too big to use unreduced')

            files.append(file)
        except BaseException as e:
            print('Error parsing fingerprint "%s":  %s' % (file, str(e)))

    defender = None
    for f in files:
        try:
            defender = factory.launch(f)
            defender.join()
            print(defender.result())
        except BaseException as e:
            print(e)
    #
    # if defender is not None:
    #     defender.send_exit()
