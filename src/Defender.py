from time import sleep

from Communication import Communicator


class Defender(Communicator):

    @staticmethod
    def handle_request(self, data):
        print('%-10s IN : %s' % (self.name, data))
        parts = data.split(' ')
        if parts[0] == 'DOWNLOAD' and parts[-1] == 'OK':
            sleep(1)  # Wait until downloads are done
            self.send(data.replace('DOWNLOAD', 'RUN').replace('OK', '30'))
        elif parts[0] == 'RUN' and parts[-1] == 'SECOND':
            run_defense(parts[1], parts[2], parts[4])
            self.send('exit')
            return False
        else:
            self.send('BOGUS')

        return True


def run_defense(name, seconds, startseconds):
    print('Running building defense for %s.json, running %s seconds and starting in %s seconds' % (
        name, seconds, startseconds))
