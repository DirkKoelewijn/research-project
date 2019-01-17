import socket
import threading
from abc import ABC, abstractmethod

EXIT = 'exit'
ENCODING = 'utf-8'
BUFFER_SIZE = 16


class Communicator(threading.Thread, ABC):
    """
    Abstract class for bidirectional traffic handling
    """

    def __init__(self, name, host, port, other_host, other_port):
        """
        Initializes a communicator
        :param name: Name for the communicator
        :param host: Own host name
        :param port: Own port
        :param other_host: Other host name
        :param other_port: Other port
        """
        threading.Thread.__init__(self, name=name)
        self.name = name
        self.host = host
        self.port = port
        self.other_host = other_host
        self.other_port = other_port

    def send(self, data: str):
        """
        Sends a string of data
        :param data: String of data
        """
        print('%-10s OUT: %s' % (self.name, data))
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.other_host, self.other_port))
        s.sendall(data.encode(ENCODING))
        s.shutdown(2)
        s.close()

    def run(self):
        """
        Starts listening for requests
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(10)
        try:
            while self.handle_client(sock.accept()):
                pass
        finally:
            print('Shutting down %s' % self.name)
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()

    def handle_client(self, accept):
        """
        Handles a connection with a client

        :param self:
        :param accept:
        :return:
        """
        connection, client_address = accept
        cont = True
        try:
            data = ""
            while True:
                rcv = connection.recv(BUFFER_SIZE)
                data += rcv.decode(ENCODING).strip()
                if not rcv:
                    if data == EXIT:
                        cont = False
                    else:
                        cont = self.handle_request(data)
                    break
        except AssertionError as error:
            print('EXCEPTION:', str(error))
            self.send(EXIT)
            cont = False
        finally:
            connection.shutdown(2)
            connection.close()
            return cont

    @abstractmethod
    def handle_request(self, data: str) -> bool:
        raise NotImplementedError
