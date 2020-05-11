"""Client to handle connections and actions executed against a remote host."""
import sys
#from loguru import logger
from os import system
from paramiko import SSHClient, AutoAddPolicy, RSAKey
from paramiko.auth_handler import AuthenticationException, SSHException
from scp import SCPClient, SCPException

"""
logger.add(sys.stderr,
           format="{time} {message}",
           filter="client",
           level="INFO")
logger.add('logs/log_{time:YYYY-MM-DD}.log',
           format="{time} {level} {message}",
           filter="client",
           level="ERROR")
"""

class RemoteClient:
    """Client to interact with a remote host via SSH & SCP."""

    def __init__(self, host, user, password, port=22):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.client = None
        self.scp = None
        self.ssh_conn = None

    def __connect(self):
        """
        Open connection to remote host.
        """
        try:
            self.client = SSHClient()
            self.client.load_system_host_keys()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            self.client.connect(self.host,
                                port=self.port,
                                username=self.user,
                                password=self.password,
                                look_for_keys=True,
                                timeout=5000)
            self.scp = SCPClient(self.client.get_transport())
        except AuthenticationException as error:
            print('Authentication failed: did you remember to create an SSH key?')
            print(error)
            raise error
        finally:
            return self.client

    def disconnect(self):
        """
        Close ssh connection.
        """
        self.client.close()
        self.scp.close()

    def download_file(self, file, local_path):
        """Download file from remote host."""
        if self.ssh_conn is None:
            self.ssh_conn = self.__connect()
        self.scp.get(file, local_path)

    def execute_command(self, cmd):
        """
        Execute multiple commands in succession.

        :param commands: List of unix commands as strings.
        """
        if self.client is None:
            self.client = self.__connect()
        stdin, stdout, stderr = self.client.exec_command(cmd)
        stdout.channel.recv_exit_status()
        response = stdout.readlines()
        for line in response:
            print(f'INPUT: {cmd} | OUTPUT: {line}')
        return response