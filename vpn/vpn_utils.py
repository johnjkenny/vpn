from logging import Logger
from subprocess import run
from time import sleep

# from vpn.encrypt import Cipher
from vpn.logger import get_logger
from vpn.color import Color
from vpn.cert_auth import CertStore


class VpnUtils():
    def __init__(self, service: str = 'server', logger: Logger = None):
        self.log = logger or get_logger('vpn')
        self.__service = service

    '''
    @property
    def encrypt(self):
        return Cipher(self.log)
    '''
    @property
    def service(self):
        return 'openvpn-server@service' if self.__service == 'server' else 'openvpn-client@service'

    def _start_and_enable_vpn_server(self):
        if self.run_cmd(f'systemctl enable --now {self.service}', True, False)[1]:
            sleep(1)
            return self.is_service_active()
        self.log.error('Failed to start and enable VPN service')
        return False

    def get_service_status(self, display: bool = False):
        print(self.service, self.__service)
        status = self.run_cmd(f'systemctl status {self.service}', True, False)
        if display:
            if status[1] is True:
                self.display_state_good(status[0])
            else:
                self.display_state_bad(status[0])
        return status

    def is_service_active(self):
        return self.run_cmd(f'systemctl is-active {self.service}', True, False)[0].strip() == 'active'

    def start_service(self):
        if self.is_service_active():
            return self.get_service_status(True)[1]
        self.run_cmd(f'systemctl start {self.service}', True, False)
        sleep(1)
        return self.get_service_status(True)[1]

    def stop_service(self):
        if not self.is_service_active():
            return self.get_service_status(True)[1]
        self.run_cmd(f'systemctl stop {self.service}', True, False)
        sleep(1)
        return self.get_service_status(True)[1]

    def restart_service(self):
        self.run_cmd(f'systemctl restart {self.service}', True, False)
        sleep(1)
        return self.get_service_status(True)[1]

    def run_cmd(self, cmd: str, ignore_error: bool = False, log_output: bool = False):
        """Run a command and return the output

        Args:
            cmd (str): Command to run
            ignore_error (bool, optional): ignore errors. Defaults to False
            log_output (bool, optional): Log command output. Defaults to False.

        Returns:
            tuple: (stdout, True. '') on success or (stdout, False, error) on failure
        """
        state = True
        error = ''
        output = run(cmd, shell=True, capture_output=True, text=True)
        if output.returncode != 0:
            state = False
            error = output.stderr
            if not ignore_error:
                self.log.error(f'Command: {cmd}\nExit Code: {output.returncode}\nError: {error}')
                return '', state, error
        stdout = output.stdout
        if log_output:
            self.log.info(f'Command: {cmd}\nOutput: {stdout}')
        return stdout, state, error

    def display_state_good(self, msg: str):
        Color().print_message(msg, 'green')

    def display_state_bad(self, msg: str):
        Color().print_message(msg, 'red')


class VpnServer(VpnUtils):
    def __init__(self, logger: Logger = None):
        super().__init__('server', logger)

    @property
    def certs(self):
        return CertStore(self.log)


class VpnClient(VpnUtils):
    def __init__(self, logger: Logger = None):
        super().__init__('client', logger)
