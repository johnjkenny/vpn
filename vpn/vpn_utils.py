import pickle
from logging import Logger
from subprocess import run
from time import sleep
from pathlib import Path
from hashlib import sha256
from json import loads
from os import remove, chown
from pwd import getpwnam
from grp import getgrnam
from getpass import getpass

from vpn.logger import get_logger
from vpn.color import Color
from vpn.cert_auth import CertStore


class VpnUtils():
    def __init__(self, service: str = 'server', logger: Logger = None):
        self.log = logger or get_logger('vpn')
        self.__service = service

    @property
    def service(self):
        return 'openvpn-server@service' if self.__service == 'server' else 'openvpn-client@service'

    @property
    def __xork(self) -> bytes:
        """Default XOR key for encryption/decryption

        Returns:
            bytes: XOR key
        """
        return b"c_#>3!ab7:/&)'.^B%(2}D_.D^+0c+8<+%0C@^[+69cA6!(+d72c<|/.0'5_?6010=&25;:8cA95+9A&{@4389]~.aF2{%-266])Ac"

    def _key(self, passwd: str):
        try:
            return sha256(passwd.encode() or self.__xork).digest()
        except Exception:
            self.log.exception('Failed to generate key')
        return b''

    def _xor(self, data: bytes, key: bytes) -> bytes:
        try:
            extended_key = (key * (len(data) // len(key) + 1))[:len(data)]
            return bytes([b ^ extended_key[i % len(extended_key)] for i, b in enumerate(data)])
        except Exception:
            self.log.exception('Failed to encrypt/decrypt data')
        return b''

    def _decrypt_bundle(self, data: bytes, passwd: str = '') -> dict:
        decrypted = self._xor(data, self._key(passwd))
        if decrypted:
            try:
                return pickle.loads(decrypted)
            except pickle.UnpicklingError:
                self.log.error('Invalid decryption key')
            except Exception:
                self.log.exception('Failed to decrypt bundle')
        return {}

    def _prompt_for_passwd(self) -> str:
        passwd = getpass('Enter password: ')
        if not passwd:
            self.log.error('Password cannot be empty')
            return self._prompt_for_passwd()
        return passwd

    def _set_openvpn_owner_and_permissions(self):
        try:
            path = Path('/etc/openvpn')
            uid = getpwnam('root').pw_uid
            gid = getgrnam('openvpn').gr_gid
            chown(path, uid, gid)
            path.chmod(0o660)
        except Exception:
            self.log.exception('Failed to set directory owner and permissions')
            return False
        return self._set_cert_owner_and_permissions()

    def _set_cert_owner_and_permissions(self):
        try:
            path = Path('/etc/openvpn/certs')
            uid = getpwnam('root').pw_uid
            gid = getgrnam('root').gr_gid
            for item in path.rglob("*"):
                chown(item, uid, gid)
                item.chmod(0o600)
            return True
        except Exception:
            self.log.exception('Failed to set certs owner and permissions')
        return False

    def _delete_client_certs(self, name: str) -> bool:
        try:
            for cert in [f'{name}.crt', f'{name}.key']:
                remove(f'/etc/openvpn/certs/{cert}')
            return True
        except Exception:
            self.log.exception(f'Failed to delete client certs: {name}')
        return False

    def _start_and_enable_vpn_server(self):
        if self.run_cmd(f'systemctl enable --now {self.service}', True, False)[1]:
            if self.__service == 'client':
                self.__set_client_dns()
            sleep(1)
            return self.is_service_active()
        self.log.error('Failed to start and enable VPN service')
        return False

    def enable_service(self):
        return self.run_cmd(f'systemctl enable {self.service}', True, False)[1]

    def disable_service(self):
        return self.run_cmd(f'systemctl disable {self.service}', True, False)[1]

    def get_service_status(self, display: bool = False):
        status = self.run_cmd(f'systemctl status {self.service}', True, False)
        if display:
            if status[1] is True:
                self.display_state_good(status[0])
            else:
                self.display_state_bad(status[0])
        return status

    def __set_client_dns(self):
        try:
            with open('/etc/resolv.conf', 'w') as file:
                file.write('nameserver 10.8.0.1')
            return True
        except Exception:
            self.log.exception('Failed to set client DNS')
        return False

    def __revert_client_dns(self):
        try:
            with open('/etc/openvpn/bkp.resolv.conf', 'r') as file:
                data = file.read()
            with open('/etc/resolv.conf', 'w') as file:
                file.write(data)
            return True
        except Exception:
            self.log.exception('Failed to revert client DNS')
        return False

    def is_service_active(self):
        return self.run_cmd(f'systemctl is-active {self.service}', True, False)[0].strip() == 'active'

    def is_firewalld_active(self):
        return self.run_cmd('systemctl is-active firewalld', True, False)[0].strip() == 'active'

    def start_service(self):
        if self.is_service_active():
            return self.get_service_status(True)[1]
        self.run_cmd(f'systemctl start {self.service}', True, False)
        if self.__service == 'client':
            self.__set_client_dns()
        sleep(1)
        return self.get_service_status(True)[1]

    def stop_service(self):
        if not self.is_service_active():
            return self.get_service_status(True)[1]
        self.run_cmd(f'systemctl stop {self.service}', True, False)
        if self.__service == 'client':
            self.__revert_client_dns()
        sleep(1)
        return not self.is_service_active()

    def restart_service(self):
        self.run_cmd(f'systemctl restart {self.service}', True, False)
        if self.__service == 'client':
            self.__set_client_dns()
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
        self.__certs: CertStore | None = None

    @property
    def certs(self) -> CertStore:
        if self.__certs is None:
            self.__certs = CertStore(self.log)
        return self.__certs

    def __get_server_port(self) -> str:
        with open('/etc/openvpn/server/service.conf', 'r') as service:
            for line in service.readlines():
                if line.startswith('port'):
                    return line.split(' ')[1].strip()
        self.log.error('Failed to get server port')
        return ''

    def __get_network_interface_ip(self, index_interface: int = 2):
        rsp = self.run_cmd('ip -j address')
        if rsp[1]:
            try:
                for interface in loads(rsp[0]):
                    interface: dict
                    if interface.get('ifindex') == index_interface:
                        return interface.get('addr_info')[0].get('local')
            except Exception:
                self.log.exception('Failed to get network interface IP')
        else:
            self.log.error('Failed to get network interface IP')
        return ''

    def __create_client_config(self, client_name: str) -> str:
        port = self.__get_server_port()
        if port:
            ip = self.__get_network_interface_ip(2)
            if ip:
                try:
                    with open(f'{Path(__file__).parent}/templates/client.conf', 'r') as file:
                        data = file.read()
                        data = data.replace('<IP>', ip)
                        data = data.replace('<PORT>', port)
                        data = data.replace('<NAME>', client_name)
                    return data, port
                except Exception:
                    self.log.exception('Failed to create client config')
                    return ''
        self.log.error('Failed to create client config')
        return '', ''

    def __stash_bundle(self, name: str, bundle: bytes) -> bool:
        if bundle:
            try:
                path_name = f'{self.certs.cert_dir}/{name}.bundle'
                with open(path_name, 'wb') as file:
                    file.write(bundle)
                self.log.info(f'Client bundle created: {path_name}')
            except Exception:
                self.log.exception('Failed to stash bundle')
                return False
            return self._delete_client_certs(name)
        return False

    def __encrypt_and_stash_bundle(self, name: str, certs: dict, passwd: str = '') -> bool:
        try:
            data = pickle.dumps(certs)
        except Exception:
            self.log.exception('Failed to encrypt bundle')
            return False
        return self.__stash_bundle(name, self._xor(data, self._key(passwd)))

    def __bundle_certs(self, name: str, passwd: str = '') -> bool:
        config, port = self.__create_client_config(name)
        if config:
            __certs = {'config': config, 'port': port}
            for cert in [f'{name}.crt', f'{name}.key', 'vpn-ca.crt', 'tls-crypt.key']:
                with open(f'{self.certs.cert_dir}/{cert}', 'r') as file:
                    __certs[cert] = file.read()
            return self.__encrypt_and_stash_bundle(name, __certs, passwd)
        return False

    def create_and_bundle_client_certs(self, name: str, passwd: bool = False, force: bool = False) -> bool:
        passwd = self._prompt_for_passwd() if passwd else ''
        if Path(self.certs.serial_file).exists():
            if Path(f'{self.certs.cert_dir}/{name}.crt').exists() and not force:
                self.log.error(f'Client certificate {name} already exists. Use --force to overwrite')
                return False
            if self.certs.create(name, server=False):
                return self.__bundle_certs(name, passwd) and self._set_cert_owner_and_permissions()
        else:
            self.log.error('CA serial file does not exist. Either init VPN server or generate certs on server')
        return False

    def delete_client_cert(self, client: str):
        cert = Path(f'{self.certs.cert_dir}/{client}.bundle')
        if cert.exists():
            try:
                remove(cert)
                self.log.info('Successfully deleted client cert')
                return True
            except Exception:
                self.log.exception(f'Failed to delete client cert: {client}')
        else:
            self.log.error(f'Client cert {client} does not exist')
        return False


class VpnClient(VpnUtils):
    def __init__(self, logger: Logger = None):
        super().__init__('client', logger)
