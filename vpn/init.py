from socket import gethostname
from pathlib import Path
from os import remove
from platform import freedesktop_os_release
from shutil import which
from json import dump


from vpn.vpn_utils import VpnUtils
from vpn.cert_auth import CertStore


class Init():
    def __init__(self, port: int | str = 1194, force: bool = False):
        """Initialize the web server environment

        Args:
            force (bool, optional): Option to recreate env objects. Defaults to False.
        """
        self.utils: VpnUtils | None = None
        self.__port = port
        self.__force = force
        self.__bundle_path = ''
        self.__passwd = ''

    def __make_dirs(self):
        try:
            for name in ['/etc/openvpn/certs', '/etc/openvpn/server', '/etc/openvpn/client', '/etc/openvpn/logs']:
                Path(name).mkdir(parents=True, exist_ok=True)
            return True
        except Exception:
            self.utils.log.exception('Failed to create directories')
            return False

    def __get_install_cmd(self):
        os_id = freedesktop_os_release().get('ID_LIKE').lower()
        if 'debian' in os_id:
            return 'apt install -y openvpn'
        if 'rhel' in os_id:
            if which('dnf'):
                return 'dnf install -y openvpn'
            elif which('yum'):
                return 'yum install -y openvpn'
            self.utils.log.error(f'Unable to find package manager for RHEL based system: {os_id}')
        else:
            self.utils.log.error(f'Unsupported OS: {os_id}')
        return ''

    def __install_openvpn(self):
        # ToDO: epel repo is required for RHEL based systems, need to check debian based system requirements
        cmd = self.__get_install_cmd()
        if cmd:
            if self.utils.run_cmd(cmd)[1]:
                return True
            self.utils.log.error('Failed to install vpn dependencies')
        return False

    def __create_ca_serial_handler(self) -> bool:
        """Create the CA serial file. If force is set, delete the file and recreate it

        Returns:
            bool: True if successful, False otherwise
        """
        path = '/etc/openvpn/certs/ca-serial'
        if not Path(path).exists():
            try:
                with open(path, 'w') as file:
                    file.write('1')
                return True
            except Exception:
                self.utils.log.exception('Failed to create CA serial file')
                return False
        if self.__force:
            remove(path)
            return self.__create_ca_serial_handler()
        return True

    def __create_cert_subject(self):
        file = Path('/etc/openvpn/certs/ca-subject')
        if file.exists() and not self.__force:
            return True
        subject = {}
        subject['country'] = input('CA Country Name (2 letter code) [US]: ') or 'US'
        subject['state'] = input('CA State or Province Name [US-STATE]: ') or 'US-State'
        subject['city'] = input('CA Locality Name (city) [US-CITY]: ') or 'US-City'
        subject['company'] = input('CA Organization Name (eg, company) [US-Company]: ') or 'US-Company'
        subject['department'] = input('CA Organizational Unit Name (eg, section) [US-Department]: ') or 'US-Department'
        subject['email'] = input('CA email [myEmail@email.com]: ') or 'myEmail@email.com'
        try:
            with open(file, 'w') as file:
                dump(subject, file, indent=2)
                file.write('\n')
            return True
        except Exception:
            self.utils.log.exception('Failed to create CA subject file')
        return False

    def __initialize_cert_authority(self) -> bool:
        """Initialize the certificate authority by creating the CA cert and key. Then create the localhost cert
        and key using the CA. If force is set, recreate the CA cert and key

        Returns:
            bool: True if successful, False otherwise
        """
        cert_auth = CertStore(self.utils.log)
        if cert_auth._initialize_cert_authority(self.__force):
            host_name = gethostname()
            short_name = host_name.split('.')[0]
            if self.__force or not Path(f'/etc/openvpn/certs/{short_name}.crt').exists():
                if cert_auth.create(short_name, [short_name, host_name, f'{short_name}.local', 'localhost',
                                                 '127.0.0.1'], server=True):
                    return cert_auth.create_dhparam_pem('dh') and \
                            self.__generate_tls_crypt_file() and \
                            self.__set_server_config(short_name)
            else:
                return True
        return False

    def __generate_tls_crypt_file(self):
        """Generate a TLS crypt file. This file is used to encrypt control channel packets.

        Args:
            name (str, optional): name of the tls crypt file. Adds .key suffix Defaults to 'tls-crypt'.

        Returns:
            bool: True if successful, False otherwise
        """
        if self.utils.run_cmd('/usr/sbin/openvpn --genkey secret /etc/openvpn/certs/tls-crypt.key')[1]:
            return True
        self.utils.log.error('Failed to generate TLS crypt file')
        return False

    def __set_server_config(self, server_name: str):
        try:
            cert_dir = '/etc/openvpn/certs'
            with open(f'{Path(__file__).parent}/templates/server.conf', 'r') as file:
                data = file.read()
                data = data.replace('<PORT>', str(self.__port))
                data = data.replace('<CA>', f'{cert_dir}/vpn-ca.crt')
                data = data.replace('<CERT>', f'{cert_dir}/{server_name}.crt')
                data = data.replace('<KEY>', f'{cert_dir}/{server_name}.key')
                with open('/etc/openvpn/server/service.conf', 'w') as file:
                    file.write(data)
        except Exception:
            self.utils.log.exception('Failed to set server config')
            return False
        return self.utils._set_openvpn_owner_and_permissions()

    def __enable_ip_forwarding(self):
        try:
            config_file = Path('/etc/sysctl.conf')
            with open(config_file, 'r') as file:
                data = file.read()
                if 'net.ipv4.ip_forward=1' in data:
                    return True
            with open(config_file, 'a') as file:
                file.write('net.ipv4.ip_forward=1\n')
        except Exception:
            self.utils.log.exception('Failed to enable IP forwarding')
            return False
        return self.utils.run_cmd('sysctl -p')[1]

    def __set_server_firewall_config(self):
        if self.utils.is_firewalld_active():
            for cmd in [f'firewall-cmd --permanent --add-port={self.__port}/udp',
                        'firewall-cmd --permanent --add-masquerade',
                        'firewall-cmd --permanent --zone=trusted --add-interface=tun0',
                        'firewall-cmd --permanent --add-forward-port=port=53:proto=udp:toaddr=10.8.0.1',
                        'firewall-cmd --reload']:
                if not self.utils.run_cmd(cmd)[1]:
                    self.utils.log.error(f'Failed to configure firewall rules: {cmd}')
                    return False
            return True
        self.utils.log.info('Firewalld is not active. Skipping firewall configuration. Add manually for your system')
        return False

    def __set_client_firewall_config(self):
        if self.utils.is_firewalld_active():
            for cmd in [f'firewall-cmd --permanent --add-port={self.__port}/udp', 'firewall-cmd --reload']:
                if not self.utils.run_cmd(cmd)[1]:
                    self.utils.log.error(f'Failed to configure firewall rules: {cmd}')
                    return False
            return True
        self.utils.log.info('Firewalld is not active. Skipping firewall configuration. Add manually for your system')
        return False

    def __get_client_bundle_data(self) -> dict:
        try:
            with open(self.__bundle_path, 'rb') as file:
                data = file.read()
        except Exception:
            self.utils.log.exception(f'Failed to read bundle: {self.__bundle_path}')
            return {}
        return self.utils._decrypt_bundle(data, self.__passwd)

    def __set_client_config(self, data: dict):
        for key, value in data.items():
            if key == 'port':
                self.__port = value
                continue
            elif key == 'config':
                config_file = '/etc/openvpn/client/service.conf'
            else:
                config_file = f'/etc/openvpn/certs/{key}'
            try:
                with open(config_file, 'w') as file:
                    file.write(value)
            except Exception:
                self.utils.log.exception(f'Failed to set config: {key}')
                return False
        return True

    def __load_and_set_client_config(self):
        data = self.__get_client_bundle_data()
        if data:
            return self.__set_client_config(data) and self.utils._set_openvpn_owner_and_permissions()
        return False

    def run_server_init(self) -> bool:
        """Run the server initialization process

        Returns:
            bool: True if successful, False otherwise
        """
        self.utils = VpnUtils('server')
        for method in [self.__make_dirs, self.__install_openvpn, self.__create_ca_serial_handler,
                       self.__create_cert_subject, self.__initialize_cert_authority, self.__enable_ip_forwarding,
                       self.__set_server_firewall_config, self.utils._start_and_enable_vpn_server]:
            if not method():
                self.utils.log.error(f'Failed to initialize server: {method.__name__}')
                return False
        return True

    def run_client_init(self, bundle_path: str, passwd: bool = False):
        """Run the client initialization process

        Returns:
            bool: True if successful, False otherwise
        """
        self.utils = VpnUtils('client')
        self.__bundle_path = bundle_path
        if not Path(self.__bundle_path).exists():
            self.utils.log.error(f'Bundle not found: {self.__bundle_path}')
            return False
        self.__passwd = self.utils._prompt_for_passwd() if passwd else ''
        for method in [self.__make_dirs, self.__install_openvpn, self.__load_and_set_client_config,
                       self.__set_client_firewall_config, self.utils._start_and_enable_vpn_server]:
            if not method():
                return False
        return True
