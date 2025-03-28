from socket import gethostname
from pathlib import Path
from platform import freedesktop_os_release
from shutil import which
from json import dump

from vpn.vpn_utils import VpnUtils
from vpn.cert_auth import CertStore


class Init():
    def __init__(self, port: int | str = 1194, force: bool = False):
        """Initialize the vpn environment

        Args:
            force (bool, optional): Option to recreate env objects. Defaults to False.
        """
        self.utils: VpnUtils | None = None
        self.__port = port
        self.__force = force
        self.__bundle_path = ''
        self.__passwd = ''
        self.__install_cmd = self.__set_install_cmd()
        if not self.__install_cmd:
            raise Exception('Unsupported OS or package manager')

    def __make_dirs(self) -> bool:
        """Create the necessary directories for the vpn environment

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            for name in ['/etc/openvpn/certs', '/etc/openvpn/server', '/etc/openvpn/client', '/etc/openvpn/logs']:
                Path(name).mkdir(parents=True, exist_ok=True)
        except Exception:
            self.utils.log.exception('Failed to create directories')
            return False
        return self.__make_resolve_bkp()

    def __make_resolve_bkp(self) -> bool:
        """Create a backup of the resolve file so it can be restored when vpn service is stopped or DNS issues occur

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open('/etc/resolv.conf', 'r') as file:
                data = file.read()
            with open('/etc/openvpn/bkp.resolv.conf', 'w') as file:
                file.write(data)
            return True
        except Exception:
            self.utils.log.exception('Failed to create resolve backup')
            return False

    def __set_install_cmd(self) -> str:
        """Set the package manager install command based on the OS

        Returns:
            str: The package manager install command
        """
        os_id = freedesktop_os_release().get('ID_LIKE').lower()
        if 'debian' in os_id:
            return 'apt install -y '
        if 'rhel' in os_id:
            if which('dnf'):
                return 'dnf install -y '
            if which('yum'):
                return 'yum install -y '
            self.utils.log.error(f'Unable to find package manager for RHEL based system: {os_id}')
        else:
            self.utils.log.error(f'Unsupported OS: {os_id}')
        return ''

    def __install_epel_repo(self) -> bool:
        """Install the EPEL repository for RHEL based systems

        Returns:
            bool: True if successful, False otherwise
        """
        if 'dnf' in self.__install_cmd or 'yum' in self.__install_cmd:
            return self.utils.run_cmd(self.__install_cmd + 'epel-release')[1]
        return True

    def __install_openvpn(self) -> bool:
        """Install the openvpn package and dependencies

        Returns:
            bool: True if successful, False otherwise
        """
        if self.__install_epel_repo():
            if self.utils.run_cmd(self.__install_cmd + 'openvpn')[1]:
                return True
        self.utils.log.error('Failed to install vpn dependencies')
        return False

    def __install_dnscrypt_proxy(self) -> bool:
        """Install the dnscrypt-proxy package

        Returns:
            bool: True if successful, False otherwise
        """
        if self.utils.run_cmd(self.__install_cmd + 'dnscrypt-proxy')[1]:
            return self.__set_dnscrypt_proxy_config()
        self.utils.log.error('Failed to install dnscrypt-proxy')
        return False

    def __set_dnscrypt_proxy_config(self) -> bool:
        """Set the dnscrypt-proxy config file

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(f'{Path(__file__).parent}/templates/dnscrypt-proxy.toml', 'r') as file:
                data = file.read()
            with open('/etc/dnscrypt-proxy/dnscrypt-proxy.toml', 'w') as file:
                file.write(data)
        except Exception:
            self.utils.log.exception('Failed to set dnscrypt-proxy config')
            return False
        return self.__start_and_enable_dnscrypt_proxy()

    def __start_and_enable_dnscrypt_proxy(self) -> bool:
        """Start and enable the dnscrypt-proxy service

        Returns:
            bool: True if successful, False otherwise
        """
        return self.utils.run_cmd('systemctl enable --now dnscrypt-proxy')[1]

    def __create_cert_subject(self) -> bool:
        """Create the CA subject file if it does not exist or force is set

        Returns:
            bool: True if successful, False otherwise
        """
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
        """Initialize the certificate authority and create the server certificate, dhparam file and tls-crypt file.
        Set the server config file.

        Returns:
            bool: True if successful, False otherwise
        """
        cert_auth = CertStore(self.utils.log)
        if cert_auth._initialize_cert_authority(self.__force):
            host_name = gethostname()
            short_name = host_name.split('.')[0]
            if self.__force or not Path(f'/etc/openvpn/certs/{short_name}.crt').exists():
                if cert_auth.create(short_name, [short_name, host_name, f'{short_name}.local', 'localhost',
                                                 '127.0.0.1'], is_server=True):
                    return cert_auth.create_dhparam_pem('dh') and \
                        self.__generate_tls_crypt_file() and self.__set_server_config(short_name)
            else:
                return True
        return False

    def __generate_tls_crypt_file(self) -> bool:
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

    def __set_server_config(self, server_name: str) -> bool:
        """Set the server config file

        Args:
            server_name (str): The server name

        Returns:
            bool: True if successful, False otherwise
        """
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

    def __enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding in the sysctl.conf file

        Returns:
            bool: True if successful, False otherwise
        """
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

    def __set_server_firewall_config(self) -> bool:
        """Set the firewall rules for the server

        Returns:
            bool: True if successful, False otherwise
        """
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

    def __set_client_firewall_config(self) -> bool:
        """Set the firewall rules for the client

        Returns:
            bool: True if successful, False otherwise
        """
        if self.utils.is_firewalld_active():
            for cmd in [f'firewall-cmd --permanent --add-port={self.__port}/udp', 'firewall-cmd --reload']:
                if not self.utils.run_cmd(cmd)[1]:
                    self.utils.log.error(f'Failed to configure firewall rules: {cmd}')
                    return False
            return True
        self.utils.log.info('Firewalld is not active. Skipping firewall configuration. Add manually for your system')
        return False

    def __get_client_bundle_data(self) -> dict:
        """Get the client bundle data by reading the file in bytes and decrypting the data using the password or
        default encryption key

        Returns:
            dict: The client bundle data
        """
        try:
            with open(self.__bundle_path, 'rb') as file:
                data = file.read()
        except Exception:
            self.utils.log.exception(f'Failed to read bundle: {self.__bundle_path}')
            return {}
        return self.utils._decrypt_bundle(data, self.__passwd)

    def __set_client_config(self, data: dict) -> bool:
        """Set the client config files

        Args:
            data (dict): The client bundle data

        Returns:
            bool: True if successful, False otherwise
        """
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

    def __load_and_set_client_config(self) -> bool:
        """Load the client bundle data and set the client config files

        Returns:
            bool: True if successful, False otherwise
        """
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
        for method in [self.__make_dirs, self.__install_openvpn, self.__install_dnscrypt_proxy,
                       self.__create_cert_subject, self.__initialize_cert_authority,
                       self.__enable_ip_forwarding, self.__set_server_firewall_config,
                       self.utils._start_and_enable_vpn_server]:
            if not method():
                self.utils.log.debug(f'Failed to initialize server: {method.__name__}')
                return False
        return True

    def run_client_init(self, bundle_path: str, passwd: bool = False):
        """Run the client initialization process

        Args:
            bundle_path (str): The client bundle path
            passwd (bool, optional): Option to prompt for password. Defaults to False.

        Returns:
            bool: True if successful, False otherwise
        """
        self.utils = VpnUtils('client')
        self.__bundle_path = bundle_path
        if not Path(self.__bundle_path).exists():
            self.utils.log.error(f'Bundle not found: {self.__bundle_path}')
            return False
        self.__passwd = self.utils._prompt_for_passwd() if passwd else ''
        for method in [self.__make_dirs, self.__install_openvpn,
                       self.__load_and_set_client_config, self.__set_client_firewall_config,
                       self.utils._start_and_enable_vpn_server]:
            if not method():
                self.utils.log.debug(f'Failed to initialize client: {method.__name__}')
                return False
        return True
