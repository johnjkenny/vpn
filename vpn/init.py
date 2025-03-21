from pwd import getpwnam
from grp import getgrnam
from os import chown
from socket import gethostname
from pathlib import Path
from os import remove
from platform import freedesktop_os_release
from shutil import which
from json import dump

from vpn.vpn_utils import VpnUtils
from vpn.cert_auth import CertStore


class Init():
    def __init__(self, force: bool = False):
        """Initialize the web server environment

        Args:
            force (bool, optional): Option to recreate env objects. Defaults to False.
        """
        self.utils: VpnUtils | None = None
        self.__force = force

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

    '''
    def __create_keys(self) -> bool:
        """Create the encryption keys. Will override the keys if force is set

        Returns:
            bool: True if successful, False otherwise
        """
        if self.__force or not Path(self.utils.encrypt.key_file).exists():
            return self.utils.encrypt._create_key()
        return True
    '''

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

    def __generate_tls_crypt_file(self, file_name='tls-crypt'):
        """Generate a TLS crypt file. This file is used to encrypt control channel packets.

        Args:
            name (str, optional): name of the tls crypt file. Adds .key suffix Defaults to 'tls-crypt'.

        Returns:
            bool: True if successful, False otherwise
        """
        if self.utils.run_cmd(f'/usr/sbin/openvpn --genkey secret /etc/openvpn/certs/{file_name}.key')[1]:
            return True
        self.utils.log.error('Failed to generate TLS crypt file')
        return False

    def __set_server_config(self, server_name: str):
        try:
            cert_dir = '/etc/openvpn/certs'
            with open(f'{Path(__file__).parent}/templates/server.conf', 'r') as file:
                data = file.read()
                data = data.replace('<CA>', f'{cert_dir}/vpn-ca.crt')
                data = data.replace('<CERT>', f'{cert_dir}/{server_name}.crt')
                data = data.replace('<KEY>', f'{cert_dir}/{server_name}.key')
                data = data.replace('<DH>', f'{cert_dir}/dh.pem')
                data = data.replace('<TLS-CRYPT>', f'{cert_dir}/tls-crypt.key')
                with open('/etc/openvpn/server/service.conf', 'w') as file:
                    file.write(data)
        except Exception:
            self.utils.log.exception('Failed to set server config')
            return False
        return self.__set_openvpn_owner_and_permissions()

    def __set_openvpn_owner_and_permissions(self):
        try:
            path = Path('/etc/openvpn')
            uid = getpwnam('root').pw_uid
            gid = getgrnam('openvpn').gr_gid
            chown(path, uid, gid)
            path.chmod(0o660)
        except Exception:
            self.utils.log.exception('Failed to set server directory owner and permissions')
            return False
        return self.__set_cert_owner_and_permissions()

    def __set_cert_owner_and_permissions(self):
        try:
            path = Path('/etc/openvpn/certs')
            uid = getpwnam('root').pw_uid
            gid = getgrnam('root').gr_gid
            for item in path.rglob("*"):
                chown(item, uid, gid)
                item.chmod(0o600)
            return True
        except Exception:
            self.utils.log.exception('Failed to set server certs owner and permissions')
        return False

    """
    def __set_server_firewall_rules(self):
        self.log.info('Setting VPN server firewall rules')
        for cmd in ['firewall-cmd --permanent --add-service=openvpn',
                    'firewall-cmd --permanent --add-masquerade',
                    'firewall-cmd --reload']:
            if not self.tools.run_cmd(cmd)[1]:
                self.log.error('Failed to set server firewall rules')
                return False
        self.log.debug('Successfully set server firewall rules')
        return True
    """

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

    def _run_server_init(self) -> bool:
        """Run the server initialization process

        Returns:
            bool: True if successful, False otherwise
        """
        self.utils = VpnUtils('server')
        for method in [self.__make_dirs, self.__install_openvpn, self.__create_ca_serial_handler,
                       self.__create_cert_subject, self.__initialize_cert_authority, self.__enable_ip_forwarding,
                       self.utils._start_and_enable_vpn_server]:
            if not method():
                self.utils.log.error(f'Failed to initialize server: {method.__name__}')
                return False
        return True

    def _run_client_init(self):
        """Run the client initialization process

        Returns:
            bool: True if successful, False otherwise
        """
        self.utils = VpnUtils('client')
        for method in [self.__make_dirs, self.__install_openvpn]:
            if not method():
                self.utils.log.error(f'Failed to initialize client: {method.__name__}')
                return False
        return True


# ToDo: set dir permissions so all new files get the same permissions under /etc/openvpn/certs
# ToDO: enable firewall or iptables rules for server and client
'''
firewall-cmd --permanent --add-service=openvpn
firewall-cmd --permanent --add-masquerade
firewall-cmd --reload
- or -
iptables -A INPUT -p udp --dport 1194 -j ACCEPT
iptables -A FORWARD -i tun0 -o eth0 -j ACCEPT
iptables -A FORWARD -i eth0 -o tun0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables-save > /etc/sysconfig/iptables
'''

# ToDO: add client config and cert bundle handling
