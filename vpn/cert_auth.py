from logging import Logger
from datetime import datetime, timedelta
from pathlib import Path
from json import load

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec, dh
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, ParameterFormat, \
    load_pem_private_key

from vpn.logger import get_logger


class CertStore():
    def __init__(self, logger: Logger = None):
        self.log = logger or get_logger('vpn')
        self.__ca_name = 'vpn-ca'
        self.__private_key = None
        self.__subject = None
        self.__subject_alt_name = None
        self.__certificate = None

    @property
    def cert_dir(self) -> str:
        return '/etc/openvpn/certs'

    @property
    def ca_key(self) -> str:
        return f'/etc/openvpn/certs/{self.__ca_name}.key'

    def __generate_private_key(self) -> bool:
        """Generate private key

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.__private_key = ec.generate_private_key(ec.SECP384R1())
            return True
        except Exception:
            self.log.exception('Failed to generate private key')
        return False

    def __load_cert_subject(self) -> dict:
        try:
            with open(f'{self.cert_dir}/ca-subject', 'r') as file:
                return load(file)
        except Exception:
            self.log.exception('Failed to load CA subject')
        return {}

    def __create_subject(self, common_name: str) -> bool:
        """Create the cert subject

        Returns:
           bool: True if self.__subject set successfully, False otherwise
        """
        subject = self.__load_cert_subject()
        if subject:
            try:
                self.__subject = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, subject.get('country', 'US')),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject.get('state', 'US-STATE')),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, subject.get('city', 'US-CITY')),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject.get('company', 'US-Company')),
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject.get('department', 'US-Department')),
                    x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject.get('email', 'myEmail@email.com'))])
                return True
            except Exception:
                self.log.exception('Failed to create subject')
            return False

    def __create_subject_alternative(self, names: list) -> bool:
        """ Create subject alternative names

        Args:
            names (list, optional): List of alternative names.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            self.__subject_alt_name = x509.SubjectAlternativeName([x509.DNSName(name) for name in names])
            return True
        except Exception:
            self.log.exception('Failed to create subject alternative names')
        return False

    def __define_cert(self, issuer: object, sign_key: bytes, is_ca: bool = False, is_server: bool = False) -> bool:
        """Define certificate

        Args:
            issuer (object): The issuer of the certificate.
            sign_key (bytes): The signing key.
            is_ca (bool, optional): Determines if the certificate is a CA. Defaults to False.
            is_server (bool, optional): Determines if the certificate is for a server. Defaults to False.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            now = datetime.now()
            self.__certificate = (
                x509.CertificateBuilder()
                .subject_name(self.__subject)
                .issuer_name(issuer)
                .public_key(self.__private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now)
                .not_valid_after(now + timedelta(days=36500))  # 100 years
                .add_extension(self.__subject_alt_name, False)
                .add_extension(x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=is_server,
                    data_encipherment=False,
                    key_agreement=not is_ca,
                    key_cert_sign=is_ca,
                    crl_sign=is_ca,
                    encipher_only=False,
                    decipher_only=False), True)
            )
            if is_ca:
                self.__certificate = self.__certificate.add_extension(
                    x509.BasicConstraints(True, None), True)
            else:
                if is_server:
                    self.__certificate = self.__certificate.add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), True)
                else:
                    self.__certificate = self.__certificate.add_extension(
                        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), True)
            self.__certificate = self.__certificate.sign(sign_key, SHA256())
            return True
        except Exception:
            self.log.exception('Failed to define certificate')
        return False

    def __save_cert(self, name: str) -> bool:
        """Save certificate

        Args:
            name (str): The name of the certificate

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(f'{name}.crt', 'wb') as file:
                file.write(self.__certificate.public_bytes(Encoding.PEM))
            return True
        except Exception:
            self.log.exception('Failed to save certificate')
        return False

    def __save_key(self, name: str) -> bool:
        """Save key

        Args:
            name (str): The name of the key

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(f'{name}.key', 'wb') as file:
                file.write(self.__private_key.private_bytes(
                    Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
            return True
        except Exception:
            self.log.exception('Failed to save key')
        return False

    def __save_cert_and_key(self, name: str) -> bool:
        """Save certificate and key

        Args:
            name (str): The name of the certificate and key

        Returns:
            bool: True if successful, False otherwise
        """
        name = f'{self.cert_dir}/{name}'
        return self.__save_cert(name) and self.__save_key(name)

    def __create_cert_authority_subject(self) -> bool:
        """Create the CA subject

        Returns:
           bool: True if successful, False otherwise
        """
        return self.__create_subject(self.__ca_name) and self.__create_subject_alternative([self.__ca_name])

    def __define_ca_cert(self) -> bool:
        """Define the CA certificate

        Returns:
            Certificate object: The CA certificate on success, None otherwise
        """
        return self.__define_cert(self.__subject, self.__private_key, is_ca=True)

    def _initialize_cert_authority(self, force: bool = False) -> bool:
        """Initialize the cluster certificate authority

        Args:
            force (bool, optional): Force the initialization. Defaults to False.

        Returns:
            bool: True if successful, False otherwise
        """
        if force or not Path(f'{self.cert_dir}/{self.__ca_name}.crt').exists():
            for func in [self.__generate_private_key, self.__create_cert_authority_subject, self.__define_ca_cert]:
                if not func():
                    self.log.error(f'Failed to initialize certificate authority: {func.__name__}')
                    return False
            return self.__save_cert_and_key(self.__ca_name)
        return True

    def __load_ca_cert_and_key(self) -> dict:
        """Load the CA certificate and key

        Returns:
            dict: The CA certificate and key objects
        """
        try:
            name = f'{self.cert_dir}/{self.__ca_name}'
            with open(f'{name}.crt', 'rb') as file:
                cert = x509.load_pem_x509_certificate(file.read())
            with open(f'{name}.key', 'rb') as file:
                key = load_pem_private_key(file.read(), None)
            return {'cert': cert, 'key': key}
        except Exception:
            self.log.exception('Failed to load CA certificate and key')
        return {}

    def create(self, common_name: str, subject_alt: list = None, is_server: bool = False) -> bool:
        """Create a certificate

        Args:
            common_name (str): The common name. Name of the service or entity.
            subject_alt (list): The subject alternative names. Defaults to [].
            is_server (bool, optional): Determines if the certificate is for a server. Defaults to False.

        Returns:
            bool: True if successful, False otherwise
        """
        if subject_alt is None:
            subject_alt = [common_name]
        ca = self.__load_ca_cert_and_key()
        if ca:
            return self.__generate_private_key() and \
                self.__create_subject(common_name) and \
                self.__create_subject_alternative(subject_alt) and \
                self.__define_cert(ca.get('cert').subject, ca.get('key'), is_server=is_server) and \
                self.__save_cert_and_key(common_name)
        return False

    def create_dhparam_pem(self, name: str, key_size: int = 2048) -> bool:
        """Generate Diffie-Hellman parameters and save to file using the name provided with suffix .pem. The DH is
        used for secure key exchange on untrusted networks (like the internet).

        Args:
            name (str): The name of the DH parameters file.
            key_size (int, optional): The size of the DH key. Defaults to 2048

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            pem = dh.generate_parameters(2, key_size).parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
            with open(f'{self.cert_dir}/{name}.pem', 'wb') as file:
                file.write(pem)
            return True
        except Exception:
            self.log.exception('Failed to generate Diffie-Hellman parameters')
        return False
