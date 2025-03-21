from logging import Logger
from pathlib import Path

from cryptography.fernet import Fernet


class Cipher:
    def __init__(self, logger: Logger):
        """Create a cipher object for encryption/decryption

        Args:
            logger (Logger): logger object
        """
        self.log = logger

    @property
    def __xork(self) -> bytes:
        """XOR key for encryption/decryption of the cipher key

        Returns:
            bytes: XOR key
        """
        return b"y8rKnU8Mr6FwrWPDmExeLuaaCO6nUQ8YKAk4Uu0M8Ic="

    @property
    def key_file(self):
        """File path to store the cipher key

        Returns:
            str: file path to cipher key
        """
        return f'{Path(__file__).parent}/vpn_env/.xork'

    def _create_key(self) -> bool:
        """Generate a cipher key for encryption/decryption

        Returns:
            bool: True if key was created successfully, False otherwise
        """
        try:
            with open(self.key_file, 'wb') as key_file:
                key_file.write(self.encrypt(Fernet.generate_key(), self.__xork))
            return True
        except Exception:
            self.log.exception('Failed to create key file')
            return False

    def load_key(self) -> bytes:
        """Load the cipher key from file and decrypt it using XOR key

        Returns:
            bytes: cipher key
        """
        try:
            with open(self.key_file, 'rb') as key_file:
                return self.decrypt(key_file.read(), self.__xork)
        except Exception:
            self.log.exception('Failed to load key file')
            return b''

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> bytes:
        """Encrypt data using Fernet

        Args:
            data (bytes): data to encrypt
            key (bytes): key to encrypt data with

        Returns:
            bytes: encrypted data
        """
        return Fernet(key).encrypt(data)

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> bytes:
        """Decrypt data using Fernet

        Args:
            data (bytes): data to decrypt
            key (bytes): key to decrypt data with

        Returns:
            bytes: decrypted data
        """
        return Fernet(key).decrypt(data)
