"""
Cryptographic components for CodeTwo backup decryption
"""
import hashlib
import xml.etree.ElementTree as ET
from typing import Optional, Tuple
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from .config import MASTER_KEY, MASTER_IV, CODETWO_ALPHABET


class CAlphabetEncoder:
    """CodeTwo's custom Base32-like encoder"""

    BITS_PER_CHAR = 5

    def decode(self, data: str) -> bytes:
        """Decode storage key string to bytes"""
        if not data:
            raise ValueError("Parameter cannot be empty")

        result = []
        current_byte = 0
        bits_in_current_byte = 0

        for char in data:
            index = CODETWO_ALPHABET.index(char)
            if index < 0:
                raise ValueError(f"Invalid character: {char}")

            for bit_pos in range(self.BITS_PER_CHAR - 1, -1, -1):
                bit = (index >> bit_pos) & 1
                current_byte |= (bit << (7 - bits_in_current_byte))
                bits_in_current_byte += 1

                if bits_in_current_byte == 8:
                    result.append(current_byte)
                    current_byte = 0
                    bits_in_current_byte = 0

        if bits_in_current_byte > 0:
            result.append(current_byte)

        return bytes(result)


class CodeTwoDecryptor:
    """Core decryption engine for CodeTwo backups"""

    def __init__(self):
        self.encoder = CAlphabetEncoder()
        self.storage_key: Optional[str] = None
        self.aes_key: Optional[bytes] = None
        self.aes_iv: Optional[bytes] = None

    def decrypt_storage_config(self, xmc_file_path: str) -> dict:
        """Decrypt storage_3.xmc configuration file"""
        with open(xmc_file_path, 'rb') as f:
            encrypted_data = f.read()

        cipher = AES.new(MASTER_KEY, AES.MODE_CBC, MASTER_IV)
        decrypted_data = cipher.decrypt(encrypted_data)

        try:
            decrypted_data = unpad(decrypted_data, AES.block_size)
        except ValueError:
            pass

        xml_content = decrypted_data.decode('utf-8')
        root = ET.fromstring(xml_content)

        # Extract storage key with namespace handling
        ns = {'': 'http://www.codetwo.com'}
        crypto_node = root.find('.//CryptoDescriptor', ns)
        if crypto_node is None:
            crypto_node = root.find('.//{http://www.codetwo.com}CryptoDescriptor')

        if crypto_node is not None:
            key_node = crypto_node.find('.//Key', ns)
            if key_node is None:
                key_node = crypto_node.find('.//{http://www.codetwo.com}Key')
            self.storage_key = key_node.text if key_node is not None else None

        return {
            'storage_key': self.storage_key,
            'xml_content': xml_content
        }

    def derive_aes_keys(self, storage_key: Optional[str] = None) -> Tuple[bytes, bytes]:
        """Derive AES key and IV from storage key"""
        if storage_key is None:
            storage_key = self.storage_key

        if storage_key is None:
            raise ValueError("Storage key not available")

        decoded_bytes = self.encoder.decode(storage_key)
        guid_bytes = decoded_bytes[:16]

        self.aes_key = guid_bytes + guid_bytes  # 32 bytes
        self.aes_iv = guid_bytes                 # 16 bytes

        return self.aes_key, self.aes_iv

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using derived AES keys"""
        if self.aes_key is None or self.aes_iv is None:
            raise ValueError("AES keys not initialized")

        cipher = AES.new(self.aes_key, AES.MODE_CBC, self.aes_iv)
        decrypted_data = cipher.decrypt(encrypted_data)

        try:
            decrypted_data = unpad(decrypted_data, AES.block_size)
        except ValueError:
            pass

        return decrypted_data

    def decrypt_file(self, input_path: str) -> bytes:
        """Decrypt a single .dac file"""
        with open(input_path, 'rb') as f:
            encrypted_data = f.read()

        return self.decrypt_data(encrypted_data)

    def get_key_hashes(self) -> Tuple[str, str]:
        """Get SHA256 hashes of AES key and IV for forensic logging"""
        if self.aes_key is None or self.aes_iv is None:
            return "", ""

        key_hash = hashlib.sha256(self.aes_key).hexdigest()
        iv_hash = hashlib.sha256(self.aes_iv).hexdigest()
        return key_hash, iv_hash


def calculate_sha256(data: bytes) -> str:
    """Calculate SHA256 hash of data"""
    return hashlib.sha256(data).hexdigest()


def calculate_file_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
