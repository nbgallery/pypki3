# vim: expandtab tabstop=4 shiftwidth=4
'Functions for handling configuration.'

from configparser import ConfigParser
from dataclasses import dataclass
from getpass import getpass
from os import environ
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Optional, Tuple

import ssl

from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography import x509

from .exceptions import Pypki3Exception

@dataclass
class LoadedPKIBytes:
    key: bytes
    cert: bytes

def get_config_path() -> Path:
    'Finds the path of the config file or raises an exception.'
    possible_paths: Tuple[Path] = [
        Path.home().joinpath('.config/pypki3/config.ini'),
        Path('/etc/pypki3/config.ini'),
    ]

    if 'PYPKI3_CONFIG' in environ:
        possible_paths = [Path(environ['PYPKI3_CONFIG'])] + possible_paths

    for path in possible_paths:
        if path.exists():
            return path

    raise Pypki3Exception(f'Could not locate pypki3 config at paths {possible_paths}')

def loaded_encoded_p12(key_cert_tuple: Tuple[Any, ...]) -> LoadedPKIBytes:
    key_bytes = key_cert_tuple[0].private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    cert_bytes = key_cert_tuple[1].public_bytes(Encoding.PEM)
    return LoadedPKIBytes(key_bytes, cert_bytes)

def load_p12_with_password(p12_data: bytes, password: Optional[str]) -> LoadedPKIBytes:
    # try the provided password
    if password is not None:
        return loaded_encoded_p12(load_key_and_certificates(p12_data, password.encode('utf8')))

    # try no password
    try:
        return loaded_encoded_p12(load_key_and_certificates(p12_data, None))
    except ValueError:
        pass

    # prompt for password
    while True:
        try:
            input_password = getpass(prompt='Enter p12 private key password: ')
            return loaded_encoded_p12(load_key_and_certificates(p12_data, input_password.encode('utf8')))

        except ValueError:
            print('Incorrect password for p12 private key.  Please try again.')
            continue

def get_decrypted_p12(config: ConfigParser, password: Optional[str]) -> LoadedPKIBytes:
    p12_path = Path(config.get('global', 'p12'))
    p12_data = p12_path.read_bytes()
    return load_p12_with_password(p12_data, password)

def loaded_encoded_pem(key_obj: Any, cert_obj: Any) -> LoadedPKIBytes:
    key_bytes = key_obj.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    cert_bytes = cert_obj.public_bytes(Encoding.PEM)
    return LoadedPKIBytes(key_bytes, cert_bytes)

def load_pem_with_password(pem_data: bytes, password: Optional[str]) -> LoadedPKIBytes:
    # try the provided password
    if password is not None:
        key_obj = load_pem_private_key(pem_data, password.encode('utf8'))
        cert_obj = x509.load_pem_x509_certificate(pem_data)
        return loaded_encoded_pem(key_obj, cert_obj)

    # try no password
    try:
        key_obj = load_pem_private_key(pem_data, password=None)
    except ValueError:
        pass
    else:
        cert_obj = x509.load_pem_x509_certificate(pem_data)
        return loaded_encoded_pem(key_obj, cert_obj)

    # prompt for password
    while True:
        try:
            input_password = getpass(prompt='Enter pem private key password: ')
            key_obj = load_pem_private_key(pem_data, input_password.encode('utf8'))

        except ValueError:
            print('Incorrect password for pem private key.  Please try again.')
            continue

        else:
            cert_obj = x509.load_pem_x509_certificate(pem_data)
            return loaded_encoded_pem(key_obj, cert_obj)

def get_decrypted_pem(config: ConfigParser, password: Optional[str]) -> LoadedPKIBytes:
    pem_path = Path(config.get('global', 'pem'))
    pem_data = pem_path.read_bytes()
    return load_pem_with_password(pem_data, password)

def verify_config(config: ConfigParser) -> None:
    if 'global' not in config:
        raise Pypki3Exception('[global] section missing from config')

    if 'p12' not in config['global'] and 'pem' not in config['global']:
        raise Pypki3Exception('[global] section must contain either "p12" or "pem" entry')

    if 'ca' not in config['global']:
        raise Pypki3Exception('[global] section missing "ca" entry')

    if 'p12' in config['global']:
        p12_path = Path(config.get('global', 'p12'))

        if not p12_path.exists():
            raise Pypki3Exception(f'p12 does not exist at {p12_path}')

    if 'pem' in config['global']:
        pem_path = Path(config.get('global', 'pem'))

        if not pem_path.exists():
            raise Pypki3Exception(f'pem does not exist at {pem_path}')

    ca_path = Path(config.get('global', 'ca'))

    if not ca_path.exists():
        raise Pypki3Exception(f'certificate authority file does not exist at {ca_path}')

class Loader:
    def __init__(self) -> None:
        self.config = ConfigParser()
        self.config.read(get_config_path())
        self.loaded_pki_bytes = None
        verify_config(self.config)

    def prepare(self, password: Optional[str]) -> None:
        if self.loaded_pki_bytes is None:
            if 'p12' in self.config['global']:
                self.loaded_pki_bytes = get_decrypted_p12(self.config, password)
            elif 'pem' in self.config['global']:
                self.loaded_pki_bytes = get_decrypted_pem(self.config, password)

    def ca_path(self) -> Path:
        'Convenience function for getting the certificate authority file path.'
        return Path(self.config.get('global', 'ca'))

    def ssl_context(self, password: Optional[str]=None) -> ssl.SSLContext:
        self.prepare(password)

        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            key_path = temp_path.joinpath('key.pem')
            cert_path = temp_path.joinpath('cert.pem')
            key_path.write_bytes(self.loaded_pki_bytes.key)
            cert_path.write_bytes(self.loaded_pki_bytes.cert)
            context = ssl.SSLContext()
            context.load_cert_chain(cert_path, key_path)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self.ca_path())
            return context
