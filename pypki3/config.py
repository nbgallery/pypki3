# vim: expandtab tabstop=4 shiftwidth=4
'Functions for handling configuration.'

from configparser import ConfigParser
from dataclasses import dataclass
from getpass import getpass
from os import environ
from pathlib import Path
from tempfile import NamedTemporaryFile
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
    except TypeError:
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

    def prepare(self, password: Optional[str]=None) -> None:
        '''
        Initiates decryption of certificates, if they haven't
        already been decrypted.  This can be useful for forcing
        the password prompt to appear before an actual call to
        ssl_context().
        '''
        if self.loaded_pki_bytes is None:
            if 'p12' in self.config['global']:
                self.loaded_pki_bytes = get_decrypted_p12(self.config, password)
            elif 'pem' in self.config['global']:
                self.loaded_pki_bytes = get_decrypted_pem(self.config, password)

    def ca_path(self) -> Path:
        'Convenience function for getting the certificate authority file path.'
        return Path(self.config.get('global', 'ca'))

    def ssl_context(self, password: Optional[str]=None) -> ssl.SSLContext:
        '''
        Creates an ssl.SSLContext object based on the settings in
        config.ini.  It takes an optional password parameter for
        decrypting the certificate.  Otherwise, it will prompt for
        a password if the certificate is encrypted.
        '''
        ContextManagerClass = self.NamedTemporaryKeyCertPaths()

        with ContextManagerClass(password) as key_cert_paths:
            key_path = key_cert_paths[0]
            cert_path = key_cert_paths[1]
            context = ssl.SSLContext()
            context.load_cert_chain(cert_path, key_path)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self.ca_path())
            return context

    def NamedTemporaryKeyCertPaths(self):
        '''
        Returns a context manager class with the
        loader already defined.  This is done so
        external users of the pypki3 package can
        reuse the same loader that's already been
        prepare()'ed when creating the context.
        '''
        loader = self

        class ContextManager:
            def __init__(self, password: Optional[str]=None) -> None:
                self.loader = loader  # uses the loader defined from self above
                self.password = password

            def __enter__(self) -> Tuple[Path, Path]:
                self.loader.prepare(self.password)  # pylint: disable=E1101
                key_file = NamedTemporaryFile(delete=False)
                cert_file = NamedTemporaryFile(delete=False)
                self.key_path = Path(key_file.name)  # pylint: disable=W0201
                self.cert_path = Path(cert_file.name) # pylint: disable=W0201
                self.key_path.write_bytes(self.loader.loaded_pki_bytes.key)  # pylint: disable=E1101
                self.cert_path.write_bytes(self.loader.loaded_pki_bytes.cert)  # pylint: disable=E1101
                return self.key_path, self.cert_path

            def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
                self.key_path.unlink()
                self.cert_path.unlink()

        return ContextManager  # returns the class, not an instance

    def pip(self, *args, **kwargs):
        try:
            import pip as _pip
        except ImportError as err:
            raise Pypki3Exception('Unable to import pip.') from err

        new_args = []

        if 'args' in kwargs:
            new_args = kwargs['args']
        elif len(args) > 0 and len(args[0]) > 0:
            new_args = args[0]

        new_args = [ arg for arg in new_args if '--client-cert=' not in arg ]
        new_args = [ arg for arg in new_args if '--cert=' not in arg ]

        ContextManagerClass = self.NamedTemporaryKeyCertPaths()

        with ContextManagerClass() as key_cert_paths:
            key_path = key_cert_paths[0]
            cert_path = key_cert_paths[1]

            new_args.append(f'--client-cert={key_path}')
            new_args.append(f'--cert={cert_path}')
            new_args.append('--disable-pip-version-check')

            _pip.main(new_args)
