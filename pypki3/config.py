# vim: expandtab tabstop=4 shiftwidth=4
'Functions for handling configuration.'

from configparser import ConfigParser
from collections import namedtuple
from enum import auto, Enum
from getpass import getpass
from json import loads
from os import environ
from pathlib import Path
from time import sleep
from typing import Any, List, Optional, Tuple

import ssl
import subprocess
import sys
import datetime

from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cryptography import x509

from pem import parse as parse_pem, PrivateKey, Certificate

from temppath import TemporaryPath, TemporaryPathContext

from .exceptions import Pypki3Exception
from .utils import in_ipython, in_nbgallery

class ConfigType(Enum):
    Pypki2 = auto()
    Pypki3 = auto()

# Using namedtuple instead of dataclass for Python 3.6 compatibility
Config = namedtuple('Config', ['p12', 'pem', 'ca'])
LoadedPKIBytes = namedtuple('LoadedPKIBytes', ['key', 'cert'])

def make_pypki3_config(path: Path) -> Config:
    config = ConfigParser()
    config.read(path)

    p12 = config.get('global', 'p12', fallback=None)
    pem = config.get('global', 'pem', fallback=None)
    ca = config.get('global', 'ca',  fallback=None)

    p12_path = Path(p12) if p12 is not None else None
    pem_path = Path(pem) if pem is not None else None
    ca_path = Path(ca) if ca is not None else None

    return Config(
        p12=p12_path,
        pem=pem_path,
        ca=ca_path,
    )

def make_pypki2_config(path: Path) -> Config:
    '''
    Create a Config instance from a pypki2 JSON configuration
    file, which looked like this:

    ```json
    {
        "p12": {
            "path": "/home/you/certificates/you.p12"
        },
        "ca": "/home/you/certificates/certificate_authorities_file.pem"
    }
    ```
    '''
    config = loads(path.read_text())
    p12 = config.get('p12', None)

    if p12 is not None:
        p12 = p12.get('path', None)

    ca = config.get('ca', None)

    p12_path = Path(p12) if p12 is not None else None
    ca_path = Path(ca) if ca is not None else None

    return Config(
        p12=p12_path,
        pem=None,  # PEM config never really worked in pypki2
        ca=ca_path,
    )

def pypki2_config_ready(config_path: Path) -> bool:
    '''
    Returns True if the pypki2 config file exists
    and contains a .p12 file path.  Otherwise False.
    '''
    try:
        config = make_pypki2_config(config_path)
        return config.p12 is not None
    except FileNotFoundError:
        return False

def ipython_config(config_path: Path) -> bool:
    '''
    Attempts to use the pypki2 configuration dialog.
    This will only work in the correct environment.
    Returns True if the run was successful.
    Returns False if nothing happened because the
    environment was not correct.
    '''
    if in_ipython() and in_nbgallery():
        if pypki2_config_ready(config_path):
            return True

        from IPython.display import display, Javascript  # pylint: disable=E0401
        display(Javascript("MyPKI.init({'no_verify':true, configure:true});"))

        # Loop until the user completes the
        # Javascript dialog above, which
        # creates the .mypki file.
        while not config_path.exists():
            sleep(2)

        return pypki2_config_ready(config_path)

    return False

def get_config_path() -> Tuple[ConfigType, Path]:
    'Finds the path of the config file or raises an exception.'

    # standard paths
    possible_paths: List[Tuple[ConfigType, Path]] = [
        (ConfigType.Pypki3, Path.home().joinpath('.config/pypki3/config.ini')),
        (ConfigType.Pypki3, Path('/etc/pypki3/config.ini')),
    ]

    if 'PYPKI3_CONFIG' in environ:
        # append to front if configured; highest priority
        possible_paths = [(ConfigType.Pypki3, Path(environ['PYPKI3_CONFIG']))] + possible_paths

    if 'MYPKI_CONFIG' in environ:
        # append to end if configured; lowest priority
        possible_paths = possible_paths + [(ConfigType.Pypki2, Path(environ['MYPKI_CONFIG']).joinpath('mypki_config'))]

    for config_type, path in possible_paths:
        if path.exists():
            return config_type, path

    # We could not find a pypki3 configuration, or predefined pypki2 configuration,
    # so try using the config dialog.
    pypki2_config_path = Path.home().joinpath('.mypki')

    if ipython_config(pypki2_config_path):
        return ConfigType.Pypki2, pypki2_config_path

    possible_paths_str = ', '.join([str(p[1]) for p in possible_paths])
    raise Pypki3Exception(f'Could not locate pypki3 config at paths {possible_paths_str}')

def combine_key_and_cert(combined_path: Path, key_path: Path, cert_path: Path) -> None:
    with combined_path.open('wb') as outfile:
        outfile.write(key_path.read_bytes())
        outfile.write(cert_path.read_bytes())

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

def get_decrypted_p12(config: Config, password: Optional[str]) -> LoadedPKIBytes:
    p12_data = config.p12.read_bytes()
    return load_p12_with_password(p12_data, password)

def loaded_encoded_pem(key_obj: Any, cert_obj: Any) -> LoadedPKIBytes:
    key_bytes = key_obj.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    cert_bytes = cert_obj.public_bytes(Encoding.PEM)
    return LoadedPKIBytes(key_bytes, cert_bytes)

def separate_pem(pem_data: bytes) -> Tuple[bytes, List[bytes]]:
    pem_objs = parse_pem(pem_data)
    key = None
    certs = list()
    
    for pem_obj in reversed(pem_objs):
        if isinstance(pem_obj, PrivateKey):
            key = pem_obj
        elif isinstance(pem_obj, Certificate):
            certs.append(pem_obj)

    if not key and not certs:
        raise Pypki3Exception('PEM missing key and certificate(s)')

    if key and not certs:
        raise Pypki3Exception('PEM contains key but is missing certificate(s)')

    if certs and not key:
        raise Pypki3Exception('PEM contains certificate(s) but is missing key')

    return key.as_bytes(), [cert.as_bytes() for cert in certs]

def find_matching_cert(key_obj: Any, certs_data: List[bytes]) -> Any:
    key_public_num = key_obj.public_key().public_numbers()

    for cert_data in certs_data:
        cert_obj = x509.load_pem_x509_certificate(cert_data)
        cert_public_num = cert_obj.public_key().public_numbers()

        if key_public_num.e == cert_public_num.e and key_public_num.n == cert_public_num.n:
            return cert_obj

    raise Pypki3Exception('Could not find certificate that matches key')

def load_pem_with_password(pem_data: bytes, password: Optional[str]) -> LoadedPKIBytes:
    key_data, certs_data = separate_pem(pem_data)

    # try the provided password
    if password is not None:
        key_obj = load_pem_private_key(key_data, password.encode('utf8'))
        cert_obj = find_matching_cert(key_obj, certs_data)
        return loaded_encoded_pem(key_obj, cert_obj)

    # try no password
    try:
        key_obj = load_pem_private_key(key_data, password=None)
    except TypeError:
        pass
    else:
        cert_obj = find_matching_cert(key_obj, certs_data)
        return loaded_encoded_pem(key_obj, cert_obj)

    # prompt for password
    while True:
        try:
            input_password = getpass(prompt='Enter pem private key password: ')
            key_obj = load_pem_private_key(key_data, input_password.encode('utf8'))

        except ValueError:
            print('Incorrect password for pem private key.  Please try again.')
            continue

        else:
            cert_obj = find_matching_cert(key_obj, certs_data)
            return loaded_encoded_pem(key_obj, cert_obj)

def get_decrypted_pem(config: Config, password: Optional[str]) -> LoadedPKIBytes:
    pem_data = config.pem.read_bytes()
    return load_pem_with_password(pem_data, password)

def verify_config(config: Config) -> None:
    if config.p12 is None and config.pem is None:
        raise Pypki3Exception('Config must contain either "p12" or "pem" entry')

    if config.ca is None:
        raise Pypki3Exception('Config missing "ca" entry')

    if config.p12 is not None and not config.p12.exists():
        raise Pypki3Exception(f'p12 does not exist at {config.p12}')

    if config.pem is not None and not config.pem.exists():
        raise Pypki3Exception(f'pem does not exist at {config.pem}')

    if not config.ca.exists():
        raise Pypki3Exception(f'certificate authority file does not exist at {config.ca}')

def make_config_by_type(config_type_path: Tuple[ConfigType, Path]) -> Config:
    '''
    Returns a Config instance based on the type of config file
    and its config info, or raises an exception if invalid.
    '''
    config_type, path = config_type_path

    if config_type == ConfigType.Pypki3:
        return make_pypki3_config(path)
    elif config_type == ConfigType.Pypki2:
        return make_pypki2_config(path)

    raise Pypki3Exception('Received unrecognized ConfigType')

class Loader:
    def __init__(self) -> None:
        self.config = make_config_by_type(get_config_path())
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
            if self.config.p12 is not None:
                self.loaded_pki_bytes = get_decrypted_p12(self.config, password)
            elif self.config.pem is not None:
                self.loaded_pki_bytes = get_decrypted_pem(self.config, password)
        self.check_cert_expiration()

    def check_cert_expiration(self) -> None:
        '''
        Checks if the loaded certificate has expired.
        Raises a Pypki3Exception if the certificate is expired.
        '''
        cert = x509.load_pem_x509_certificate(self.loaded_pki_bytes.cert)
        expiration_date = cert.not_valid_after_utc
        if datetime.datetime.now(tz=datetime.timezone.utc) > expiration_date:
            raise Pypki3Exception(f'Certificate expired on {expiration_date}. Please renew your certificate.')

    def ca_path(self) -> Path:
        'Convenience function for getting the certificate authority file path.'
        return self.config.ca

    def ssl_context(self, password: Optional[str]=None) -> ssl.SSLContext:
        '''
        Creates an ssl.SSLContext object based on the settings in
        config.ini.  It takes an optional password parameter for
        decrypting the certificate.  Otherwise, it will prompt for
        a password if the certificate is encrypted.
        '''
        ContextManagerClass = CreateNamedTemporaryKeyCertPathsContextManager(self)

        with ContextManagerClass(password) as key_cert_paths:
            key_path = key_cert_paths[0]
            cert_path = key_cert_paths[1]
            context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
            context.load_cert_chain(cert_path, key_path)
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self.ca_path())
            return context

    def pip(self, *args, **kwargs):
        new_args = []

        if 'args' in kwargs:
            new_args = kwargs['args']
        elif len(args) > 0 and len(args[0]) > 0:
            new_args = args[0]

        new_args = [ arg for arg in new_args if '--client-cert=' not in arg ]
        new_args = [ arg for arg in new_args if '--cert=' not in arg ]

        ContextManagerClass = CreateNamedTemporaryKeyCertPathsContextManager(self)

        with ContextManagerClass() as key_cert_paths:
            key_path = key_cert_paths[0]
            cert_path = key_cert_paths[1]
            ca_path = self.ca_path()

            with TemporaryPathContext() as combined_key_cert_path:
                combine_key_and_cert(combined_key_cert_path, key_path, cert_path)
                new_args.append(f'--client-cert={combined_key_cert_path}')
                new_args.append(f'--cert={ca_path}')
                new_args.append('--disable-pip-version-check')

                command = [sys.executable, '-m', 'pip'] + new_args
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

                for line in iter(process.stdout.readline, b''):
                    sys.stdout.write(line.decode(sys.stdout.encoding))

def CreateNamedTemporaryKeyCertPathsContextManager(loader: Loader):
    '''
    Returns a context manager class with the
    loader already defined.  This is done so
    external users of the pypki3 package can
    reuse the same loader that's already been
    prepare()'ed when creating the context.
    '''

    class ContextManager:
        def __init__(self, password: Optional[str]=None) -> None:
            self.loader = loader  # uses the loader passed in above
            self.password = password

        def __enter__(self) -> Tuple[Path, Path]:
            self.loader.prepare(self.password)
            self.key_path = TemporaryPath()  # pylint: disable=W0201
            self.cert_path = TemporaryPath()  # pylint: disable=W0201
            self.key_path.write_bytes(self.loader.loaded_pki_bytes.key)
            self.cert_path.write_bytes(self.loader.loaded_pki_bytes.cert)
            return self.key_path, self.cert_path

        def __exit__(self, exc_type, exc_value, exc_traceback) -> None:
            self.key_path.unlink()
            self.cert_path.unlink()

    return ContextManager  # returns the class, not an instance
