# vim: expandtab tabstop=4 shiftwidth=4

# based on https://stackoverflow.com/questions/56285000/python-cryptography-create-a-certificate-signed-by-an-existing-ca-and-export

from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates

def make_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def make_cert(key, signing_key, name, issuer=None):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Colorado"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Denver"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Super"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    if issuer is None:
        issuer = subject

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).sign(signing_key, hashes.SHA256())

    return cert

def key_pem_bytes(key, password):
    if password is None:
        key_data = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    else:
        key_data = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(password))

    return key_data

def cert_pem_bytes(cert):
    return cert.public_bytes(Encoding.PEM)

def p12_bytes(key, cert, password):
    if password is not None:
        data = serialize_key_and_certificates(b'p12', key, cert, None, BestAvailableEncryption(password))
    else:
        data = serialize_key_and_certificates(b'p12', key, cert, None, NoEncryption())

    return data

def generate_certs(working_path: Path):
    root_key = make_key()
    root_cert = make_cert(root_key, root_key, 'My CA')

    user_key = make_key()
    user_cert = make_cert(user_key, root_key, 'User cert', root_cert.issuer)

    server_key = make_key()
    server_cert = make_cert(server_key, root_key, 'Server cert', root_cert.issuer)

    working_path.joinpath('ca.pem').write_bytes(cert_pem_bytes(root_cert))

    working_path.joinpath('user-combined-encrypted.pem').write_bytes(  key_pem_bytes(user_key,   b'userpass')   + cert_pem_bytes(user_cert))
    working_path.joinpath('server-combined-encrypted.pem').write_bytes(key_pem_bytes(server_key, b'serverpass') + cert_pem_bytes(server_cert))

    working_path.joinpath('user-combined-nopass.pem').write_bytes(     key_pem_bytes(user_key,   None)          + cert_pem_bytes(user_cert))
    working_path.joinpath('server-combined-nopass.pem').write_bytes(   key_pem_bytes(server_key, None)          + cert_pem_bytes(server_cert))

    working_path.joinpath('user-encrypted.p12').write_bytes(p12_bytes(user_key, user_cert, b'userpass'))
    working_path.joinpath('user-nopass.p12').write_bytes(p12_bytes(user_key, user_cert, None))

def generate_unencrypted_pem_config(working_path: Path):
    working_path.joinpath('config.ini').write_text(
f'''
[global]
pem = {working_path}/user-combined-nopass.pem
ca = {working_path}/ca.pem
'''
    )

if __name__ == "__main__":
    generate_certs(Path.cwd())
