# vim: expandtab tabstop=4 shiftwidth=4

# based on https://stackoverflow.com/questions/56285000/python-cryptography-create-a-certificate-signed-by-an-existing-ca-and-export

from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption

def make_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

def make_cert(signing_key, name, issuer=None):
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
        signing_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=30)
    ).sign(signing_key, hashes.SHA256())

    return cert

def key_bytes(key, password):
    if password is None:
        key_data = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    else:
        key_data = key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(password))

    return key_data

def cert_bytes(cert, path):
    return cert.public_bytes(Encoding.PEM)

def main():
    root_key = make_key()
    root_cert = make_cert(root_key, 'My CA')

    user_key = make_key()
    user_cert = make_cert(root_key, 'User cert', root_cert.issuer)

    server_key = make_key()
    server_cert = make_cert(root_key, 'Server cert', root_cert.issuer)

    #print(type(user_key))
    #print(dir(user_key))
    #print(type(user_cert))
    #print(dir(user_cert))

    Path('ca.pem').write_bytes(cert_bytes(root_cert))
    Path('user-combined-encrypted.pem').write_bytes(key_bytes(user_key)+cert_bytes(user_cert))

if __name__ == "__main__":
    main()
