import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from ecp_auth.validators import SignatureValidator
from ecp_auth.exceptions import InvalidSignatureError, InvalidCertificateError
from tests.conftest import make_cert_and_key


def test_valid_signature():
    key, cert_pem = make_cert_and_key()
    data = b"test_nonce"
    sig = key.sign(data, ec.ECDSA(hashes.SHA256()))
    assert SignatureValidator().verify(data, sig, cert_pem) is True


def test_tampered_data():
    key, cert_pem = make_cert_and_key()
    sig = key.sign(b"original", ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignatureError):
        SignatureValidator().verify(b"tampered", sig, cert_pem)


def test_invalid_signature_bytes():
    _, cert_pem = make_cert_and_key()
    with pytest.raises(InvalidSignatureError):
        SignatureValidator().verify(b"data", b"badsig", cert_pem)


def test_wrong_key():
    # key1 signs the data, but verification uses cert2 (which holds key2's
    # public key) — the mismatch must be caught as InvalidSignatureError.
    key1, _ = make_cert_and_key()
    _, cert_pem2 = make_cert_and_key()
    sig = key1.sign(b"data", ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignatureError):
        SignatureValidator().verify(b"data", sig, cert_pem2)


def test_invalid_cert_bytes():
    with pytest.raises(InvalidCertificateError):
        SignatureValidator().verify(b"data", b"sig", b"not_a_cert")
