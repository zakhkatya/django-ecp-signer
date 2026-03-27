import pytest
from ecp_auth.certificate import CertificateParser
from ecp_auth.exceptions import InvalidCertificateError
from tests.conftest import make_cert_and_key


def test_not_expired():
    _, cert_pem = make_cert_and_key()
    assert CertificateParser(cert_pem).is_expired() is False


def test_expired():
    _, cert_pem = make_cert_and_key(expired=True)
    assert CertificateParser(cert_pem).is_expired() is True


def test_not_yet_valid():
    _, cert_pem = make_cert_and_key(not_yet_valid=True)
    assert CertificateParser(cert_pem).is_expired() is True


def test_common_name():
    _, cert_pem = make_cert_and_key(common_name="john_doe")
    assert CertificateParser(cert_pem).get_common_name() == "john_doe"


def test_invalid_bytes():
    with pytest.raises(InvalidCertificateError):
        CertificateParser(b"not a certificate")


def test_to_dict():
    _, cert_pem = make_cert_and_key(common_name="testuser")
    d = CertificateParser(cert_pem).to_dict()
    assert d["common_name"] == "testuser"
    assert "not_valid_after" in d
    assert "not_valid_before" in d
