from ecp_auth.certificate import CertificateParser
from ecp_auth.exceptions import InvalidCertificateError
from tests.conftest import make_cert_and_key


def test_extract_taxpayer_id():
    _, cert_pem = make_cert_and_key(taxpayer_id="9876543210")
    assert CertificateParser(cert_pem).extract_taxpayer_id() == "9876543210"


def test_not_expired():
    _, cert_pem = make_cert_and_key()
    assert CertificateParser(cert_pem).is_expired() is False


def test_expired():
    _, cert_pem = make_cert_and_key(expired=True)
    assert CertificateParser(cert_pem).is_expired() is True


def test_common_name():
    _, cert_pem = make_cert_and_key()
    assert CertificateParser(
        cert_pem).get_common_name() == "Тестовий Користувач"


def test_invalid_bytes():
    try:
        CertificateParser(b"not a certificate")
        assert False
    except InvalidCertificateError:
        assert True


def test_to_dict():
    _, cert_pem = make_cert_and_key()
    d = CertificateParser(cert_pem).to_dict()
    assert "taxpayer_id" in d
    assert "common_name" in d
    assert "not_valid_after" in d
