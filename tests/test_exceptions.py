import pytest

from curl_reap import exceptions as ex


def test_hierarchy_keeps_transport_error_and_oserror():
    assert issubclass(ex.DNSError, ex.TransportError)
    assert issubclass(ex.TransportError, OSError)
    assert issubclass(ex.ConnectTimeout, ex.ConnectionError)
    assert issubclass(ex.ConnectTimeout, ex.Timeout)
    assert issubclass(ex.CertificateVerifyError, ex.SSLError)
    assert ex.RequestsError is ex.RequestException
    assert ex.HTTPStatusError is ex.HTTPError


def test_codes_match_curl():
    assert ex.DNSError("x").code == 6
    assert ex.ConnectionError("x").code == 7
    assert ex.Timeout("x").code == 28
    assert ex.TooManyRedirects("x").code == 47
    assert ex.CertificateVerifyError("x").code == 60
    assert ex.TransportError("x").code == 0
    assert ex.TransportError("x", code=52).code == 52
    assert "curl error 6" in str(ex.DNSError("no such host"))


def test_http_error_carries_response():
    class R:
        status = 503
        url = "https://x/"
    err = ex.HTTPError(R())
    assert err.response.status == 503
    assert "503" in str(err)


def test_websocket_closed():
    err = ex.WebSocketClosed("bye", code=1001, reason="going away")
    assert err.close_code == 1001 and err.reason == "going away"
    assert isinstance(err, ex.RequestException)


def test_code2error_covers_common_numbers():
    assert ex.CODE2ERROR[ex.CurlECode.COULDNT_RESOLVE_HOST] is ex.DNSError
    assert ex.CODE2ERROR[ex.CurlECode.PEER_FAILED_VERIFICATION] is ex.CertificateVerifyError
