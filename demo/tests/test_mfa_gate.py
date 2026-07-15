"""The login MFA challenge must be a HARD gate: while a session is mfa-pending,
data routes are blocked (so closing the challenge page can't bypass it), but the
few endpoints needed to complete or abandon the challenge stay reachable."""
import authn
from fastapi import Request


def _req(path, mfa_pending):
    scope = {"type": "http", "path": path, "headers": [], "method": "GET",
             "session": {"sb": {"access_token": "t", "user_id": "u",
                                "refresh_token": "r", "expires_at": 9999999999},
                         "mfa_pending": mfa_pending}}
    return Request(scope)


def test_data_route_blocked_while_mfa_pending():
    try:
        authn.session(_req("/api/tree", True))
    except Exception as e:
        assert getattr(e, "status_code", None) == 403 and "mfa" in str(e.detail).lower()
    else:
        raise AssertionError("data route must be blocked while mfa pending")


def test_download_blocked_while_mfa_pending():
    import pytest
    with pytest.raises(Exception) as ei:
        authn.session(_req("/api/download/fil_x", True))
    assert getattr(ei.value, "status_code", None) == 403


def test_mfa_and_me_endpoints_allowed_while_pending():
    for p in ("/api/me", "/api/account/mfa/verify", "/api/account/mfa/challenge",
              "/api/logout"):
        s = authn.session(_req(p, True))          # must NOT raise
        assert s["user_id"] == "u"


def test_all_routes_open_once_satisfied():
    s = authn.session(_req("/api/tree", False))   # pending cleared
    assert s["user_id"] == "u"
