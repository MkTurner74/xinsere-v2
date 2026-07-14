"""Security-notification email helper (best-effort, never raises)."""
import notify


def test_send_email_noop_when_unconfigured(monkeypatch):
    monkeypatch.setattr(notify, "RESEND_API_KEY", "")
    monkeypatch.setattr(notify, "EMAIL_FROM", "")
    assert notify.send_email("a@b.com", "Subj", "body") is False   # no provider, no raise


def test_send_email_noop_without_recipient():
    assert notify.send_email("", "Subj", "body") is False


def test_password_changed_never_raises(monkeypatch):
    monkeypatch.setattr(notify, "RESEND_API_KEY", "")
    monkeypatch.setattr(notify, "EMAIL_FROM", "")
    # Must not raise even when unconfigured.
    assert notify.password_changed("user@x.com", "Mark Turner") is False


def test_send_email_uses_resend_when_configured(monkeypatch):
    monkeypatch.setattr(notify, "RESEND_API_KEY", "re_test")
    monkeypatch.setattr(notify, "EMAIL_FROM", "security@xinsere.com")
    sent = {}

    class _Resp:
        status_code = 200
        text = ""
    import requests
    def _post(url, headers=None, json=None, timeout=None):
        sent.update({"url": url, "to": json["to"], "subject": json["subject"]})
        return _Resp()
    monkeypatch.setattr(requests, "post", _post)
    assert notify.send_email("user@x.com", "Hi", "body") is True
    assert sent["to"] == ["user@x.com"] and "resend.com" in sent["url"]
