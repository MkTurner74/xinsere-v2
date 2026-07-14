"""Transactional security notifications (e.g. "your password was changed").

Best-effort by design: a delivery failure must NEVER break the action that
triggered it (a password change succeeds whether or not the heads-up email sends).

Provider is chosen by env, so it lights up when ops configures a sender and is a
silent no-op until then:
  * XINSERE_RESEND_API_KEY  -> Resend (HTTP, uses `requests`)
  * else XINSERE_EMAIL_FROM -> AWS SES (uses boto3, already a dependency)
  * else                    -> log-only no-op
`XINSERE_EMAIL_FROM` is the verified sender address in both cases.
"""
from __future__ import annotations

import logging
import os

_log = logging.getLogger("xinsere.notify")

EMAIL_FROM = os.environ.get("XINSERE_EMAIL_FROM", "")          # e.g. "security@xinsere.com"
RESEND_API_KEY = os.environ.get("XINSERE_RESEND_API_KEY", "")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
APP_NAME = os.environ.get("XINSERE_APP_NAME", "Xinsere")


def send_email(to: str, subject: str, text: str, html: str | None = None) -> bool:
    """Send one transactional email. Returns True if handed to a provider, False if
    unconfigured or on any error. Never raises."""
    if not to:
        return False
    try:
        if RESEND_API_KEY and EMAIL_FROM:
            import requests
            r = requests.post("https://api.resend.com/emails",
                              headers={"Authorization": f"Bearer {RESEND_API_KEY}",
                                       "Content-Type": "application/json"},
                              json={"from": EMAIL_FROM, "to": [to], "subject": subject,
                                    "text": text, **({"html": html} if html else {})},
                              timeout=10)
            if r.status_code >= 400:
                _log.warning("resend send failed (%s): %s", r.status_code, r.text[:200])
                return False
            return True
        if EMAIL_FROM:
            import boto3
            body = {"Text": {"Data": text}}
            if html:
                body["Html"] = {"Data": html}
            boto3.client("ses", region_name=AWS_REGION).send_email(
                Source=EMAIL_FROM, Destination={"ToAddresses": [to]},
                Message={"Subject": {"Data": subject}, "Body": body})
            return True
        _log.info("email not configured (set XINSERE_EMAIL_FROM) — skipped: %r to %s", subject, to)
        return False
    except Exception as exc:  # best-effort — never propagate
        _log.warning("security email send failed to %s: %s", to, exc)
        return False


def password_changed(to: str, name: str = "") -> bool:
    """Notify a user their account password was just changed (security heads-up so a
    change they didn't make is noticed)."""
    who = name.split()[0] if name else "there"
    subject = f"Your {APP_NAME} password was changed"
    text = (f"Hi {who},\n\n"
            f"Your {APP_NAME} account password was just changed.\n\n"
            f"If this was you, no action is needed.\n"
            f"If it wasn't, reset your password immediately and enable two-factor "
            f"authentication in your {APP_NAME} security settings.\n\n"
            f"— {APP_NAME} Security")
    html = (f"<p>Hi {who},</p>"
            f"<p>Your <strong>{APP_NAME}</strong> account password was just changed.</p>"
            f"<p>If this was you, no action is needed. If it wasn't, "
            f"<strong>reset your password immediately</strong> and turn on two-factor "
            f"authentication in your security settings.</p>"
            f"<p>— {APP_NAME} Security</p>")
    return send_email(to, subject, text, html)
