"""Gated API documentation site.

FastAPI's default public /docs and /openapi.json are disabled in app.py; the
routes here re-expose them ONLY to a signed-in user (any provisioned account —
accounts are invite-only, so this is effectively partners-and-staff). The
OpenAPI schema is filtered to the /v1 surface: the interactive app's session
endpoints and the admin console are internal and never documented.

  /docs        — interactive Swagger UI over the filtered schema
  /docs/guide  — hand-written getting-started guide (auth, flows, curl examples)
  /openapi.json — the filtered schema itself
"""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Request
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, JSONResponse

import authn

router = APIRouter(include_in_schema=False)


def _public_docs() -> bool:
    """When XINSERE_PUBLIC_DOCS=true, the hand-written getting-started GUIDE is
    readable without sign-in (the standard 'public reference docs, gated try-it/
    keys' split — integrator feedback #6). Interactive Swagger and the raw
    openapi.json stay gated regardless. Default off preserves the current
    invite-only posture until Mark flips it on."""
    return os.environ.get("XINSERE_PUBLIC_DOCS", "").lower() == "true"

_DESCRIPTION = """
Server-to-server API for securing assets with Xinsere Distributed Permissioned Data (DPD).

Files sent to this API are fragmented, encrypted (AES-256-GCM, per-fragment keys wrapped
by KMS) and scattered across storage — no complete copy exists anywhere. Read permission
is enforced by an on-chain smart contract: grants and revokes are immutable, timestamped
transactions any auditor can verify without ever seeing the content.

**Authentication:** every request carries `Authorization: Bearer <api key>`. Keys are
issued per organization in the admin console and act as your organization's *service
identity* (`party_id`) — the owner of everything you store and the party in every grant.
"""


def _filtered_openapi(app) -> dict:
    schema = get_openapi(title="Xinsere API", version="1.0.0",
                         description=_DESCRIPTION, routes=app.routes)
    schema["paths"] = {p: v for p, v in schema["paths"].items() if p.startswith("/v1")}
    schema.setdefault("components", {})["securitySchemes"] = {
        "ApiKey": {"type": "http", "scheme": "bearer",
                   "description": "Organization API key (xin_...)"}}
    schema["security"] = [{"ApiKey": []}]
    return schema


@router.get("/openapi.json")
def openapi_json(request: Request, s: dict = Depends(authn.require_signed_in)):
    return JSONResponse(_filtered_openapi(request.app))


@router.get("/docs")
def swagger(request: Request, s: dict = Depends(authn.require_signed_in)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="Xinsere API — Reference",
                               swagger_favicon_url="")


_GUIDE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Xinsere API — Getting Started</title>
<style>
  :root{--bg:#0A0713;--panel:rgba(255,255,255,0.035);--edge:rgba(146,119,255,0.16);
    --violet:#8A6BFF;--word:#9277FF;--mint:#4FE3C1;--text:#ECE9F8;--muted:#9A93B8;
    --code-bg:#17122b;}
  body{margin:0;font-family:"Poppins","Segoe UI",system-ui,sans-serif;background:
    radial-gradient(120% 90% at 88% -10%,rgba(124,91,255,0.18),transparent 55%),var(--bg);
    color:var(--text);line-height:1.65;}
  main{max-width:860px;margin:0 auto;padding:48px 24px 96px;}
  h1{font-size:1.9rem;margin:0 0 4px;} h1 .brand{color:var(--word);}
  h2{margin-top:44px;font-size:1.25rem;border-bottom:1px solid var(--edge);padding-bottom:8px;}
  .sub{color:var(--muted);margin-bottom:32px;}
  code,pre{font-family:"JetBrains Mono",ui-monospace,Consolas,monospace;font-size:0.85rem;}
  code{background:var(--code-bg);padding:2px 6px;border-radius:6px;}
  pre{background:var(--code-bg);border:1px solid var(--edge);border-radius:12px;
    padding:16px 18px;overflow-x:auto;}
  pre code{background:none;padding:0;}
  table{border-collapse:collapse;width:100%;margin:12px 0;}
  th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--edge);font-size:0.9rem;}
  th{color:var(--muted);font-weight:600;}
  .note{border-left:3px solid var(--mint);background:var(--panel);padding:12px 16px;
    border-radius:0 10px 10px 0;margin:16px 0;font-size:0.92rem;}
  a{color:var(--violet);} .muted{color:var(--muted);}
</style></head><body><main>
<h1><span class="brand">Xinsere</span> API — Getting Started</h1>
<p class="sub">Secure assets with Distributed Permissioned Data: fragment, encrypt,
scatter — with permissions on-chain. Full endpoint reference: <a href="/docs">/docs</a>.</p>

<h2>1 &middot; Authentication</h2>
<p>Your organization was issued an API key (<code>xin_...</code>) from the Xinsere admin
console. Send it on every request:</p>
<pre><code>Authorization: Bearer xin_your_key_here</code></pre>
<p>The key acts as your organization's <strong>service identity</strong>. Its
<code>party_id</code> (a uuid) owns everything you store and is the party recorded in
on-chain grants. Check your key and discover your <code>party_id</code>:</p>
<pre><code>curl -H "Authorization: Bearer $XINSERE_KEY" https://BASE_URL/v1/ping</code></pre>

<h2>2 &middot; Store a file</h2>
<pre><code>curl -X POST https://BASE_URL/v1/files \\
  -H "Authorization: Bearer $XINSERE_KEY" \\
  -F "file=@contract.pdf" \\
  -F "path=productions/show-x"      # optional folder path</code></pre>
<p>The response includes the file <code>id</code> (use it in every later call) and the
<code>sha256</code> of your original bytes. The file is now fragmented, encrypted and
scattered — no complete copy exists anywhere, and Xinsere itself cannot read it.</p>
<div class="note">The inline cap is advertised as <code>max_inline_bytes</code> in
<code>GET /v1/ping</code> — read it rather than hardcoding. Larger files: call
<code>POST /v1/uploads</code> for a presigned URL, PUT the raw bytes there, then
<code>POST /v1/files/finalize</code>.</div>

<h2>3 &middot; Retrieve</h2>
<p>Two paths:</p>
<table>
<tr><th>Endpoint</th><th>What happens</th></tr>
<tr><td><code>GET /v1/files/{id}/content</code></td><td>Server-side reassembly — bytes
streamed back, integrity-verified (<code>X-Content-SHA256</code> header).</td></tr>
<tr><td><code>GET /v1/files/{id}/plan</code></td><td>Client-side reassembly — per-fragment
presigned URLs + data keys; <em>your</em> systems fetch and decrypt, the plaintext never
transits Xinsere. Preferred for large media.</td></tr>
</table>

<h2>4 &middot; Grant &amp; revoke access</h2>
<p>Permissions are written to a Polygon smart contract — immutable, timestamped,
independently verifiable. Grant read access to another party (a user or another
organization's <code>party_id</code>):</p>
<pre><code>curl -X POST https://BASE_URL/v1/files/{id}/grants \\
  -H "Authorization: Bearer $XINSERE_KEY" \\
  -F "party_id=&lt;grantee uuid&gt;"</code></pre>
<p>The returned <code>tx</code> hash is your proof — inspectable on PolygonScan. Revoke with
<code>DELETE /v1/files/{id}/grants/{party_id}</code>; the revoke is itself an on-chain
event, so the full history survives.</p>

<h2>5 &middot; Verify (the audit layer)</h2>
<pre><code>curl "https://BASE_URL/v1/files/{id}/verify?party_id=&lt;uuid&gt;" \\
  -H "Authorization: Bearer $XINSERE_KEY"</code></pre>
<p>Answers "does this party currently have access, and since when?" straight from the
chain — without touching the file content. <code>GET /v1/files/{id}/grants</code> lists
current shares with their transaction hashes.</p>

<h2>6 &middot; Delete</h2>
<p><code>DELETE /v1/files/{id}</code> moves to Trash (recoverable, auto-erased after 30
days). Add <code>?permanent=true</code> for immediate cryptographic erasure — fragments
and keys destroyed, outstanding grants revoked on-chain.</p>

<h2>7 &middot; Operability</h2>
<p>Two helper endpoints keep integrations honest:</p>
<table>
<tr><th>Endpoint</th><th>Use</th></tr>
<tr><td><code>GET /v1/chain/status</code></td><td>Signer wallet + gas health (spends no
gas). Check <code>wallet_ok</code> / <code>est_grants_remaining</code> <em>before</em> a
grant so it never dies mid-demo for lack of gas.</td></tr>
<tr><td><code>GET /v1/parties?slug=</code></td><td>Resolve another organization's
<code>party_id</code> from its slug, so machine-to-machine grants need no human to copy a
uuid. Returns <code>{slug, name, party_id}</code> for active orgs.</td></tr>
</table>

<h2>Errors</h2>
<p>Every error — including <code>422</code> validation errors — returns a single shape:</p>
<pre><code>{ "error": "human-readable message [error_code]" }</code></pre>
<p>Validation errors add an <code>errors</code> array with the field-level detail. Codes you
may want to branch on: <code>chain_grant_failed</code>, <code>chain_revoke_failed</code>,
<code>chain_status_unavailable</code>. The HTTP status still carries the primary signal
(<code>401</code> bad key, <code>403</code> missing scope, <code>404</code> not found /
hidden, <code>413</code> too large, <code>422</code> bad input, <code>502</code> chain
write failed, <code>503</code> backend unavailable — retry).</p>

<h2>Scopes</h2>
<table>
<tr><th>Scope</th><th>Endpoints</th></tr>
<tr><td><code>files:read</code></td><td>list, metadata, content, plan</td></tr>
<tr><td><code>files:write</code></td><td>store, uploads, finalize, delete</td></tr>
<tr><td><code>grants:manage</code></td><td>grant, revoke, list grants</td></tr>
<tr><td><code>verify:read</code></td><td>verify</td></tr>
</table>
<p class="muted">Questions or a key that needs re-scoping: contact your Xinsere admin.</p>
</main></body></html>"""


@router.get("/docs/guide")
def guide(request: Request):
    # Public when XINSERE_PUBLIC_DOCS=true; otherwise sign-in gated like the rest.
    if not _public_docs():
        authn.require_signed_in(request)  # raises 401 if not signed in
    base = str(request.base_url).rstrip("/")
    return HTMLResponse(_GUIDE.replace("https://BASE_URL", base))
