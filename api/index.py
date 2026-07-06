"""Vercel serverless entrypoint (ASGI).

Vercel's Python runtime serves the `app` ASGI object exported here. The FastAPI
app and the pipeline package live in sibling dirs (demo/, lambdas/pipeline/), so we
add them to sys.path before importing. All requests are rewritten to this function
by vercel.json.
"""
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "demo"))
sys.path.insert(0, os.path.join(_ROOT, "lambdas", "pipeline"))

from app import app  # noqa: E402  (re-exported for Vercel)
