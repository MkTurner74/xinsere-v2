"""File-bytes storage for the app: the real DPD pipeline, backend chosen by env.

`XINSERE_BACKEND=aws` -> S3 + KMS + DynamoDB (production). Otherwise an ephemeral
local pipeline for offline dev. The app calls PIPELINE.store()/retrieve(); the
folder tree + shares live in Supabase (see supa.py), not here.
"""
from __future__ import annotations

import os
import sys

# Make the pipeline package importable from the sibling lambdas/ dir.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "lambdas", "pipeline"))

from xinsere_pipeline import XinsereIntegrityError  # noqa: E402,F401
from xinsere_pipeline.factory import build_pipeline_from_env  # noqa: E402

PIPELINE = build_pipeline_from_env()
