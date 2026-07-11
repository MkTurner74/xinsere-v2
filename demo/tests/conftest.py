"""Make the demo package and the sibling pipeline importable for the test run."""
import os
import sys

_DEMO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PIPE = os.path.join(_DEMO, "..", "lambdas", "pipeline")
for p in (_DEMO, _PIPE):
    if p not in sys.path:
        sys.path.insert(0, p)

# Local backend (no AWS): keeps config.validate_production_config() a no-op and
# lets chain/store stay lazily un-initialized during import.
os.environ.setdefault("XINSERE_BACKEND", "local")
