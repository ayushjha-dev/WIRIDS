"""Root conftest: ensure the project root is importable as a package source.

Lets tests import top-level modules (config, database, main, models, modules.*)
and the tests package (tests.conftest) regardless of the invocation directory.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
