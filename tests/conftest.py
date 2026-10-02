import sys
from pathlib import Path

# Ensure the project root is importable as `ot_recon` regardless of where
# pytest is invoked from.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
