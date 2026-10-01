"""Make scripts/ importable in tests (for example `import gen_inventory`)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
