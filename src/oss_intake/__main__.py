"""Allow `python -m oss_intake` when the console script is not on PATH."""

import sys

from .cli import main

sys.exit(main())
