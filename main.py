"""Entry point: `python main.py [LOG_CSV] [options]` runs the SSH brute-force detector."""

import sys

from openssh_regex import main

if __name__ == "__main__":
    sys.exit(main())
