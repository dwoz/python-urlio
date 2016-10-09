from __future__ import print_function
import sys
from . import __version__
if __name__ == "__main__":
    if '--version' in sys.argv:
        print(__version__)
        sys.exit(0)
