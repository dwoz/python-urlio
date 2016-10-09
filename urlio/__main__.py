from __future__ import print_function
import sys
__version__ = '0.6.0'
if __name__ == "__main__":
    if '--version' in sys.argv:
        print(__version__)
        sys.exit(0)
