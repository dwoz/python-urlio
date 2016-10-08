from __future__ import print_function
import sys
from . import VERSION
if __name__ == "__main__":
    if '--version' in sys.argv:
        print( '.'.join([str(a) for a in VERSION]))
        sys.exit(0)
