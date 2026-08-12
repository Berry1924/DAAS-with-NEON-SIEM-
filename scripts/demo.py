import sys
import os

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security_engine.demo.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
