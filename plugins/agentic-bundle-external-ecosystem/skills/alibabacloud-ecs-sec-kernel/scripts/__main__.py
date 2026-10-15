"""sec-kernel: Linux Kernel CVE Vulnerability Detection Tool"""
import sys
import os

# Ensure the project root (parent of scripts/) is on sys.path
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from scripts.main import main

if __name__ == "__main__":
    sys.exit(main())
