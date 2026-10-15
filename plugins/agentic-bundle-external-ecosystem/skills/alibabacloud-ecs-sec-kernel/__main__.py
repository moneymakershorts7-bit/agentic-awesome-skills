"""sec-kernel: Linux Kernel CVE 漏洞检测工具"""
import sys
import os

# Ensure the project root is on sys.path so `scripts` package is importable
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from scripts.main import main

if __name__ == "__main__":
    sys.exit(main())
