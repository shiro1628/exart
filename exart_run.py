# -*- coding: utf-8 -*-
"""패키지 밖에서 실행하기 위한 진입점(PyInstaller 빌드, python3 exart_run.py ...)."""
import sys

from exart.cli import main

if __name__ == "__main__":
    sys.exit(main())
