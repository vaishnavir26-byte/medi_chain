#!/usr/bin/env python3
"""
Launcher script for Healthcare Consent & Audit Log.
Supports running tests or starting the web and API server.

Usage:
    python3 run_healthcare.py           # Starts server on port 8085
    python3 run_healthcare.py --port 8090 # Starts server on port 8090
    python3 run_healthcare.py --test    # Runs automated test suite
"""

import sys
import os

if __name__ == "__main__":
    if "--test" in sys.argv:
        import unittest
        suite = unittest.defaultTestLoader.discover(".", pattern="test_healthcare.py")
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        sys.exit(0 if result.wasSuccessful() else 1)

    port = 8085
    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])
    elif len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])

    from healthcare_consent.server import run_server
    run_server(port)
