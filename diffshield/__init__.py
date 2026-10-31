"""
diffshield package root.
"""

from __future__ import annotations
import sys

import engine
import app

# Provide diffshield.engine and diffshield.app aliases
sys.modules["diffshield.engine"] = engine
sys.modules["diffshield.app"] = app

