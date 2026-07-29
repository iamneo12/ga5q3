"""Root-level shim so `uvicorn app:app` works on Render / Railway / Fly / local.

Vercel uses api/index.py directly; everything else can point here.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "api"))

from index import app  # noqa: E402,F401
