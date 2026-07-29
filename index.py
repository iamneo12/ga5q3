"""ASGI entrypoint for the Q3 pre-tool-call guardrail hook.

Works unchanged on Vercel (@vercel/python picks up `app` from this file) and on
any plain ASGI host: `uvicorn api.index:app` or `uvicorn app:app` from the repo
root.

The grader POSTs to <submitted-url>/q3/check; the slash-normalise middleware
keeps "//q3/check" (base URL that ends in a slash) routing correctly.
"""
import os
import re
import sys

# Vercel puts /var/task on sys.path, not /var/task/api, so make the sibling
# guardrail module importable either way.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI

import guardrail

app = FastAPI(title="TDS GA5 Q3 - Agent Tool Guardrail Hook")


@app.middleware("http")
async def normalise_path(request, call_next):
    path = request.scope.get("path") or "/"
    fixed = re.sub(r"/{2,}", "/", path)
    if len(fixed) > 1 and fixed.endswith("/"):
        fixed = fixed.rstrip("/") or "/"
    if fixed != path:
        request.scope["path"] = fixed
        raw = request.scope.get("raw_path")
        if isinstance(raw, bytes):
            request.scope["raw_path"] = fixed.encode("utf-8")
    return await call_next(request)


app.include_router(guardrail.router)


@app.get("/")
async def root():
    return {
        "service": "tds-ga5-q3-guardrail",
        "status": "ok",
        "endpoint": "POST /q3/check",
        "policy": {
            "secret": guardrail.SECRET,
            "write_root": guardrail.WRITE_ROOT + "/",
            "allowed_hosts": sorted(guardrail.ALLOWED_HOSTS),
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
