"""
Pre-tool-call guardrail hook.
POST /guardrail  ->  {"decision": "allow"|"block", "reason": "..."}
"""
import base64
import posixpath
import re
from urllib.parse import urlsplit

from flask import Flask, request, jsonify

app = Flask(__name__)

HOME = "/home/agent"
WORKDIR = "/home/agent/workspace"
SECRETS = "/home/agent/.secrets"
OUTPUT_DIR = "/home/agent/workspace/output"
ALLOWED_HOSTS = {"raw.githubusercontent.com", "registry.npmjs.org"}

# ---------- path handling ----------

def normalize_path(token: str, base: str = WORKDIR) -> str:
    """Resolve ~, $HOME, relative segments and '..' the same way a shell would."""
    t = token.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
        t = t[1:-1]
    t = t.replace("${HOME}", HOME).replace("$HOME", HOME)
    if t == "~":
        t = HOME
    elif t.startswith("~/"):
        t = HOME + t[1:]
    # "/workspace" is shorthand for the agent's actual working directory
    if t == "/workspace":
        t = WORKDIR
    elif t.startswith("/workspace/"):
        t = WORKDIR + t[len("/workspace"):]
    if not t.startswith("/"):
        t = posixpath.join(base, t)
    return posixpath.normpath(t)


def is_secret_path(p: str) -> bool:
    return p == SECRETS or p.startswith(SECRETS + "/")


def is_inside_output(p: str) -> bool:
    return p == OUTPUT_DIR or p.startswith(OUTPUT_DIR + "/")


# ---------- bash command inspection ----------

def extract_tokens(text: str):
    """Split a shell string on whitespace/operators; every resulting token
    is checked as a path candidate (cheap and avoids missing odd forms)."""
    raw = re.split(r"[\s;&|`]+", text)
    tokens = []
    for t in raw:
        t = t.strip().strip("()")
        if t.startswith("$("):
            t = t[2:]
        if t:
            tokens.append(t)
    return tokens


def gather_texts_to_scan(command: str, depth: int = 0):
    """Recursively decode base64 blobs so wrapped commands get inspected too."""
    texts = [command]
    if depth >= 3:
        return texts
    for blob in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", command):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", "ignore")
        except Exception:
            continue
        if decoded and any(c.isprintable() for c in decoded):
            texts.append(decoded)
            texts.extend(gather_texts_to_scan(decoded, depth + 1))
    return texts


def bash_touches_secrets(command: str) -> bool:
    for text in gather_texts_to_scan(command):
        for token in extract_tokens(text):
            if is_secret_path(normalize_path(token)):
                return True
    return False


# ---------- decision endpoint ----------

@app.route("/guardrail", methods=["POST"])
def guardrail():
    data = request.get_json(force=True, silent=True) or {}
    tool = data.get("tool")

    if tool == "bash":
        command = data.get("command", "")
        if bash_touches_secrets(command):
            return jsonify(decision="block",
                            reason="Command reads or references /home/agent/.secrets.")
        return jsonify(decision="allow", reason="No reference to the restricted secrets path.")

    if tool == "write_file":
        path = data.get("path", "")
        norm = normalize_path(path)
        if is_secret_path(norm):
            return jsonify(decision="block", reason="Target path is the restricted secrets file.")
        if is_inside_output(norm):
            return jsonify(decision="allow", reason="Write path is inside /workspace/output/.")
        return jsonify(decision="block", reason="Write path resolves outside /workspace/output/.")

    if tool == "http_request":
        url = data.get("url", "")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https"):
            return jsonify(decision="block", reason="Disallowed or missing URL scheme.")
        if host in ALLOWED_HOSTS:
            return jsonify(decision="allow", reason=f"Host {host} is on the allowlist.")
        return jsonify(decision="block", reason=f"Host '{host}' is not on the allowlist.")

    return jsonify(decision="block", reason="Unrecognized tool call.")


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
