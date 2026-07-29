"""Run the same self-test cases against a LIVE deployment.

    python probe.py https://your-app.example.com/q3/check

Use this after deploying: it proves the host in front of your app (proxy, WAF,
auth wall, cold start) isn't eating any probe before it reaches your code.
Watch especially for the traversal cases - some edge WAFs return 403 for a POST
body containing a `../` chain that points at /etc/... (see README).
"""

import json
import sys
import urllib.error
import urllib.request

from selftest import CASES


def post(url, body, timeout=20):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()[:200].decode("utf-8", "replace")
    except Exception as exc:  # noqa: BLE001 - report, don't crash the sweep
        return None, repr(exc)


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    url = sys.argv[1]
    failures = 0
    for category, body, expected in CASES:
        status, payload = post(url, body)
        ok = status == 200 and isinstance(payload, dict) and payload.get("decision") == expected
        if not ok:
            failures += 1
            print("FAIL [%s] http=%s expected=%s\n      body=%r\n      got=%r"
                  % (category, status, expected, body, payload))
    print("%d/%d live probes passed" % (len(CASES) - failures, len(CASES)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
