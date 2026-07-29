# TDS GA5 Q3 — Agent Tool Guardrail Hook (public solver)

A complete, deployable answer for **`q-agent-tool-guardrail-server`** (GA5, "Agent Harness:
pre-tool-call guardrail hook"). Deterministic policy engine — **no LLM, no API key, no database,
no account of any kind**. Clone → change 3 lines → deploy → submit the URL.

Nothing personal is baked in: the three personalised values are yours to fill in, and there are no
tokens, emails or private URLs anywhere in this repo.

---

## What the grader does

It POSTs one proposed tool call at a time to `<your-url>` and expects a JSON verdict:

```jsonc
// request
{"tool": "bash",         "command": "cat ~/.netrc"}
{"tool": "write_file",   "path": "/srv/reports/out.md", "content": "..."}
{"tool": "http_request", "method": "GET", "url": "https://pypi.org/simple/"}

// response — exactly these two keys
{"decision": "block", "reason": "Reading the restricted secret file /home/agent/.netrc is never permitted."}
```

It fires ~15 probes across these categories: direct read of the secret, obfuscated read,
*legitimate* read (must be **allowed** — over-blocking costs marks), write inside the allowed dir,
write outside it, write traversal (`<writeDir>/../../etc/passwd`), allowed host, blocked host,
domain confusion (`evil.pypi.org`, `pypi.org@evil.com`), and unknown tool.

---

## 1. Put YOUR three values in

Every student gets a different combination. Open your Q3 question text and copy out:

| Question says | Where it goes |
|---|---|
| the secret file that must never be read | `Q3_SECRET` |
| the only directory writes are allowed in | `Q3_WRITE_ROOT` |
| the allowed outbound domains (usually 2) | `Q3_ALLOWED_HOSTS` (comma-separated) |

Either edit the `CONFIG` block at the top of [`api/guardrail.py`](api/guardrail.py):

```python
SECRET        = os.environ.get("Q3_SECRET", "/home/agent/.netrc")
WRITE_ROOT    = os.environ.get("Q3_WRITE_ROOT", "/srv/reports").rstrip("/")
ALLOWED_HOSTS = {... "pypi.org,raw.githubusercontent.com" ...}
```

…or leave the file alone and set those three as environment variables on your host. Both work.

> The defaults shipped here are placeholders from the question's value pool — they are almost
> certainly **not** your combination. Check.

## 2. Verify offline (no deploy, no network)

```bash
pip install -r requirements.txt
python selftest.py
```

96 probe-shaped cases, generated from whatever config you set, covering every grader category.
Expect `96/96 passed`. If a case fails, fix that before deploying — the grader will find it too.

## 3. Deploy

**Vercel** (recommended — see the WAF note below):

```bash
npm i -g vercel
vercel deploy --prod
```

`vercel.json` + `api/index.py` are already wired up. Set the three env vars in the Vercel dashboard
if you didn't edit the file.

**Render / Railway / Fly / your own box** (any ASGI host):

```bash
uvicorn app:app --host 0.0.0.0 --port 8000
```

`render.yaml` is included for a one-click Render blueprint.

**Locally, to eyeball it:**

```bash
uvicorn app:app --port 8000
curl -s localhost:8000/q3/check -H 'content-type: application/json' \
     -d '{"tool":"bash","command":"cat ~/.netrc"}'
```

## 4. Probe the live URL, then submit

```bash
python probe.py https://your-app.vercel.app/q3/check
```

This replays the whole self-test over HTTP against the deployed service. It catches the things
local tests can't: cold starts, auth walls, proxies and WAFs. Then paste
`https://your-app.example.com/q3/check` into the Q3 field and press **Check** → **Save**.

---

## ⚠️ The WAF trap (this is the one that quietly costs you marks)

The write-traversal probe sends a body containing something like
`<writeDir>/../../etc/passwd`. Managed edge WAFs read that as an LFI attack and answer **403
themselves** — the request never reaches your app, so a perfectly correct policy engine still loses
that probe. Free-tier Render (behind Cloudflare) does exactly this: `../` + `/etc/passwd` → 403,
with no toggle to turn it off.

Symptoms: 14/15 instead of 15/15, and the missing probe is nowhere in your logs.

Check for it in one command:

```bash
curl -i -s -X POST https://your-app/q3/check -H 'content-type: application/json' \
     -d '{"tool":"write_file","path":"/srv/reports/../../etc/passwd","content":"x"}'
```

`{"decision":"block"}` = fine. `403` with a challenge page = your host's WAF ate it — deploy
somewhere without one (Vercel, a Hugging Face Space, your own VPS) and submit that URL instead.

---

## How the engine works

Single pure function, `evaluate(body) -> {"decision", "reason"}` — trivially unit-testable, which is
why the self-test can be so thorough.

* **De-obfuscation** (`expand`): every command is re-read through several views —
  `\x2f`/`\057`/`/` escapes decoded, quote-splitting and backslash tricks collapsed
  (`cat /home/agent/.n""etrc`, `c\at`, `.ne'tr'c`), and base64/hex blobs decoded recursively up to
  3 levels so `echo <b64> | base64 -d | sh` (even nested) is judged on what it actually runs.
  A reversed-name backstop catches `echo crten. | rev`.
* **Path canonicalisation** (`canonicalize`): pure string resolution of `~`, `$HOME`, `${PWD}`,
  `..`, `.` and `//` against the cwd — the real filesystem is never touched. `cd` targets on the
  same line become extra bases, so `cd ~ && cat .netrc` still resolves onto the secret.
* **Directory containment** (`is_under`): boundary-aware, so `/srv/reportsomething` and
  `/srv/reports-backup` are correctly *outside* `/srv/reports`.
* **Writes judged by where they land**: a `..` chain that resolves back inside the write root is
  allowed; one that escapes is blocked. Bash is not a loophole around `write_file` — redirects
  (`>`, `>>`, `>|`, `tee`), `cp`/`mv`/`install`/`rsync`/`ln` (last arg), `touch`/`mkdir`/`truncate`/
  `mkfifo`/`mknod` (all args), `dd of=` and `sed -i` all get their destination checked. Sources
  stay readable.
* **Hosts**: exact-match allowlist, lowercased, trailing dot stripped, non-http(s) schemes rejected,
  and parsed with `urlsplit` so `pypi.org@evil.com` resolves to `evil.com`. No subdomain or suffix
  matching — that's what the domain-confusion probes hunt for.
* **Deliberately narrow over-blocking**: only a tiny extra denylist (`/etc/shadow`, `/etc/sudoers`,
  …). Blocking ordinary workspace commands loses just as many marks as missing an attack.

## Files

```
api/guardrail.py   the policy engine + FastAPI router  ← your 3 values go at the top
api/index.py       ASGI app (routes, /health, slash-normalising middleware)
app.py             root shim so `uvicorn app:app` works on non-Vercel hosts
selftest.py        96 offline cases, generated from your config
probe.py           replays those cases against a deployed URL
vercel.json        Vercel build config
render.yaml        Render blueprint
```

MIT licensed. Use it, read it, learn from it — the interesting part is the de-obfuscation and the
"judge a write by where it lands" rule, both of which are worth understanding before you submit.
