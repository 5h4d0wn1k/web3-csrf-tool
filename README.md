> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# WEB3 — CSRF Attack / Replay Toolkit

CSRF token extraction and entropy analysis, form replay, and auto-generated
proof-of-concept payloads with bypass assessments for **web security** testing
and OWASP Top-10 validation.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/5h4d0wn1k/web3-csrf-tool)](https://github.com/5h4d0wn1k/web3-csrf-tool)
[![Issues](https://img.shields.io/github/issues/5h4d0wn1k/web3-csrf-tool)](https://github.com/5h4d0wn1k/web3-csrf-tool/issues)
[![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/web3-csrf-tool)](https://github.com/5h4d0wn1k/web3-csrf-tool)

## Why

Cross-Site Request Forgery is the silent cousin of XSS: a victim's browser is
tricked into submitting a state-changing request on a site the victim trusts,
and the server can't tell the request browser-originated from attacker-driven —
unless it validates an unpredictable token. Testing that protection means
extracting the token from the page, judging whether it has real entropy, and
proving the outcome of a token-less replay. WEB3 automates that whole chain —
form/meta-tag token extraction, strength analysis, form replay with custom
data, and generation of HTML proof-of-concept payloads (plus CORS,
content-type, and subdomain-trust bypass variants). Bundled vulnerable and clean
simulators prove the detection code path works over loopback with both outcomes,
so the toolkit stays a precise instrument for authorized web pentests.

## Features

- **Token extraction** — pulls CSRF tokens from forms and meta tags
- **Token analysis** — entropy, predictability, and strength verdicts
- **Form replay** — replay captured forms with modified POST data
- **PoC generation** — write self-contained HTML proof-of-concept files
- **Bypass variants** — CORS misconfiguration, subdomain trust, content-type tricks
- **Bundled simulators** — vulnerable (accepts token-less replay) + clean (403) control
- **Optional `requests`** — transparently upgrades the HTTP stack; stdlib otherwise

## Quickstart

Python standard library only; `pip install requests` is optional.

```bash
# Offline demo against the built-in vulnerable simulator (exit 0)
python3 csrf_tool.py --demo

# Offline demo against the clean control simulator (no findings, exit 0)
python3 csrf_tool.py --demo --clean

# Full protection assessment of a lab form
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form"

# Token analysis / forms / replay / PoC generation
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action analyze
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action replay --data "email=admin@example.com"
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action generate -o output/
python3 csrf_tool.py -u "http://127.0.0.1:<port>/form" --action bypass

# Unit tests (8 cases)
python3 -m unittest discover -s tests -v
```

Actions: `analyze`, `forms`, `assess`, `replay`, `generate`, `bypass`, `all`.

## Project structure

- `csrf_tool.py` — CLI entry point, extraction/analysis/replay/PoC engine
- `tests/` — unit tests

## Legal & authorized use

For **educational and authorized security testing purposes only**. Point it only
at deliberately vulnerable lab apps on `127.0.0.1`/`192.0.2.x` (RFC 5737) or
other targets you own with written scope. See [ETHICS.md](ETHICS.md),
[SCOPE.md](SCOPE.md), and [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).