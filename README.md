# NoMoreForbidden

NoMoreForbidden is a tool that tries various techniques to bypass forbidden(403) pages on websites and presents their results to the user.

**Use only on systems you are authorized to test.** Prefer **`--dry-run`** to review the estimated request count, **`--allow-host`** / **`--allow-url-prefix`** to limit scope, and **`--max-requests`** / **`--rate-limit`** / **`--delay`** to cap traffic.

> [!NOTE]
> NoMoreForbidden now has golang version. Check in https://github.com/akinerkisa/GoNMF

> [!NOTE]
> You can try this tool with https://github.com/akinerkisa/renikApp 403 vulnerable page section.

## Installation

<code>git clone https://github.com/akinerkisa/NoMoreForbidden</code>
<p><code>cd NoMoreForbidden</code></p>
<p><code>pip install -r requirements.txt</code></p>

To install the package (adds the <code>nmf</code> command on your PATH):

<code>pip install .</code>

Development install (editable, includes dev extras from <code>pyproject.toml</code>):

<code>pip install -e ".[dev]"</code>

## Usage

<code>python3 nmf.py -u https://www.example.com/test</code>

After <code>pip install .</code>, you can run:

<code>nmf -u https://www.example.com/test</code>

You can also run the package as a module:

<code>python3 -m nomoreforbidden -u https://www.example.com/test</code>

| Flag | Description | Example | Default |
| --- | --- | --- | --- |
| `-u` / `--url` | Target URL | `python3 nmf.py -u https://www.example.com/test` | required |
| `-i` / `-ip` / `--ip` | IP for IP-based headers (e.g. `X-Forwarded-For`) | `python3 nmf.py -u … -ip 1.1.1.1` | `127.0.0.1` |
| `-v` / `--verbose` | Show all valid/invalid lines and errors | `python3 nmf.py -u … -v` | off |
| `--proxy` | HTTP(S) proxy for `requests` (Burp, corporate proxy, etc.) | `python3 nmf.py -u … --proxy http://127.0.0.1:8080` | none |
| `--cookie` | Cookie header (applied after `-H` headers; overrides `Cookie` from `-H`) | `python3 nmf.py -u … --cookie 'session=abc'` | none |
| `-H` / `--header` | Extra header, `Name: Value` (repeatable) | `python3 nmf.py -u … -H 'Authorization: Bearer x'` | none |
| `--output-format` | `text` (default), `json`, or `csv` | `python3 nmf.py -u … --output-format csv` | `text` |
| `--json` | Same as `--output-format json` (mutually exclusive with `--output-format`) | `python3 nmf.py -u … --json` | off |
| `--delay` | Seconds to sleep after each HTTP request (throttle) | `python3 nmf.py -u … --delay 0.5` | `0` |
| `--fp-bytes` | Number of prefix bytes hashed for false-positive detection | `python3 nmf.py -u … --fp-bytes 128` | `64` |
| `--fp-threshold` | False-positive score threshold | `python3 nmf.py -u … --fp-threshold 60` | `40` |
| `--fp-baseline` | False-positive baseline strategy: `auto`, `target`, `root` | `python3 nmf.py -u … --fp-baseline target` | `auto` |
| `--payloads-file` | Extra URL suffix payloads, one per line | `python3 nmf.py -u … --payloads-file payloads.txt` | none |
| `--headers-file` | Extra spoofing header names, one per line | `python3 nmf.py -u … --headers-file headers.txt` | none |
| `--methods` | Extra methods for case-path probe, comma-separated | `python3 nmf.py -u … --methods HEAD,OPTIONS,PATCH` | `HEAD,OPTIONS` |
| `--http2` | Try an additional HTTP/2 probe via `httpx` | `python3 nmf.py -u https://example.com/test --http2` | off |
| `--concurrency` | Concurrent workers for URL payload probes | `python3 nmf.py -u … --concurrency 4` | `1` |
| `--rate-limit` | Global request cap in requests/sec for session traffic | `python3 nmf.py -u … --rate-limit 2.5` | `0` |
| `--timeout` | Per-request timeout in seconds | `python3 nmf.py -u … --timeout 8` | `5` |
| `--retries` | Retry count for failed HTTP requests | `python3 nmf.py -u … --retries 2` | `0` |
| `--profile` | Probe preset: `safe`, `default`, `aggressive`, `proxy-aware` | `python3 nmf.py -u … --profile aggressive` | `default` |
| `--aggressive` | Expand methods, payloads, headers, concurrency beyond the selected profile | `python3 nmf.py -u … --aggressive` | off |
| `--only` | Run only selected probes | `python3 nmf.py -u … --only nmf,http_version` | all |
| `--skip` | Skip selected probes | `python3 nmf.py -u … --skip wayback,get_ip` | none |
| `--allow-host` | Allowed hostname (repeatable); target host must match (case-insensitive) | `python3 nmf.py -u … --allow-host example.com` | none (no restriction) |
| `--allow-url-prefix` | Allowed URL prefix (repeatable); target must start with one prefix | `python3 nmf.py -u … --allow-url-prefix https://example.com/` | none |
| `--dry-run` | No HTTP; print estimated request upper bound and exit `0` | `python3 nmf.py -u … --dry-run` | off |
| `--max-requests` | Abort before scanning if estimated HTTP total exceeds N (exit `2`); `0` = off | `python3 nmf.py -u … --max-requests 500` | `0` |
| `--safe-mode` | Applies guarded defaults (`require-scope`, lower concurrency/rate); runs dry-run unless `--force-run` | `python3 nmf.py -u … --safe-mode` | off |
| `--force-run` | Allows real scan while `--safe-mode` is active | `python3 nmf.py -u … --safe-mode --force-run` | off |
| `--require-scope` | Requires at least one of `--allow-host` / `--allow-url-prefix` | `python3 nmf.py -u … --require-scope --allow-host example.com` | off |
| `--allow-private` | Allows localhost/private targets (blocked by default) | `python3 nmf.py -u http://127.0.0.1:5000/x --allow-private` | off |
| `--deadline` | Global runtime cap in seconds; stops scan when exceeded | `python3 nmf.py -u … --deadline 30` | `0` (disabled) |
| `--output-file` | Writes the same output to a file as well as stdout | `python3 nmf.py -u … --json --output-file out.json` | none |
| `--redact` | Masks sensitive fields in structured outputs (`json`/`csv`) | `python3 nmf.py -u … --json --redact` | off |
| `--version` | Print version and exit | `python3 nmf.py --version` | — |

Legacy note: older docs used `-v on/off`. The current CLI uses a boolean flag: pass `-v` or `--verbose` to enable verbose output.

### JSON / CSV output

- **`--dry-run` with `--output-format json`:** stdout is a single JSON object with `dry_run`, `target`, `allow_host`, `allow_url_prefix`, and `estimated_http_upper_bound` (per-probe counts and `total_upper_bound`). No network I/O. Example:

```bash
python3 nmf.py -u https://www.example.com/secret --only nmf --dry-run --output-format json
```

Example fragment (counts vary with profile, probes, and URL):

```json
{
  "dry_run": true,
  "target": "https://www.example.com/secret",
  "allow_host": [],
  "allow_url_prefix": [],
  "estimated_http_upper_bound": {
    "nmf": { "fp_baseline_max": 2, "main": 110 },
    "total_upper_bound": 112
  }
}
```
- **`--output-format json`** or **`--json`:** stdout is one JSON object: `schema_version`, `version`, `target`, `proxy`, `summary`, `findings` (array), and **`hit`** (boolean). `summary` includes totals, category counts, status-hit count, false-positive count, and error count. Use `-v` to include more rows (e.g. non-200 URL payloads). URL/header false-positive rows also include `baseline_length`, `candidate_length`, `same_length`, `same_digest`, `same_normalized_text`, `baseline_content_type_family`, `candidate_content_type_family`, `same_content_type_family`, `title_mismatch`, `root_fallback`, `same_json_shape`, `same_json_text`, `json_deny_markers`, `fp_score`, `fp_threshold`, `fp_decision`, `confidence`, `fp_reasons`, and prefix digests. Structured response metadata also includes `body_preview`, `final_url` and `redirect_chain`. Low-level HTTP/1.0–1.1 probes do **not** use `--proxy`; each such finding includes `"note": "does_not_use_proxy"`.
- Structured findings now also include response metadata when available: `content_type`, `location`, `server`, `etag`, `content_length_header`.
- **`--output-format csv`:** CSV with a header row derived from union of keys; one row per finding.
- **`text` output:** prints normal probe lines plus a final `Scan Summary:` line for quick review.

### Profiles and probe selection

- **Profiles:** `safe`, `default`, `aggressive`, `proxy-aware`
- **Probe names for `--only` / `--skip`:** `nmf`, `wayback`, `ssl_switch`, `http_version`, `get_ip`
- **`--aggressive`:** merges in the aggressive preset even if another profile is selected

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | At least one “signal” was observed (e.g. HTTP 200/302 on a bypass attempt, Wayback snapshot, HTTP/1.x probe success), **`--dry-run`**, or **`--version`**. |
| `1` | Run finished with no such signal. |
| `2` | **`--max-requests`:** estimated HTTP total exceeded the limit (scan aborted; no requests sent). |

Argparse errors use the usual non-zero exit (typically `2`).

## Features

<li> Url based bypass ( url.com/path/../ etc.)
<li>Ip-based header bypass ( X-Forwarded-For etc.)
<li> Web cache based header bypass ( X-Original-URL etc.)
<li> Path char change based bypass (admin to aDmIn)
<li> Protocol change based bypass (http to https - https to http)
<li> Wayback Machine history check
<li> False-Positive result detection</li>
<li> Ip Adress based bypass  -new v0.2 </li>
<li> HTTP protocol version checks (HTTP/1.0 vs HTTP/1.1 via low-level client)  -new v0.2 </li>
<li> Optional proxy, custom headers/cookie, JSON/CSV output for automation  -new v0.3 </li>
<li> Exit codes, request delay, structured output formats  -new v0.4 </li>
<li> Extra spoofing headers, custom payload files, extra HTTP methods  -new v0.6 </li>
<li> Optional HTTP/2 probe via httpx  -new v0.7 </li>
<li> Controlled concurrency for URL payload probes  -new v0.8 </li>
<li> JSON schema version and global rate-limit support  -new v0.8.2 </li>
<li> Structured JSON summary counts for automation  -new v0.8.3 </li>
<li> Text-mode final scan summary line  -new v0.8.4 </li>
<li> Dynamic path variants and HTTP method-override header probes  -new v0.9 </li>
<li> Profiles, aggressive mode, and per-probe selection  -new v1.0 </li>
<li> Host header variations and header-combination probes  -new v1.1 </li>
<li> Timeout/retry controls and response metadata capture  -new v1.2 </li>

## HTTP protocol version checks

The tool probes **HTTP/1.0** and **HTTP/1.1** using Python’s `http.client` with separate connections (the wire request line matches the selected version). With **`--http2`**, it also tries an **HTTP/2** request via `httpx` on HTTPS targets. The HTTP/1.x probes ignore `--proxy` because they open direct sockets; the HTTP/2 probe also uses its own direct client rather than the session proxy. JSON findings include notes showing which transport path was used.

## How to work False-Positive Detection

<code>https://google.com/test/../ etc.</code> payloads or <code>X-Original-URL etc.</code> headers such as has a high false-positive rate. NoMoreForbidden now uses a small **heuristic score** instead of a single comparison: it combines **content length**, **SHA-256 digest of the first N bytes** (`--fp-bytes`, default `64`), normalized body similarity, deny-page title/body markers (such as `forbidden`, `access denied`, `restricted`), and deny-like redirects (for example `/403`). You can tune sensitivity with `--fp-threshold` (default `40`): lower values mark more responses as possible FP, higher values are stricter. The scorer is also **content-type aware**: JSON responses are evaluated with JSON-specific signals such as key-shape similarity and deny markers in `error` / `message` style fields, instead of relying only on HTML/text heuristics. Baseline selection is now configurable with `--fp-baseline`: `target` always compares against the original target response, `root` compares against the site root, and `auto` prefers the target when it already looks like a deny response and otherwise falls back to the root. For HTML responses, the scorer now also treats redirects or fallbacks to the site root as suspicious and boosts the score further when the root page title differs from the protected page title. Structured output now also exposes a short `body_preview` plus a coarse `confidence` (`low`, `medium`, `high`) so the final decision is easier to audit quickly.

### renikApp false-positive scenarios

The bundled `renikApp` playground now includes extra 403/FP cases:

- `/403/fake-200`: returns `200` with the normal forbidden template
- `/403/fake-302`: redirects back into the forbidden area
- `/403/dynamic-forbidden`: returns `403` with changing body fragments
- `/403/same-length-different-body`: returns `200` with deny-like content meant to fool naive size checks
- `/403/fake-json-200`: returns `200` JSON with deny semantics for content-type aware FP testing

## How to work CDN/WAF && Cloudflare - Cloudfront Detection

IP address-based bypass only works with the origin IP. If the target uses services like Cloudflare or CloudFront, we cannot access the original IP. While testing IP address bypass, NMF checks the server, and if the website uses Cloudflare or CloudFront, NMF notifies the user of this. Additionally, SSL Handshake failed error may also indicate a cdn/waf. This is also notified to the user.

## Development tests

<code>pip install -e ".[dev]"</code>

<code>pytest</code>

<code>ruff check .</code>

## References

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/403-and-401-bypasses
