# Nmap HTTP version disclosure checker

Recheck HTTP/HTTPS services from an **existing Nmap report** and collect live version-disclosure evidence. Python 3.10+, standard library only. Works on Windows, Linux, and WSL. Use on networks you are authorized to assess.

## Run

From this project directory:

```bash
# Preview endpoints without contacting them
python nmap_disclosure.py scan.xml --dry-run

# Perform checks and save JSON evidence
python nmap_disclosure.py scan.xml -o findings.json

# Internal HTTPS with self-signed certificates
python nmap_disclosure.py scan.xml --insecure -o findings.json

# A named virtual host: TCP stays on the IP from the report
python nmap_disclosure.py scan.xml --vhost app.example.com -o app-findings.json

# Existing normal-text or grepable reports also work
python nmap_disclosure.py scan.nmap
python nmap_disclosure.py scan.gnmap
```

Use `python3` on WSL/Linux if `python` is unavailable, or `py -3` on Windows. XML is preferred because it preserves structured service and TLS information. No new Nmap scan is required. The bundled sample contains documentation-only addresses: use it with `--dry-run`.

## What is checked

Only reported **open TCP** ports are eligible. The default selection includes services whose name contains `http`, plus common web ports (80, 81, 443, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443). `--all-open-tcp` also tries other open TCP ports. HTTPS is selected from Nmap's SSL tunnel/service information or ports 443/8443/9443; there is no automatic protocol fallback.

Each endpoint receives `HEAD /`, `GET /`, and a GET for a randomized missing path. The latter can expose an error-page server signature. `--no-error-page` disables it; `--options` adds `OPTIONS /`. No malformed requests, authentication, crawling, or exploitation are implemented. Redirects are recorded but never followed. Proxy environment variables are not used.

Detection covers:

- Numeric product versions in `Server`, `X-Powered-By`, and `X-Generator`.
- `X-AspNet-Version`, `X-AspNetMvc-Version`, and `X-Runtime-Version`.
- HTML generator metadata and known software names followed by versions in page text, including error pages.

Product-only banners such as `Server: nginx` are retained as evidence but are not version findings. Historical Nmap product/version data is kept separately and never treated as a live disclosure. Findings are informational: version exposure alone does not establish a vulnerable version or a CVE.

## Results and controls

The terminal prints endpoint outcomes and unique versions. JSON includes each finding's product, version, source, evidence, confidence, URL, method, and HTTP status. It also records individual request errors, body truncation, redirects, TLS verification, and historical fingerprints.

- `disclosure_found`: at least one live version-bearing response.
- `no_disclosure_observed`: all configured requests completed without a detected version in inspected evidence. This does not guarantee absence elsewhere.
- `inconclusive`: no findings and at least one failed request.
- `coverage: partial`: one or more requests failed, even if another exposed a version.

Default concurrency is four endpoints (`--workers 1` through `32`). Default timeout is five seconds **per socket operation**, not a total endpoint deadline. Response inspection is limited to 256 KiB (`--max-body`); compressed/non-text bodies are skipped. Only disclosure headers and matching excerpts are saved, not full pages or cookies.

Exit codes: `0` completed; `1` findings with `--fail-on-finding`; `2` invalid input, output failure, or any incomplete endpoint check. Incomplete checks take precedence over exit code 1.

Connections use literal scanned IP addresses, including IPv6. Hostname-only reports cannot establish this scope and are skipped; use Nmap XML with addresses. `--vhost` sets one DNS name for every selected endpoint, including TLS SNI, without changing the connection address. Run separately for different virtual hosts. Certificates are verified by default; `--insecure` explicitly disables verification and is recorded.

## Method references and limits

This is an independent implementation informed by public descriptions, not a Nessus plugin port or an equivalent to its coverage:

- [Tenable 10107: HTTP Server Type and Version](https://www.tenable.com/plugins/nessus/10107) describes server type/version identification.
- [Tenable 88099: Web Server HTTP Header Information Disclosure](https://www.tenable.com/plugins/nessus/88099) describes header disclosure. Tenable labels that plugin Medium and requires its paranoid setting; this tool uses informational findings and does not copy its severity policy.
- [Tenable 11239: Crafted Request Vendor/Version Information Disclosure](https://www.tenable.com/plugins/nessus/11239) describes discovery using crafted requests. Our missing-page GET is a limited independent check; it does not reproduce that plugin's unspecified request techniques.
- [Nmap XML output documentation](https://nmap.org/book/output-formats-xml-output.html) recommends XML for programmatic consumption.
- [RFC 9110, Server field](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.4) documents server product information and cautions against unnecessary detail.

Banners can be spoofed, added by proxies, or refer to client-side components. Body matches have medium confidence and need review; header confidence means confidence in the observed string, not installed software accuracy. Checks miss authenticated pages, other virtual hosts, redirect destinations, unsupported product patterns, compressed content, and content beyond the body limit. Treat results as evidence to review. Reduce exposed banner detail and production error-page signatures using your server/framework settings; keep software patched independently.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests cover parsers, version extraction, false-positive controls, HTTP parsing, redirect scope, TLS SNI/IP pinning, errors, body limits, and a local HTTP server. Local socket tests skip when the execution sandbox prohibits sockets.

## Reproducible real-Nmap lab

Install Nmap and OpenSSL and put them on PATH, then run:

```bash
python scripts/run_lab.py
```

The lab binds ten temporary HTTP/HTTPS services to `127.0.0.1`, runs real Nmap TCP connect and lightweight version detection against only those ports, and feeds the generated XML into this checker using `--all-open-tcp`. This includes arbitrary TLS ports that Nmap may label `ssl/unknown`; Nmap’s SSL tunnel metadata still selects HTTPS. It validates header and framework leaks, generator metadata, error-page-only disclosure, versionless banners, unrelated numbers, redirects, named virtual hosts, OPTIONS-only disclosure, self-signed TLS, and a service that disappears after Nmap scans it. It also checks that redirects never reach a separate local destination.

Reports and the assertion summary are saved in `lab-artifacts/` (excluded from Git). Servers stop automatically, and temporary TLS keys/certificates are removed. Fixtures advertise synthetic versions; they do not install or run those software versions. The scanner itself still requires no third-party Python packages.
