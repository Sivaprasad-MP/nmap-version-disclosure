#!/usr/bin/env python3
"""Recheck HTTP version disclosure on open TCP endpoints in an Nmap report."""
import argparse
from excel_report import write_excel
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
import http.client
import ipaddress
import json
from pathlib import Path
import re
import socket
import ssl
import sys
import uuid
import xml.etree.ElementTree as ET

COMMON_HTTP = {80, 81, 443, 591, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9443}
TLS_PORTS = {443, 8443, 9443}
VERSION = r'\d+(?:\.\d+){1,4}(?:[a-zA-Z][\w.-]*|[-+][\w.-]+)?'
PAIRS = re.compile(r'\b([A-Za-z][A-Za-z0-9_.+-]*)\s*[/ ]\s*(' + VERSION + r'|\d+)(?![\w.])')
BODY_PAIR = re.compile(r'\b(Apache(?: Tomcat)?|nginx|openresty|PHP|Microsoft-IIS|Jetty|Werkzeug|Python|OpenSSL|LiteSpeed|Express|gunicorn|WordPress|Drupal|Joomla|Kestrel|uvicorn|CherryPy)(?:\s+version)?\s*[/ :\-(]\s*(' + VERSION + r'|\d+)(?![\w.])', re.I)
DISCLOSURE_HEADERS = {'server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-runtime-version'}

@dataclass(frozen=True)
class Target:
    address: str
    port: int
    scheme: str
    service: str = ''
    nmap_version: str = ''


def target(address, port, service='', banner='', tunnel='', all_tcp=False):
    # Require literal scanned addresses: never resolve report hostnames to new hosts.
    try:
        ipaddress.ip_address(address)
        port = int(port)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    service = service.lower()
    if not (all_tcp or 'http' in service or port in COMMON_HTTP):
        return None
    tls = tunnel == 'ssl' or 'https' in service or service.startswith('ssl/') or port in TLS_PORTS
    return Target(address, port, 'https' if tls else 'http', service, banner)


def parse_report(path, all_tcp=False):
    data = Path(path).read_text(encoding='utf-8-sig', errors='replace')
    found = []
    def add(*args):
        item = target(*args, all_tcp=all_tcp)
        if item:
            found.append(item)
    if data.lstrip().startswith('<'):
        if re.search(r'<!ENTITY', data, re.I):
            raise ValueError('XML entity declarations are not supported')
        root = ET.fromstring(data)
        if root.tag != 'nmaprun':
            raise ValueError('Expected an Nmap XML report')
        for host in root.findall('host'):
            addresses = [a.get('addr') for a in host.findall('address') if a.get('addrtype') in ('ipv4', 'ipv6')]
            if not addresses:
                continue
            for p in host.findall('./ports/port'):
                state = p.find('state')
                if p.get('protocol') != 'tcp' or state is None or state.get('state') != 'open':
                    continue
                s = p.find('service')
                attrs = s.attrib if s is not None else {}
                add(addresses[0], p.get('portid', '0'), attrs.get('name', ''),
                    ' '.join(attrs.get(k, '') for k in ('product', 'version', 'extrainfo')).strip(), attrs.get('tunnel', ''))
    elif re.search(r'^Host: .*Ports:', data, re.M):
        for line in data.splitlines():
            m = re.match(r'Host:\s+(\S+).*?Ports:\s*(.*)', line)
            if not m:
                continue
            for entry in m[2].split(','):
                fields = entry.strip().split('/')
                if len(fields) >= 7 and fields[1:3] == ['open', 'tcp']:
                    add(m[1], fields[0], fields[4].replace('|', '/'), fields[6])
    else:
        address = None
        for line in data.splitlines():
            m = re.match(r'Nmap scan report for (.+)', line)
            if m:
                address = m[1].split('(')[-1].rstrip(') ')
            m = re.match(r'^(\d+)/tcp\s+open\s+(\S+)(?:\s+(.*))?$', line)
            if m and address:
                add(address, m[1], m[2], m[3] or '')
    return sorted(set(found), key=lambda t: (t.address, t.port, t.scheme))


class Metadata(HTMLParser):
    def __init__(self):
        super().__init__()
        self.generators = []
        self.text = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag.lower() == 'meta' and (a.get('name') or '').lower() == 'generator':
            self.generators.append(a.get('content') or '')
    def handle_data(self, data):
        self.text.append(data)


def inspect(headers, body):
    findings = []
    def record(product, version, source, evidence, confidence='high'):
        findings.append(dict(product=product, version=version, source=source,
                             evidence=evidence[:500], confidence=confidence,
                             severity='info', kind='version_disclosure'))
    for name, value in headers:
        key = name.lower()
        if key not in DISCLOSURE_HEADERS:
            continue
        if key in {'x-aspnet-version', 'x-aspnetmvc-version', 'x-runtime-version'}:
            m = re.fullmatch(r'\s*(' + VERSION + r'|\d+)\s*', value)
            if m:
                record(key.removeprefix('x-').removesuffix('-version'), m[1], 'header:' + key, value)
        else:
            for m in PAIRS.finditer(value):
                record(m[1], m[2], 'header:' + key, value)
    parser = Metadata()
    parser.feed(body)
    for value in parser.generators:
        for m in PAIRS.finditer(value):
            record(m[1], m[2], 'html:generator', value, 'medium')
    # Known software names reduce false positives from dates and arbitrary numbers.
    for m in BODY_PAIR.finditer(' '.join(parser.text)):
        record(m[1], m[2], 'html:software-banner', m[0], 'medium')
    return list({(f['product'], f['version'], f['source'], f['evidence']): f for f in findings}.values())


class PinnedTLS(http.client.HTTPSConnection):
    """Use selected SNI/Host while keeping the connection on the scanned IP."""
    def __init__(self, address, port, name, timeout, context):
        super().__init__(name, port, timeout=timeout, context=context)
        self.address = address
    def connect(self):
        raw = socket.create_connection((self.address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def request(t, method, path, args):
    name = args.vhost or t.address
    authority = '[' + name + ']' if ':' in name else name
    if t.port != (443 if t.scheme == 'https' else 80):
        authority += ':' + str(t.port)
    url = f'{t.scheme}://{authority}{path}'
    conn = None
    result = dict(method=method, url=url, status=None, error=None, findings=[])
    try:
        if t.scheme == 'https':
            context = ssl._create_unverified_context() if args.insecure else ssl.create_default_context()
            conn = PinnedTLS(t.address, t.port, name, args.timeout, context)
        else:
            conn = http.client.HTTPConnection(t.address, t.port, timeout=args.timeout)
        conn.request(method, path, headers={'Host': authority, 'User-Agent': 'NmapDisclosure/1.0',
                     'Accept': 'text/html,*/*;q=0.1', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = conn.getresponse()
        result['status'] = response.status
        headers = response.getheaders()
        # Do not retain cookies, authentication challenges, or arbitrary response bodies.
        result['disclosure_headers'] = [(k, v) for k, v in headers if k.lower() in DISCLOSURE_HEADERS]
        result['redirect_not_followed'] = 300 <= response.status < 400
        result['findings'] = inspect(headers, '')
        if method != 'HEAD':
            payload = response.read(args.max_body + 1)
            result['body_truncated'] = len(payload) > args.max_body
            content_type = response.getheader('Content-Type', '').lower()
            encoding = response.getheader('Content-Encoding', 'identity').lower()
            if encoding in ('', 'identity') and (not content_type or 'text/' in content_type or 'html' in content_type):
                body = payload[:args.max_body].decode('utf-8', errors='replace')
                result['findings'] = inspect(headers, body)
            else:
                result['body_skipped'] = 'Non-text or compressed response'
    except (OSError, http.client.HTTPException, ValueError) as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        if conn:
            conn.close()
    return result


def scan(t, args):
    probes = [('HEAD', '/'), ('GET', '/')]
    if not args.no_error_page:
        probes.append(('GET', '/__version_disclosure_check_' + uuid.uuid4().hex))
    if args.options:
        probes.append(('OPTIONS', '/'))
    responses = [request(t, method, path, args) for method, path in probes]
    findings = []
    for r in responses:
        for f in r['findings']:
            findings.append(dict(f, method=r['method'], url=r['url'], status=r['status']))
    successes = sum(r['status'] is not None and not r['error'] for r in responses)
    state = 'disclosure_found' if findings else ('no_disclosure_observed' if successes == len(responses) else 'inconclusive')
    return dict(target=asdict(t), outcome=state, coverage='complete' if successes == len(responses) else 'partial',
                findings=findings, responses=responses)


def positive_float(value):
    n = float(value)
    if not 0 < n <= 300:
        raise argparse.ArgumentTypeError('must be > 0 and <= 300')
    return n


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('report', type=Path, help='Existing Nmap XML (preferred), normal text, or grepable report')
    p.add_argument('-o', '--output', type=Path, default=Path('disclosure-report.json'))
    p.add_argument('--excel', type=Path, help='Excel output path (default: JSON output name with .xlsx extension)')
    p.add_argument('--dry-run', action='store_true', help='List selected targets without network requests')
    p.add_argument('--all-open-tcp', action='store_true', help='Try HTTP on every reported open TCP port')
    p.add_argument('--insecure', action='store_true', help='Accept untrusted HTTPS certificates; recorded in report')
    p.add_argument('--vhost', help='Host header and TLS SNI name; connection remains on each scanned IP')
    p.add_argument('--timeout', type=positive_float, default=5, help='Socket-operation timeout in seconds (default 5)')
    p.add_argument('--workers', type=int, choices=range(1, 33), default=4, metavar='1..32')
    p.add_argument('--max-body', type=int, default=262144, help='Maximum inspected response bytes (default 262144)')
    p.add_argument('--no-error-page', action='store_true', help='Skip the randomized missing-page GET')
    p.add_argument('--options', action='store_true', help='Also issue OPTIONS /')
    p.add_argument('--fail-on-finding', action='store_true', help='Exit 1 if any version disclosure is observed')
    args = p.parse_args(argv)
    if not 1 <= args.max_body <= 10485760:
        p.error('--max-body must be between 1 and 10485760')
    if args.vhost and (len(args.vhost) > 253 or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', args.vhost)):
        p.error('--vhost must be an ASCII DNS name without scheme, port, or path')
    try:
        targets = parse_report(args.report, args.all_open_tcp)
        if not targets:
            p.error('No HTTP candidates with literal IP addresses and open TCP ports found; use XML or --all-open-tcp')
        if args.dry_run:
            print(json.dumps([asdict(t) for t in targets], indent=2))
            return 0
        excel_path = args.excel or args.output.with_suffix('.xlsx')
        paths = [args.report.resolve(), args.output.resolve(), excel_path.resolve()]
        if len(set(paths)) != len(paths):
            p.error('Input, JSON output, and Excel output must have different paths')
        if excel_path.suffix.lower() != '.xlsx':
            p.error('Excel output must have an .xlsx extension')
        print(f'Checking {len(targets)} endpoints...', file=sys.stderr)
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(lambda t: scan(t, args), targets))
        report = dict(schema_version=1, generated_at=datetime.now(timezone.utc).isoformat(),
                      input_report=str(args.report), tls_verification=not args.insecure,
                      settings=dict(timeout=args.timeout, max_body=args.max_body, vhost=args.vhost,
                                    error_page=not args.no_error_page, options=args.options),
                      note='Live self-reported versions; not proof of installed versions or CVE exposure. Nmap fingerprints are historical context.',
                      results=results)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        write_excel(report, excel_path)
        for result in results:
            t = result['target']
            versions = sorted({f"{f['product']}/{f['version']}" for f in result['findings']})
            print(f"{t['address']}:{t['port']} ({t['scheme']}) {result['outcome']} [coverage: {result['coverage']}] " + ', '.join(versions))
        print(f'Report: {args.output.resolve()}')
        print(f'Excel: {excel_path.resolve()}')
        if any(r['coverage'] != 'complete' for r in results):
            return 2
        return 1 if args.fail_on_finding and any(r['findings'] for r in results) else 0
    except (OSError, ValueError, ET.ParseError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
