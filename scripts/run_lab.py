#!/usr/bin/env python3
"""Start loopback fixtures, run real Nmap, then validate the checker end to end."""
import argparse
import http.server
import json
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def handle(self):
        try: super().handle()
        except (ConnectionResetError, BrokenPipeError): pass
    def do_HEAD(self): self.respond()
    def do_GET(self): self.respond()
    def do_OPTIONS(self): self.respond()
    def respond(self):
        mode = self.server.scenario
        missing = self.path != '/'
        headers = {'Content-Type': 'text/html'}
        body = b'<html><title>Local test fixture</title><p>Hello</p></html>'
        status = 404 if missing else 200
        if mode == 'header': headers['Server'] = 'Apache/2.4.62'
        elif mode == 'framework':
            headers['X-Powered-By'] = 'PHP/8.2.12'
            headers['X-AspNet-Version'] = '4.0.30319'
        elif mode == 'generator': body = b'<html><meta name="generator" content="WordPress 6.6.2"></html>'
        elif mode == 'error_only' and missing: body = b'<html><address>nginx/1.24.0</address></html>'
        elif mode == 'versionless': headers['Server'] = 'nginx'
        elif mode == 'numbers': body = b'<html>Copyright 2026. Price 12.50. Date 2026-11-08</html>'
        elif mode == 'redirect':
            status = 302
            headers['Location'] = f'http://127.0.0.1:{self.server.sink_port}/outside'
        elif mode == 'vhost' and self.headers.get('Host','').split(':')[0] == 'app.lab.test': headers['Server'] = 'Jetty/12.0.1'
        elif mode == 'https': headers['Server'] = 'nginx/1.26.2'
        elif mode == 'options_only' and self.command == 'OPTIONS': headers['Server'] = 'gunicorn/23.0.0'
        if mode == 'sink': self.server.hits += 1
        self.send_response_only(status)
        headers['Content-Length'] = str(len(body))
        for k,v in headers.items(): self.send_header(k,v)
        self.end_headers()
        if self.command != 'HEAD':
            try: self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError): pass


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output-dir', type=Path, default=ROOT/'lab-artifacts')
    args = p.parse_args()
    for executable in ('nmap','openssl'):
        if not shutil.which(executable): p.error(f'{executable} is required')
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    servers, threads, checks = [], [], []
    def start(mode, context=None):
        s = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        s.scenario, s.hits = mode, 0
        if context: s.socket = context.wrap_socket(s.socket,server_side=True)
        t = threading.Thread(target=s.serve_forever,daemon=True)
        t.start()
        servers.append(s)
        threads.append(t)
        return s
    def check(name, condition):
        checks.append({'scenario':name,'passed':bool(condition)})
        print(('PASS ' if condition else 'FAIL ')+name,flush=True)
    def run_checker(name,*extra):
        dest = out/(name+'.json')
        command = [sys.executable,str(ROOT/'nmap_disclosure.py'),str(out/'nmap.xml'),'-o',str(dest),'--timeout','2','--all-open-tcp',*extra]
        result = subprocess.run(command,capture_output=True,text=True,timeout=120)
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        if result.returncode not in (0,2): raise RuntimeError(result.stderr)
        data = json.loads(dest.read_text())
        return {r['target']['port']:r for r in data['results']}
    try:
        with tempfile.TemporaryDirectory(prefix='nmap-disclosure-cert-') as tmp:
            cert, key = Path(tmp)/'cert.pem', Path(tmp)/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:app.lab.test'],check=True,capture_output=True)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert,key)
            sink = start('sink')
            modes = ('header','framework','generator','error_only','versionless','numbers','redirect','vhost','options_only','https')
            lab = {mode:start(mode,context if mode == 'https' else None) for mode in modes}
            lab['redirect'].sink_port = sink.server_port
            ports = ','.join(str(s.server_port) for s in lab.values())
            command = ['nmap','-sT','-sV','--version-light','-Pn','-n','-p',ports,'-oA',str(out/'nmap'),'127.0.0.1']
            print('Running: '+' '.join(command),flush=True)
            result = subprocess.run(command,capture_output=True,text=True,timeout=240)
            (out/'nmap.log').write_text(result.stdout+result.stderr)
            if result.returncode: raise RuntimeError(result.stderr)
            sink.hits = 0
            default = run_checker('verified')
            relaxed = run_checker('insecure','--insecure')
            virtual = run_checker('vhost-options','--insecure','--vhost','app.lab.test','--options')
            no_error = run_checker('no-error','--insecure','--no-error-page')
            check('All 10 services discovered by real Nmap and selected with --all-open-tcp',set(relaxed)=={s.server_port for s in lab.values()})
            for mode, version in [('header','2.4.62'),('framework','8.2.12'),('generator','6.6.2'),('error_only','1.24.0'),('https','1.26.2')]:
                r = relaxed.get(lab[mode].server_port,{})
                check(mode+' version detected',version in {f['version'] for f in r.get('findings',[])})
            for mode in ('versionless','numbers','redirect','vhost','options_only'):
                check(mode+' no false version finding',relaxed.get(lab[mode].server_port,{}).get('outcome')=='no_disclosure_observed')
            check('Redirect destination never contacted',sink.hits==0)
            r = default.get(lab['https'].server_port,{})
            check('Self-signed HTTPS fails verification and is inconclusive',r.get('outcome')=='inconclusive' and any('CERTIFICATE_VERIFY_FAILED' in (x.get('error') or '') for x in r.get('responses',[])))
            check('Virtual-host header exposes Jetty',any(f['version']=='12.0.1' for f in virtual.get(lab['vhost'].server_port,{}).get('findings',[])))
            check('OPTIONS-only banner detected',any(f['version']=='23.0.0' for f in virtual.get(lab['options_only'].server_port,{}).get('findings',[])))
            check('Error-page probe can be disabled',no_error.get(lab['error_only'].server_port,{}).get('outcome')=='no_disclosure_observed')
            # Close a service AFTER Nmap recorded it as open, then reuse that report.
            lab['header'].shutdown()
            lab['header'].server_close()
            stale = run_checker('stale-report','--insecure')
            check('Previously open service now unavailable is inconclusive',stale.get(lab['header'].server_port,{}).get('outcome')=='inconclusive')
            (out/'summary.json').write_text(json.dumps({'nmap_command':command,'scenarios':{k:s.server_port for k,s in lab.items()},'checks':checks},indent=2)+'\n')
            print(f'{sum(c["passed"] for c in checks)}/{len(checks)} checks passed. Artifacts: {out}',flush=True)
            return 0 if all(c['passed'] for c in checks) else 1
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
        for t in threads: t.join(timeout=3)

if __name__ == '__main__': sys.exit(main())
