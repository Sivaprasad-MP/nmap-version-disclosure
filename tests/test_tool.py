import contextlib
import http.server
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import nmap_disclosure as tool

class Tests(unittest.TestCase):
    def parse(self, text, **kw):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'scan'
            p.write_text(text)
            return tool.parse_report(p, **kw)
    def test_formats(self):
        a = self.parse('Nmap scan report for host (192.0.2.1)\n8080/tcp open http nginx 1.24.0\n443/tcp open|filtered https')
        b = self.parse('Host: 192.0.2.1 ()\tPorts: 8080/open/tcp//http//nginx 1.24.0/, 443/closed/tcp//https///')
        self.assertEqual(a, b)
        self.assertEqual(len(a), 1)
    def test_xml(self):
        r = self.parse('<nmaprun><host><address addr="::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="10443"><state state="open"/><service name="http" tunnel="ssl"/></port><port protocol="udp" portid="80"><state state="open"/></port><port protocol="tcp" portid="443"><state state="closed"/></port></ports></host></nmaprun>')
        self.assertEqual(len(r), 1)
        self.assertEqual((r[0].address, r[0].scheme), ('::1', 'https'))
    def test_entities(self):
        with self.assertRaises(ValueError):
            self.parse('<!DOCTYPE nmaprun [<!ENTITY x "abc">]><nmaprun/>')
    def test_finding(self):
        r = tool.inspect([('Server', 'Apache/2.4.62 OpenSSL/3.0.2'), ('X-AspNet-Version', '4.0.30319')], '<meta content="WordPress 6.6.2" name="generator"><p>nginx/1.24.0</p>')
        self.assertEqual({f['version'] for f in r}, {'2.4.62','3.0.2','4.0.30319','6.6.2','1.24.0'})
    def test_false_positive(self):
        self.assertEqual(tool.inspect([('Server','nginx'),('Date','2026-11-08')], '<p>Price 12.50 Copyright 2026</p>'), [])
    def test_hostname_not_resolved(self):
        self.assertEqual(self.parse('Nmap scan report for example.test\n80/tcp open http'), [])

class Handler(http.server.BaseHTTPRequestHandler):
    hits = []
    mode = 'version'
    def log_message(self, *args): pass
    def do_HEAD(self): self.do_GET()
    def do_GET(self):
        self.hits.append(self.headers['Host'])
        self.send_response_only(302 if self.mode == 'redirect' else 200)
        self.send_header('Content-Type', 'text/html')
        if self.mode == 'version': self.send_header('Server','nginx/1.24.0')
        if self.mode == 'redirect': self.send_header('Location','http://192.0.2.99:9999/outside')
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(b'<meta name="generator" content="WordPress 6.6.2">' if self.mode == 'version' else b'hello')

class Integration(unittest.TestCase):
    def setUp(self):
        Handler.hits, Handler.mode = [], 'version'
        try:
            self.s = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        except PermissionError:
            self.skipTest('Sandbox does not permit local sockets')
        self.thread = threading.Thread(target=self.s.serve_forever,daemon=True)
        self.thread.start()
        self.temp = tempfile.TemporaryDirectory()
        self.input = Path(self.temp.name)/'scan.xml'
        self.output = Path(self.temp.name)/'result.json'
        self.input.write_text(f'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="{self.s.server_port}"><state state="open"/><service name="http" product="old" version="0.0.1"/></port></ports></host></nmaprun>')
    def tearDown(self):
        self.s.shutdown()
        self.s.server_close()
        self.thread.join()
        self.temp.cleanup()
    def run_cli(self,*args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return tool.main([str(self.input),'-o',str(self.output),*args])
    def result(self): return json.loads(self.output.read_text())['results'][0]
    def test_live(self):
        self.assertEqual(self.run_cli('--vhost','app.example.test','--fail-on-finding'),1)
        self.assertEqual(self.result()['outcome'],'disclosure_found')
        self.assertTrue(self.output.with_suffix('.xlsx').is_file())
        self.assertEqual(len(Handler.hits),3)
        self.assertTrue(all(h.startswith('app.example.test:') for h in Handler.hits))
        self.assertNotIn('0.0.1',{f['version'] for f in self.result()['findings']})
    def test_custom_excel_path(self):
        dest = Path(self.temp.name)/'custom.xlsx'
        self.assertEqual(self.run_cli('--excel', str(dest)), 0)
        self.assertTrue(dest.is_file())

    def test_output_collision(self):
        with self.assertRaises(SystemExit):
            self.run_cli('--excel',str(self.input))
        self.assertEqual(Handler.hits,[])

    def test_redirect(self):
        Handler.mode = 'redirect'
        self.assertEqual(self.run_cli(),0)
        self.assertTrue(all(r['redirect_not_followed'] for r in self.result()['responses']))
        self.assertEqual(len(Handler.hits),3)
    def test_failure(self):
        with patch.object(tool.http.client.HTTPConnection,'connect',side_effect=OSError('test failure')):
            self.assertEqual(self.run_cli(),2)
        self.assertEqual(self.result()['outcome'],'inconclusive')
    def test_dry_run(self):
        self.assertEqual(self.run_cli('--dry-run'),0)
        self.assertEqual(Handler.hits,[])
        self.assertFalse(self.output.exists())
    def test_body_limit(self):
        self.assertEqual(self.run_cli('--max-body','8'),0)
        self.assertTrue(self.result()['responses'][1]['body_truncated'])
        self.assertEqual({f['product'] for f in self.result()['findings']},{'nginx'})



class FakeSocket:
    def __init__(self, payload): self.payload = payload
    def makefile(self, *args): return io.BytesIO(self.payload)
    def sendall(self, data): pass
    def setsockopt(self, *args): pass
    def close(self): pass

class TransportTests(unittest.TestCase):
    def args(self):
        from argparse import Namespace
        return Namespace(vhost='app.example.test', timeout=1, insecure=False, max_body=1000, no_error_page=False, options=False)
    def test_real_http_parser_and_scope(self):
        wire = b'HTTP/1.1 302 Found\r\nServer: nginx/1.24.0\r\nLocation: http://192.0.2.99/\r\nContent-Length: 0\r\n\r\n'
        with patch.object(tool.socket, 'create_connection', side_effect=lambda *a, **kw: FakeSocket(wire)) as connect:
            result = tool.scan(tool.Target('192.0.2.1',8080,'http'), self.args())
        self.assertEqual(result['outcome'], 'disclosure_found')
        self.assertEqual(connect.call_count,3)
        self.assertTrue(all(c.args[0] == ('192.0.2.1',8080) for c in connect.call_args_list))
        self.assertTrue(all(r['redirect_not_followed'] for r in result['responses']))
    def test_failure_not_clean(self):
        with patch.object(tool.socket, 'create_connection', side_effect=OSError('unreachable')):
            result = tool.scan(tool.Target('192.0.2.1',80,'http'), self.args())
        self.assertEqual(result['outcome'], 'inconclusive')
    def test_tls_sni_pinned(self):
        from unittest.mock import MagicMock
        context = MagicMock()
        with patch.object(tool.socket, 'create_connection') as connect:
            conn = tool.PinnedTLS('192.0.2.1',443,'app.example.test',1,context)
            conn.connect()
        connect.assert_called_once_with(('192.0.2.1',443),1)
        context.wrap_socket.assert_called_once_with(connect.return_value,server_hostname='app.example.test')
    def test_body_and_truncation(self):
        body = b'<meta name="generator" content="WordPress 6.6.2">'
        wire = b'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        args = self.args()
        with patch.object(tool.socket, 'create_connection', side_effect=lambda *a, **kw: FakeSocket(wire)):
            r = tool.request(tool.Target('192.0.2.1',80,'http'),'GET','/missing',args)
            self.assertEqual(r['findings'][0]['version'],'6.6.2')
            args.max_body = 8
            r = tool.request(tool.Target('192.0.2.1',80,'http'),'GET','/',args)
            self.assertTrue(r['body_truncated'])
            self.assertEqual(r['findings'],[])

if __name__ == '__main__': unittest.main()
