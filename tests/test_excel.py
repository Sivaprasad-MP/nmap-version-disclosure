import json
from pathlib import Path
import tempfile
import unittest
import xml.etree.ElementTree as ET
from zipfile import ZipFile
from excel_report import write_excel, MAIN

class ExcelTests(unittest.TestCase):
    def report(self):
        return dict(generated_at='2026-11-08T00:00:00+00:00', input_report='scan.xml', tls_verification=False, note='Test report', settings={}, results=[dict(target=dict(address='127.0.0.1',port=443,scheme='https',nmap_version='old 1.0'), outcome='disclosure_found',coverage='partial',findings=[dict(product='nginx',version='1.26.2',evidence='=HYPERLINK("https://example.invalid")\x00 <&>',source='header:server',confidence='high',severity='info',method='GET',url='https://127.0.0.1/',status=200)],responses=[dict(method='HEAD',url='https://127.0.0.1/',status=None,error='timeout')])])
    def test_workbook_evidence_and_safe_strings(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'result.xlsx'
            write_excel(self.report(),p)
            with ZipFile(p) as z:
                for name in z.namelist(): ET.fromstring(z.read(name))
                workbook = ET.fromstring(z.read('xl/workbook.xml'))
                self.assertEqual([s.get('name') for s in workbook.findall(f'{{{MAIN}}}sheets/{{{MAIN}}}sheet')],['Findings','Endpoints','Requests','Scan details'])
                root = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
                values = [t.text for t in root.iter(f'{{{MAIN}}}t')]
                self.assertIn('1.26.2',values)
                self.assertIn('=HYPERLINK("https://example.invalid") <&>',values)
                self.assertEqual(list(root.iter(f'{{{MAIN}}}f')),[])
                errors = z.read('xl/worksheets/sheet3.xml').decode()
                self.assertIn('timeout',errors)
    def test_empty_findings_has_headers(self):
        r = self.report()
        r['results'][0]['findings'] = []
        r['results'][0]['outcome'] = 'inconclusive'
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'empty.xlsx'
            write_excel(r,p)
            with ZipFile(p) as z:
                root = ET.fromstring(z.read('xl/worksheets/sheet1.xml'))
                self.assertEqual(len(list(root.iter(f'{{{MAIN}}}row'))),1)
                self.assertIn('inconclusive',z.read('xl/worksheets/sheet2.xml').decode())
