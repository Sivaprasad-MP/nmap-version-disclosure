"""Minimal Excel OOXML report writer using only the Python standard library."""
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from zipfile import ZipFile, ZIP_DEFLATED

MAIN = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
REL = 'http://schemas.openxmlformats.org/package/2006/relationships'
DOCREL = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
CONTENT = 'http://schemas.openxmlformats.org/package/2006/content-types'


def xml(element):
    return ET.tostring(element, encoding='utf-8', xml_declaration=True)


def column(n):
    result = ''
    while n:
        n, remainder = divmod(n - 1, 26)
        result = chr(65 + remainder) + result
    return result


def sheet(rows):
    if len(rows) > 1048576:
        raise ValueError('Excel row limit exceeded; use JSON for the full report')
    root = ET.Element('worksheet', xmlns=MAIN)
    views = ET.SubElement(root, 'sheetViews')
    view = ET.SubElement(views, 'sheetView', workbookViewId='0')
    ET.SubElement(view, 'pane', ySplit='1', topLeftCell='A2', activePane='bottomLeft', state='frozen')
    cols = ET.SubElement(root, 'cols')
    for i, heading in enumerate(rows[0], 1):
        width = 65 if heading in ('Evidence', 'Error', 'URL', 'Value') else 26
        ET.SubElement(cols, 'col', min=str(i), max=str(i), width=str(width), customWidth='1')
    data = ET.SubElement(root, 'sheetData')
    for i, values in enumerate(rows, 1):
        row = ET.SubElement(data, 'row', r=str(i))
        for j, value in enumerate(values, 1):
            # Inline strings preserve versions/IPs and keep untrusted evidence inert:
            # even values starting with =, +, -, or @ never become Excel formulas.
            cell = ET.SubElement(row, 'c', r=f'{column(j)}{i}', t='inlineStr')
            text = ET.SubElement(ET.SubElement(cell, 'is'), 't', {'{http://www.w3.org/XML/1998/namespace}space': 'preserve'})
            value = '' if value is None else str(value)
            value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]', '', value)
            text.text = value.encode('utf-16-le')[:65534].decode('utf-16-le', errors='ignore')
    ET.SubElement(root, 'autoFilter', ref=f'A1:{column(len(rows[0]))}{len(rows)}')
    return xml(root)


def write_excel(report, path):
    findings = [['IP address', 'Port', 'Protocol', 'Product', 'Version', 'Source', 'Evidence', 'Confidence', 'Severity', 'Method', 'URL', 'HTTP status']]
    endpoints = [['IP address', 'Port', 'Protocol', 'Outcome', 'Coverage', 'Nmap fingerprint (historical)', 'Finding count']]
    requests = [['IP address', 'Port', 'Method', 'URL', 'HTTP status', 'Error', 'Redirect not followed', 'Body truncated', 'Body skipped']]
    metadata = [['Field', 'Value'], ['Generated UTC', report['generated_at']], ['Input report', report['input_report']],
                ['TLS verification', report['tls_verification']], ['Interpretation', report['note']],
                ['Cell values', 'Stored as text. Evidence over 32767 UTF-16 units is truncated in Excel; JSON retains original values.']]
    metadata.extend([key, value] for key, value in report.get('settings', {}).items())
    for result in report['results']:
        t = result['target']
        prefix = [t['address'], t['port'], t['scheme']]
        endpoints.append(prefix + [result['outcome'], result['coverage'], t['nmap_version'], len(result['findings'])])
        for f in result['findings']:
            findings.append(prefix + [f.get(k, '') for k in ('product','version','source','evidence','confidence','severity','method','url','status')])
        for r in result['responses']:
            requests.append(prefix[:2] + [r.get(k, '') for k in ('method','url','status','error','redirect_not_followed','body_truncated','body_skipped')])
    tabs = [('Findings', findings), ('Endpoints', endpoints), ('Requests', requests), ('Scan details', metadata)]
    workbook = ET.Element('workbook', xmlns=MAIN)
    sheets = ET.SubElement(workbook, 'sheets')
    relations = ET.Element('Relationships', xmlns=REL)
    types = ET.Element('Types', xmlns=CONTENT)
    ET.SubElement(types, 'Default', Extension='rels', ContentType='application/vnd.openxmlformats-package.relationships+xml')
    ET.SubElement(types, 'Default', Extension='xml', ContentType='application/xml')
    ET.SubElement(types, 'Override', PartName='/xl/workbook.xml', ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml')
    root_rel = ET.Element('Relationships', xmlns=REL)
    ET.SubElement(root_rel, 'Relationship', Id='rId1', Type=DOCREL+'/officeDocument', Target='xl/workbook.xml')
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(path, 'w', compression=ZIP_DEFLATED) as archive:
        for i, (name, rows) in enumerate(tabs, 1):
            ET.SubElement(sheets, 'sheet', name=name, sheetId=str(i), attrib={f'{{{DOCREL}}}id': f'rId{i}'})
            ET.SubElement(relations, 'Relationship', Id=f'rId{i}', Type=DOCREL+'/worksheet', Target=f'worksheets/sheet{i}.xml')
            ET.SubElement(types, 'Override', PartName=f'/xl/worksheets/sheet{i}.xml', ContentType='application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml')
            archive.writestr(f'xl/worksheets/sheet{i}.xml', sheet(rows))
        archive.writestr('[Content_Types].xml', xml(types))
        archive.writestr('_rels/.rels', xml(root_rel))
        archive.writestr('xl/workbook.xml', xml(workbook))
        archive.writestr('xl/_rels/workbook.xml.rels', xml(relations))
