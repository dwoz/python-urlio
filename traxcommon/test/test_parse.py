from . import data_path
from ..parse import xml_to_json, EdifactParser
from StringIO import StringIO


def test_xmltojson():
    """
    Tag names are lowered
    """
    i = xml_to_json('<a><b>1</b><b>2</b><b>x</b></a>')
    assert i == '{"a": {"b": [{"#text": 1}, {"#text": 2}, {"#text": "x"}]}}'
    i = xml_to_json('<A><b>1</b><b>2</b><b>X</b></A>')
    assert i == '{"a": {"b": [{"#text": 1}, {"#text": 2}, {"#text": "X"}]}}'

def test_xmltojson_attrs():
    """
    Tag attribute names are lowered
    """
    i = xml_to_json('<a><b Foo="Bar">1</b><b>2</b><b>x</b></a>')
    assert i == '{"a": {"b": [{"@foo": "Bar", "#text": 1}, {"#text": 2}, {"#text": "x"}]}}', i


def test_edifact_parsing_a():
    a = list(EdifactParser(filename=data_path('edifact'), split_elements=True))
    assert a[1][2] == ['SC1COS']
    assert a[1][3] == ['TRAX.HPENTEMEA']

def test_multi_edifact_a():
    a = EdifactParser(filename=data_path('edifact'))
    b = list(a.iter_parts())
    assert b == [(1, 0, 250917)], b

def test_multi_edifact_b():
    a = EdifactParser(filename=data_path('multi_edifact'))
    b = list(a.iter_parts())
    assert b == [(1, 0, 1320), (2, 1320, 2640)], b
    fp = open(data_path('multi_edifact'))

def test_multi_edifact_c():
    a = EdifactParser(filename=data_path('HPI_AS2PRO.TRAXPROD.file.201509291957116DE1BAC3.oigsodesadvams.0468766546.in'))
    b = list(a.iter_parts())
    assert b == [(1, 0, 906)], b

def test_edifact_parsing_b():
    s = (
        "UNB+UNOC:4+003897733:01:HPE+TRAX:ZZ+20151014:1949+9505598++DESADV'"
        "UNG+DESADV+IGSOAMHPE+TRAX+20151014:1949+9505598+UN+D:99B'UNH+1+DES"
        "ADV:D:99B:UN'BGM+351:::OUT+1000162050+9'DTM+11:201510160000EST:303"
        "'DTM+137:201510141544:203'MEA+CT+SQ+NMP'MEA+WT+AAD+LB:2.000'RFF+SI"
        ":1000162050'RFF+ON:4760916894-473-1'RFF+AAO:Delivery Block 60 remo"
        "ved.  Line?: 1'RFF+SF:US00'RFF+OP:0632634485'RFF+ZZZ:1 1'RFF+ACE:0"
        "000001602641083'RFF+BM:1000162050'RFF+AOJ:SAPPN1'NAD+SP+0080077208"
        ":161++Hewlett Packard Enterprise/SDO-US+400 WEST 69TH STREET+LOVEL"
        "AND+CO+80538+US'NAD+SR+C200:ZZZ'NAD+FW+NOSCAC:160'NAD+SF+C299:160+"
        "+Hewlett Packard Enterprise Company:C/O UPS-SCS+2230 Outer Loop+LO"
        "UISVILLE+KY+40219+US'NAD+ST+0080118531:160++Hewlett Packard Enterp"
        "rise/HFPU+165 DASCOMB RD+ANDOVER+MA+01810+US'LOC+20+US'TOD+6++DDU'"
        "FTX+DEL+++Standard'FTX+ABD+++ZSLQ'FTX+PRI+++91'CPS+1'LIN+1++12-236"
        "09-04:VP'PIA+1+HA:MP'IMD+F++:::FAN,TUBE AXIAL 4.5?'?''MEA+WT+AAA+L"
        "B:2.000'QTY+12:1.000:EA'FTX+AFT+++S2'RFF+PE:C299'PCI+24+1000162050"
        "'QTY+52:0.000:CT'UNT+36+1'UNE+1+9505598'UNZ+1+9505598'"
    )
    a = EdifactParser(fp=StringIO(s))
    l = list(a)
    assert len(l) == 42
    assert l[-1].startswith('UNZ')
