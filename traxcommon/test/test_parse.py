from . import data_path
from ..parse import xml_to_json, EdifactParser


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


def test_edifact_parsing():
    a = list(EdifactParser(filename=data_path('edifact'), split_elements=True))
    assert a[1][2] == ['SC1COS']
    assert a[1][3] == ['TRAX.HPENTEMEA']

def test_multi_edifact_a():
    a = EdifactParser(filename=data_path('edifact'))
    b = list(a.iter_parts())
    assert b == [(1, 0, 2303)], b

def test_multi_edifact_b():
    a = EdifactParser(filename=data_path('multi_edifact'))
    b = list(a.iter_parts())
    assert b == [(1, 0, 1321), (2, 1321, 2484)], b

def test_multi_edifact_c():
    a = EdifactParser(filename=data_path('HPI_AS2PRO.TRAXPROD.file.201509291957116DE1BAC3.oigsodesadvams.0468766546.in'))
    b = list(a.iter_parts())
    assert b == [(1, 0, 906)], b
