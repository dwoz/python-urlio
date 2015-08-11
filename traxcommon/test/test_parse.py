from ..parse import xml_to_json


def test_xmltojson():
    """
    Tag names are lowered
    """
    i = xml_to_json('<a><b>1</b><b>2</b><b>x</b></a>')
    assert i == '{"a": {"b": [{"#text": 1}, {"#text": 2}, {"#text": "x"}]}}'
    i = xml_to_json('<A><b>1</b><b>2</b><b>X</b></A>')
    assert i == '{"a": {"b": [{"#text": 1}, {"#text": 2}, {"#text": "X"}]}}'
