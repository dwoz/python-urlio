from __future__ import print_function, unicode_literals
import io
import sys
import six
import collections
import string
import array
import re
import logging
import json
import xmltodict


log = logging.getLogger(__name__)


class REGEX:
    number = re.compile('^\d+$')
    float_number = re.compile('^\d+\.\d+$')


def is_strval(x):
    return isinstance(x, str) or isinstance(x, unicode)


def is_dict(x):
    return isinstance(x, collections.OrderedDict)


def value_transform(data_in):
    if not data_in:
        return data_in
    data_out = collections.OrderedDict()
    for k in data_in:
        if isinstance(data_in[k], list) and data_in[k] and is_dict(data_in[k][0]):
            l = []
            for i in data_in[k]:
                l.append(value_transform(i))
            data_out[k.lower()] = l
            continue
        if is_dict(data_in[k]):
            data_out[k.lower()] = value_transform(data_in[k])
            continue
        if is_strval(data_in[k]) and REGEX.number.match(data_in[k]):
            data_out[k.lower()] = int(data_in[k])
            continue
        if is_strval(data_in[k]) and REGEX.float_number.match(data_in[k]):
            data_out[k.lower()] = float(data_in[k])
            continue
        data_out[k.lower()] = data_in[k]
    return data_out


def xml_to_dict(fp, force_cdata=True, **kwargs):
    return value_transform(xmltodict.parse(fp, force_cdata=force_cdata, **kwargs))


def xml_to_json(fp, force_cdata=True, **kwargs):
    return json.dumps(xml_to_dict(fp, force_cdata=force_cdata, **kwargs))


def x12transform(fp, data_element_separator=None, component_separator=None,
        segment_terminator=None, segment_suffix=None):
    parser = X12Parser(fp=fp, split_elements=True)
    s = ''
    for element in parser:
        # TODO: This seems sketch in python3 land. Needs some thought and/or
        # testing.
        def bytes(i):
            try:
                if type(i) == unicode:
                    return i.encode('ascii')
            except NameError:
                return i
            return i
        if data_element_separator is None:
            data_element_separator = parser.data_element_separator
        data_element_separator = bytes(data_element_separator)
        if segment_terminator is None:
            segment_terminator = parser.segment_terminator
        segment_terminator = bytes(segment_terminator)
        if segment_suffix is None:
            segment_suffix = parser.segment_suffix
        segment_suffix = bytes(segment_suffix)
        if component_separator is None:
            component_separator = parser.component_separator
        component_separator = bytes(component_separator)
        if element[0] == 'ISA':
            element[-1] = ''.join([component_separator, segment_terminator])
            s += data_element_separator.join(element)
            s += segment_suffix
        else:
            s += data_element_separator.join(element)
            s += segment_terminator + segment_suffix
    return s
