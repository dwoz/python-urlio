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

is_strval = lambda x : isinstance(x, str) or isinstance(x, unicode)
is_dict = lambda x : isinstance(x, collections.OrderedDict)

class BadFile(Exception):
    """Raised when file corruption is detected."""


class X12Parser(object):
    """
    Parse X12 files

    Invalid files will raise a BadFile exception.

    Delimiters -
      ISA*00**00**ZZ*RECEIVERID*12*SENDERID*100325*1113*U*00403*000011436*0*T*>~ 
         ^                                                                    ^^^
         |                                                                    |||
         +-- data_element_separator                                           |||
                                                       component_separator ---+||
                                                                               ||
                                                       segment_terminator -----+|
                                                                                |
                                                       segment_suffix ----------+
    """

    alphanums = string.letters + string.digits

    def __init__(self, filename=None, fp=None, split_elements=False, offset=0):
        self.split_elements = split_elements
        self.version = None
        self.fp = fp
        self._offset = offset
        self._stop = False
        if self.fp:
            self.fp.seek(self._offset)
            self.in_isa = False
        else:
            if filename:
                self.open_file(filename)
            else:
                raise Exception("Must supply filename or fp")

    def __iter__(self):
        """Return the iterator for use in a for loop"""
        return self

    def open_file(self, filename):
        self.fp = open(filename, 'r')
        self.in_isa = False

    def iter_parts(self):
        self.fp.seek(self._offset)
        index = 1
        start = None
        end = None
        for segment in self:
            if segment[:3] == 'ISA':
                start = self.fp.tell() - len(segment)
            if segment[:3] == 'IEA':
                end = self.fp.tell()
            if start is not None and end is not None:
                yield index, start, end
                index += 1
                start = None
                end = None

    def next(self):
        """return the next segment from the file or raise StopIteration

        Here we'll return the next segment, this will be a 'bare'
        segment
        without the segment terminator.

        We're using the array module.  Written in C this should be very
        efficient at adding and converting to a string.
        """
        if self._stop:
            raise StopIteration
        seg = array.array('c')
        if not self.in_isa:
            n = self.fp.tell()
            # A strict implimentation would just take the first 106 bytes,
            # however we receive EDI that would fail. So instead we grab the
            # first 150 bytes and search for the GS segment
            chunk = self.fp.read(300)
            if len(chunk) < 4:
                raise StopIteration
            # The fourth character in the ISA is the element separator
            # but is optional, the default is *
            if chunk[3] in '0123456789':
                self.data_element_separator = '*' # Data element separator
            else:
                self.data_element_separator = chunk[3] # Data element separator
            # TODO: This could potentially fail if the sender or
            # receiver is 15 characters and the last two are GS. The
            # logic in the parse_isa function handles this case by continuing
            # to search until a valid ISA is found.
            gs_loc = chunk.find('GS' + self.data_element_separator)
            if gs_loc < 0:
                raise StopIteration
            ISA = chunk[:gs_loc]
            ISA_SEGMANTS = ISA.split(self.data_element_separator)
            self.fp.seek(n + gs_loc)
            # A strict version would look at segment char 106
            DELIMS = ISA_SEGMANTS[-1]
            if len(DELIMS) == 1:
                self.component_separator = ''
                self.segment_terminator = ISA_SEGMANTS[-1][0]
                self.segment_suffix = '' # Segmant suffix
            else:
                self.component_separator = ISA_SEGMANTS[-1][0]
                self.segment_terminator = ISA_SEGMANTS[-1][1] # Segmant separator
                self.segment_suffix = ISA_SEGMANTS[-1][2:] # Segmant suffix
            self.version = ISA_SEGMANTS[12]
            self.in_isa = True
            if self.split_elements:
                return ISA.split(self.data_element_separator)
            else:
                return ISA
        else:
            #We're somewhere in the body of the X12 message.  We just
            #read until we find the segment terminator and return the
            #segment.  (We still ignore line feeds unless the line feed
            #is the segment terminator.
            while 1:
                i = self.fp.read(1)
                if i == '\0': continue
                if i == self.segment_terminator:
                    suffix_len = len(self.segment_suffix)
                    if suffix_len > 0:
                        suffix = self.fp.read(suffix_len)
                        if suffix != self.segment_suffix:
                            log.debug(
                                "Invalid suffix in edi document: header=%s parsed=%s",
                                suffix, self.segment_suffix
                            )
                            self.fp.seek(self.fp.tell() - suffix_len)
                    # End of segment found, exit the loop and return the
                    # segment.
                    segment = seg.tostring()
                    if segment.startswith('IEA'):
                        self.in_isa = False
                    if self.split_elements:
                        return segment.split(self.data_element_separator)
                    return segment
                elif not i:
                    self._stop = True
                    segment = seg.tostring()
                    if segment.startswith('IEA'):
                        self.in_isa = False
                    if self.split_elements:
                        return segment.split(self.data_element_separator)
                    return segment
                elif i not in ['\r', '\n']:
                    try:
                        seg.append(i)
                    except TypeError:
                        raise BadFile(
                            'Corrupt characters found or unexpected EOF: {}'.format(repr(i))
                        )

def parse_isa(data, max_tries=10):
    isa_segments = []
    a = data.find("ISA")
    isadata = data[a:]
    elmsep = isadata[3]
    if elmsep in '0123456789':
        elmsep = '*'
    b = 0
    tried = 0
    while True:
        tried += 1
        if tried > max_tries:
            raise Exception("Max tries reached")
        c = isadata[b:].find("GS" + elmsep)
        if c < 0:
            raise Exception("Valid ISA not found")
        isa_segments = isadata[:b+c].split(elmsep)
        if len(isa_segments) < 16:
            print 'isa seg less than 16:', len(isa_segments), b, c
            b += c + 2
            continue
        elif len(isa_segments) > 17:
            raise Exception("Valid ISA not found")
        break
    return data[:a+b+c]


class EdifactParser(object):
    """
    Parse EDIFACT files

    Invalid files will raise a BadFile exception.
    """

    def __init__(self, filename=None, fp=None, split_elements=False, offset=0):
        self.nseg = 0
        self.split_elements = split_elements
        self.version = None
        self.fp = fp
        self.in_una = False
        self._offset = offset
        if self.fp:
            self.fp.seek(self._offset)
        else:
            if filename:
                self.open_file(filename)
            else:
                raise Exception("Must supply filename or fp")
        self.newline_after_sep = False
        self.ending_newline = False
        self.end_of_stream = False
        self.buffer = ''

    def __iter__(self):
        """Return the iterator for use in a for loop"""
        return self

    def open_file(self, filename):
        self.fp = open(filename, 'r')
        self.in_isa = False

    def iter_parts(self):
        self.fp.seek(self._offset)
        index = 1
        start = None
        end = None
        for segment in self:
            if segment[:3] == 'UNA':
                start = self.start_of_segment
                print 'has start a',  start
            elif start is None and segment[:3] == 'UNB':
                start = self.start_of_segment
                print 'has start b',  start
            if segment[:3] == 'UNZ':
                end = self.start_of_buffer
                print 'has end', end
            if start is not None and end is not None:
                yield index, start, end
                index += 1
                start = None
                end = None

    def next(self):
        while True:
            if self.fp.tell() == 0:
                self.start_of_buffer = 0
            elif not self.buffer:
                raise StopIteration
            if not self.end_of_stream:
                chunk = self.fp.read(300)
                if not chunk:
                    self.end_of_stream = True
                chunk = self.buffer + chunk
            else:
                chunk = self.buffer
            if not self.in_una:
                if chunk.startswith('\n'):
                    chunk = chunk[1:]
                    self.start_of_buffer += 1
                self.component_data = ':'
                self.data_element = '+'
                self.decimal_mark = ','
                self.release_char = '?'
                self.segment_delim = '\''
                if chunk.startswith('UNA'):
                    self.component_data = chunk[3]
                    self.data_element = chunk[4]
                    self.decimal_mark = chunk[5]
                    self.release_char = chunk[6]
                    self.segment_delim = chunk[8]
                    self.buffer = chunk[9:]
                    self.start_of_segment = self.start_of_buffer
                    self.start_of_buffer = self.start_of_buffer + 9
                    if self.split_elements:
                        return [
                            _.split(self.component_data) for _ in
                            chunk[:9].split(self.data_element)
                        ]
                    else:
                        return chunk[:9]
                self.in_una = True
            orig_len = len(chunk)
            l = escape_split(chunk, self.segment_delim, self.release_char, 1)
            last_chunk = False
            segment = l[0]
            if len(l) == 1 and not self.end_of_stream:
                if l[0] == '\n':
                    self.buffer = ''
                else:
                    self.buffer = l[0]
                continue
            elif len(l) == 1 and self.end_of_stream:
                self.buffer = ''
            else:
                self.buffer = l[1]
            self.start_of_segment = self.start_of_buffer
            self.start_of_buffer += orig_len - len(self.buffer)
            if not segment:
                raise StopIteration
            if segment[0] == '\n':
                segment = segment[1:]
                self.newline_after_sep = True
            if segment[:3] == 'UNZ':
                self.in_una = False
            if self.split_elements:
                self.nseg += 1
                return [
                    escape_split(_, self.component_data, self.release_char)
                    for _ in escape_split(segment, self.data_element, self.release_char)
                ]
            else:
                self.nseg += 1
                return segment


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
        def bytes(i):
            if type(i) == unicode:
                return i.encode('ascii')
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

def escape_split(s, delim, escape_chr='\\', max_split=0):
    i, res, buf, n = 0, [], '', 0
    while True:
        j, e = s.find(delim, i), 0
        if j < 0:  # end reached
            return res + [buf + s[i:]]  # add remainder
        elif max_split and n == max_split:
            return res + [buf + s[i:]]
        while j - e and s[j - e - 1] == escape_chr:
            e += 1  # number of escapes
        d = e // 2  # number of double escapes
        if e != d * 2:  # odd number of escapes
            buf += s[i:j - d - 1] + s[j]  # add the escaped char
            i = j + 1  # and skip it
            continue  # add more to buf
        res.append(buf + s[i:j - d])
        n += 1
        i, buf = j + len(delim), ''  # start after delim
