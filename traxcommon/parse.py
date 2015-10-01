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
    """

    alphanums = string.letters + string.digits

    def __init__(self, filename=None, fp=None, split_elements=False):
        self.split_elements = split_elements
        self.version = None
        self.fp = fp
        if self.fp:
            self.fp.seek(0)
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
        self.fp.seek(0)
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

        Here we'll return the next segment, this will be a 'bare' segment
        without the segment terminator.

        We're using the array module.  Written in C this should be very
        efficient at adding and converting to a string.
        """
        seg = array.array('c')
        if not self.in_isa:
            n = self.fp.tell()
            # A strict implimentation would just take the first 106 bytes,
            # however we receive EDI that would fail. So instead we grab the
            # first 150 bytes and search for the GS segmant
            chunk = self.fp.read(300)
            if len(chunk) < 4:
                raise StopIteration
            # The fourth character in the ISA is the element separator
            # but is optional, the default is *
            if chunk[3] in '0123456789':
                self.element_sep = '*'
            else:
                self.element_sep = chunk[3]
            # TODO: This could potentially fail if the sender or
            # receiver is 15 characters and the last two are GS. The
            # logic in the parse_isa function handles this case by continuing
            # to search until a valid ISA is found.
            gs_loc = chunk.find('GS' + self.element_sep)
            if gs_loc < 0:
                raise StopIteration
            ISA = chunk[:gs_loc]
            ISA_SEGMANTS = ISA.split(self.element_sep)
            self.fp.seek(n + gs_loc)
            # A strict version would look at segmant char 106
            self.subelm_delim = ISA_SEGMANTS[-1][0]
            self.segmant_delim = ISA_SEGMANTS[-1][1]
            self.segmant_suffix = ISA_SEGMANTS[-1][2:]
            self.version = ISA_SEGMANTS[12]
            self.in_isa = True
            if self.split_elements:
                return ISA.split(self.element_sep)
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
                if i == self.segmant_delim:
                    suffix_len = len(self.segmant_suffix)
                    if suffix_len > 0:
                        suffix = self.fp.read(suffix_len)
                        if suffix != self.segmant_suffix:
                            log.debug(
                                "Invalid suffix in edi document: header=%s parsed=%s",
                                suffix, self.segmant_suffix
                            )
                            self.fp.seek(self.fp.tell() - suffix_len)
                    # End of segment found, exit the loop and return the
                    # segment.
                    segment = seg.tostring()
                    if segment.startswith('IEA'):
                        self.in_isa = False
                    if self.split_elements:
                        return segment.split(self.element_sep)
                    return segment
                elif i != '\n':
                    try:
                        seg.append(i)
                    except TypeError:
                        raise BadFile(
                            'Corrupt characters found or unexpected EOF: {}'.format(repr(i))
                        )

def parse_isa(data, max_tries=10):
    isa_segmants = []
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
        print 'b is', b
        c = isadata[b:].find("GS" + elmsep)
        if c < 0:
            raise Exception("Valid ISA not found")
        print 'gs found at', b + c
        isa_segmants = isadata[:b+c].split(elmsep)
        if len(isa_segmants) < 16:
            print 'isa seg less than 16:', len(isa_segmants), b, c
            b += c + 2
            continue
        elif len(isa_segmants) > 17:
            raise Exception("Valid ISA not found")
        break
    return data[:a+b+c]


class EdifactParser(object):
    """
    Parse EDIFACT files

    Invalid files will raise a BadFile exception.
    """

    def __init__(self, filename=None, fp=None, split_elements=False):
        self.nseg = 0
        self.split_elements = split_elements
        self.version = None
        self.fp = fp
        self.in_una = False
        if self.fp:
            self.fp.seek(0)
        else:
            if filename:
                self.open_file(filename)
            else:
                raise Exception("Must supply filename or fp")
        self.newline_after_sep = False
        self.ending_newline = False

    def __iter__(self):
        """Return the iterator for use in a for loop"""
        return self

    def open_file(self, filename):
        self.fp = open(filename, 'r')
        self.in_isa = False

    def iter_parts(self):
        index = 1
        start = None
        end = None
        for seg in self:
            if seg[:3] == 'UNA':
                if start is not None:
                    end = self.fp.tell() - len(seg)
                    yield index, start, end
                    index += 1
                    start = self.fp.tell() - len(seg)
                else:
                    start = self.fp.tell() - len(seg)
        end = self.fp.tell()
        # If the file does not start with an UNA header 'start' will be None
        if start is None:
            start = 0
        yield index, start, end

    def next(self):
        if self.nseg >= 100:
            raise StopIteration
        if not self.in_una:
            self.component_data = ':'
            self.data_element = '+'
            self.decimal_mark = ','
            self.release_char = '?'
            self.segment_delim = '\''
            n = self.fp.tell()
            chunk = self.fp.read(300)
            if chunk.startswith('UNA'):
                self.component_data = chunk[3]
                self.data_element = chunk[4]
                self.decimal_mark = chunk[5]
                self.release_char = chunk[6]
                self.segment_delim = chunk[8]
                self.fp.seek(n + 9)
                self.in_una = True
                if self.split_elements:
                    self.nseg += 1
                    return [
                        _.split(self.component_data) for _ in
                        chunk[:9].split(self.data_element)
                    ]
                else:
                    self.nseg += 1
                    return chunk[:9]
            else:
                self.fp.seek(n)
        n = self.fp.tell()
        chunk = ''
        while self.segment_delim not in chunk:
            _ = self.fp.read(300)
            if not _:
               break
            chunk += _
        if not chunk:
            raise StopIteration
        l = chunk.split(self.segment_delim, 1)
        last_chunk = False
        if len(l) == 1:
            last_chunk = True
        segment = l[0]# chunk.split(self.segment_delim, 1)[0]
        # Store the original length since we may trim it.
        seg_len = len(segment)
        if segment[0] == '\n':
            segment = segment[1:]
            self.newline_after_sep = True
            if last_chunk:
                self.ending_newline = True
        elif self.newline_after_sep == True:
            raise Exception("Expected new line")
        #print 'seek to', n + len(segment) + 1
        #print 'chunk', segment
        self.fp.seek(n + seg_len + 1)
        if not segment:
            raise StopIteration
        if self.split_elements:
            self.nseg += 1
            return [
                _.split(self.component_data) for _ in segment.split(self.data_element)
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
