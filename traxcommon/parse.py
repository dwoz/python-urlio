import string
import array

class BadFile(Exception):
    """Raised when file corruption is detected."""


class X12Parser(object):
    """
    Parse X12 files

    Invalid files will raise a BadFile exception.
    """

    alphanums = string.letters + string.digits

    def __init__(self, filename=None, fp=None):
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
                            log.warn(
                                "Invalid suffix in edi document: header=%s parsed=%s",
                                suffix, self.segmant_suffix
                            )
                            self.fp.seek(self.fp.tell() - suffix_len)
                    # End of segment found, exit the loop and return the
                    # segment.
                    segment = seg.tostring()
                    if segment.startswith('IEA'):
                        self.in_isa = False
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
