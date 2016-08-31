from . import data_path
from ..parse import xml_to_json, EdifactParser, x12transform, X12Parser
from six import StringIO
import six
if six.PY3:
    from io import BytesIO


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
    if six.PY3:
        assert b == [(1, 0, 905)], b
    else:
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
    a = EdifactParser(fp=StringIO(s), split_elements=True)
    l = list(a)
    assert len(l) == 40, len(l)
    assert l[-1][0][0] == 'UNZ', l[-1][0]


def test_edifact_parsing_c():
    s = (
        "UNB+UNOC:4+003897733:01:HPE+TRAX:ZZ+20151014:1949+9505598++DESADV'\n"
        "UNG+DESADV+IGSOAMHPE+TRAX+20151014:1949+9505598+UN+D:99B'\nUNH+1+DES"
        "ADV:D:99B:UN'\nBGM+351:::OUT+1000162050+9'\nDTM+11:201510160000EST:303"
        "'\nDTM+137:201510141544:203'\nMEA+CT+SQ+NMP'\nMEA+WT+AAD+LB:2.000'\nRFF+SI"
        ":1000162050'RFF+ON:4760916894-473-1'\nRFF+AAO:Delivery Block 60 remo"
        "ved.  Line?: 1'\nRFF+SF:US00'\nRFF+OP:0632634485'\nRFF+ZZZ:1 1'\nRFF+ACE:0"
        "000001602641083'\nRFF+BM:1000162050'\nRFF+AOJ:SAPPN1'\nNAD+SP+0080077208"
        ":161++Hewlett Packard Enterprise/SDO-US+400 WEST 69TH STREET+LOVEL"
        "AND+CO+80538+US'\nNAD+SR+C200:ZZZ'\nNAD+FW+NOSCAC:160'\nNAD+SF+C299:160+"
        "+Hewlett Packard Enterprise Company:C/O UPS-SCS+2230 Outer Loop+LO"
        "UISVILLE+KY+40219+US'\nNAD+ST+0080118531:160++Hewlett Packard Enterp"
        "rise/HFPU+165 DASCOMB RD+ANDOVER+MA+01810+US'\nLOC+20+US'\nTOD+6++DDU'\n"
        "FTX+DEL+++Standard'\nFTX+ABD+++ZSLQ'\nFTX+PRI+++91'\nCPS+1'\nLIN+1++12-236"
        "09-04:VP'\nPIA+1+HA:MP'\nIMD+F++:::FAN,TUBE AXIAL 4.5?'\n?'\n'MEA+WT+AAA+L"
        "B:2.000'\nQTY+12:1.000:EA'\nFTX+AFT+++S2'\nRFF+PE:C299'\nPCI+24+1000162050"
        "'\nQTY+52:0.000:CT'\nUNT+36+1'\nUNE+1+9505598'UNZ+1+9505598'\n"
    )
    a = EdifactParser(fp=StringIO(s), split_elements=True)
    l = list(a)
    assert len(l) == 40, len(l)
    assert l[-1][0][0] == 'UNZ', l[-1][0]


def test_edifact_parsing_e():
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
    a = EdifactParser(fp=StringIO(s), split_elements=True)
    l = list(a)
    assert len(l) == 40, len(l)
    assert l[-1][0][0] == 'UNZ', l[-1][0]


def test_x12transform():
    edi = (
        "ISA*00*          *00*          *ZZ*EXDO           *ZZ*TRAX."
        "HPLA      *140905*2132*U*00401*922950489*1*P*:!GS*IM*EXDO*T"
        "RAX.HPLA*20140905*2132*922950489*X*004010!ST*210*922950489!"
        "B3**E2J0563155*22J0169431*CC*K*20140905*5035****EXDO!C3*USD"
        "*1.  !N9*OR*CKG!N9*DE*GDL!N9*8X*INBOUND ASN!G62*10*20140826"
        "!G62*11*20140827!G62*12*20140904!R3*CA***A******DD*ST!N9*SO"
        "*0027914338!N9*SO*0027914335!N9*SO*0027914334!LX*1!N9*IK*E2"
        "J0563155!N9*BM*421140028!N9*MB*999-24399631!N9*PO*H5258685!"
        "N9*PO*H5258678!N9*PO*H5258677!N9*DO*6931296262!N9*DO*693129"
        "6261!N9*DO*6931296260!L0*1***9.0*G*0.04*X*2*PLT**K!L0*1*600"
        "0*OR*9.0*B******K!L1*1***3093****400****AIR FREIGHT!L1*1***"
        "1765****405****FUEL SURCHARGE!L1*1***177****GSS****ISS!L4*4"
        "3*18*31*C*1!L4*47*15*29*C*1!N1*BT*Hewlett-Packard Mexico S "
        "de!N3*RL de CV /Prolongacion Reforma #800*Col. Lomas de San"
        "ta Fe!N4*Mexico*DF*01210*MX!N1*SH*INVENTEC(CHONGQING) CORPO"
        "RATION!N3*NO.66 WEST DISTRICT 2ND RD!N4*CHONGQING 401331***"
        "CN!N1*CN*Hewlett Packard de Mexico SA de CV!N3*Montemorelos"
        "#299*Colonia Loma Bonita!N4*Guadalajara*JA*45060*MX!L3*9.0*"
        "B***5035*******K!SE*41*922950489!GE*1*922950489!IEA*1*92295"
        "0489!"
    )
    fp = StringIO(edi)
    s = x12transform(
        fp,
        data_element_separator='+',
        component_separator='^',
        segment_terminator='-',
        segment_suffix='\n',
    )
    transformed = (
        'ISA+00+          +00+          +ZZ+EXDO           +ZZ+TRAX.H'
        'PLA      +140905+2132+U+00401+922950489+1+P+^-\nGS+IM+EXDO+TR'
        'AX.HPLA+20140905+2132+922950489+X+004010-\nST+210+922950489-\n'
        'B3++E2J0563155+22J0169431+CC+K+20140905+5035++++EXDO-\nC3+USD'
        '+1.  -\nN9+OR+CKG-\nN9+DE+GDL-\nN9+8X+INBOUND ASN-\nG62+10+20140'
        '826-\nG62+11+20140827-\nG62+12+20140904-\nR3+CA+++A++++++DD+ST-'
        '\nN9+SO+0027914338-\nN9+SO+0027914335-\nN9+SO+0027914334-\nLX+1-'
        '\nN9+IK+E2J0563155-\nN9+BM+421140028-\nN9+MB+999-24399631-\nN9+P'
        'O+H5258685-\nN9+PO+H5258678-\nN9+PO+H5258677-\nN9+DO+6931296262'
        '-\nN9+DO+6931296261-\nN9+DO+6931296260-\nL0+1+++9.0+G+0.04+X+2+'
        'PLT++K-\nL0+1+6000+OR+9.0+B++++++K-\nL1+1+++3093++++400++++AIR'
        ' FREIGHT-\nL1+1+++1765++++405++++FUEL SURCHARGE-\nL1+1+++177++'
        '++GSS++++ISS-\nL4+43+18+31+C+1-\nL4+47+15+29+C+1-\nN1+BT+Hewlet'
        't-Packard Mexico S de-\nN3+RL de CV /Prolongacion Reforma #80'
        '0+Col. Lomas de Santa Fe-\nN4+Mexico+DF+01210+MX-\nN1+SH+INVEN'
        'TEC(CHONGQING) CORPORATION-\nN3+NO.66 WEST DISTRICT 2ND RD-\nN'
        '4+CHONGQING 401331+++CN-\nN1+CN+Hewlett Packard de Mexico SA '
        'de CV-\nN3+Montemorelos#299+Colonia Loma Bonita-\nN4+Guadalaja'
        'ra+JA+45060+MX-\nL3+9.0+B+++5035+++++++K-\nSE+41+922950489-\nGE'
        '+1+922950489-\nIEA+1+922950489-\n'
    )
    assert s == transformed, repr(s)

def test_no_ending_nl():
    """
    Parse edi which is missing last segment terminator
    """
    src = (
        'ISA+00+          +00+          +ZZ+EXDO           +ZZ+TRAX.H'
        'PLA      +140905+2132+U+00401+922950489+1+P+^\nGS+IM+EXDO+TR'
        'AX.HPLA+20140905+2132+922950489+X+004010\nST+210+922950489\n'
        'B3++E2J0563155+22J0169431+CC+K+20140905+5035++++EXDO\nC3+USD'
        '+1.  \nN9+OR+CKG\nN9+DE+GDL\nN9+8X+INBOUND ASN\nG62+10+20140'
        '826\nG62+11+20140827\nG62+12+20140904\nR3+CA+++A++++++DD+ST'
        '\nN9+SO+0027914338\nN9+SO+0027914335\nN9+SO+0027914334\nLX+1'
        '\nN9+IK+E2J0563155\nN9+BM+421140028\nN9+MB+99924399631\nN9+P'
        'O+H5258685\nN9+PO+H5258678\nN9+PO+H5258677\nN9+DO+6931296262'
        '\nN9+DO+6931296261\nN9+DO+6931296260\nL0+1+++9.0+G+0.04+X+2+'
        'PLT++K\nL0+1+6000+OR+9.0+B++++++K\nL1+1+++3093++++400++++AIR'
        ' FREIGHT\nL1+1+++1765++++405++++FUEL SURCHARGE\nL1+1+++177++'
        '++GSS++++ISS\nL4+43+18+31+C+1\nL4+47+15+29+C+1\nN1+BT+Hewlet'
        'tPackard Mexico S de\nN3+RL de CV /Prolongacion Reforma #80'
        '0+Col. Lomas de Santa Fe\nN4+Mexico+DF+01210+MX\nN1+SH+INVEN'
        'TEC(CHONGQING) CORPORATION\nN3+NO.66 WEST DISTRICT 2ND RD\nN'
        '4+CHONGQING 401331+++CN\nN1+CN+Hewlett Packard de Mexico SA '
        'de CV\nN3+Montemorelos#299+Colonia Loma Bonita\nN4+Guadalaja'
        'ra+JA+45060+MX\nL3+9.0+B+++5035+++++++K\nSE+41+922950489\nGE'
        '+1+922950489\nIEA+1+922950489'
    )
    parser = X12Parser(fp=StringIO(src), split_elements=True)
    isa = None
    iea = None
    for a in parser:
        if a[0] == 'ISA':
            isa = a
        if a[0] == 'IEA':
            iea = a
    assert isa == ['ISA', '00', '          ', '00', '          ', 'ZZ',
        'EXDO           ', 'ZZ', 'TRAX.HPLA      ', '140905', '2132', 'U',
        '00401', '922950489', '1', 'P', '^\n'], isa
    assert iea == ['IEA', '1', '922950489'], iea
