import re

from lxml.etree import Element

# sbi_regex = re.compile(
#     r'(?P<protocol>HTTP/2)?[ ]*([\w\.]+[\\n]+)?[ ]*(?P<method>POST|GET|PATCH|DELETE|PUT)?[ ]*(?P<url>/.*)')
# imsi_cleaner = re.compile(r'imsi-[\d]+')
# pdu_session_id_cleaner = re.compile(r'/[\d]+')
# multiple_slash_cleaner = re.compile(r'/[/]+')
# sbiUrlDescription = collections.namedtuple('SbiDescription', 'method call')
# ascii_non_printable = re.compile(r'[\x00-\x09\x0b-\x0c\x0e-\x1f]')

# http_payload_for_stream = re.compile(r'HTTP/2 stream ([\d]+) payload')
# http_rsp_regex = re.compile(r'status: ([\d]{3})')
# http_url_regex = re.compile(r':path: (.*)')
# http_method_regex = re.compile(r':method: (.*)')

sip_rsp_regex = re.compile(r'SIP/2\.0\s+(\d{3})(.*)\n')
sip_req_regex = re.compile(r'([A-Z]+)\s+(.*?)\s+SIP/2\.0\n')


# --- Main SIP Parser ---
def parse_sip_proto(frame_number: str, sip_pdu: Element):
    """
    Parses a SIP PDU from an lxml.etree.Element (Wireshark PDML <proto name="sip">).
    Args:
        frame_number: The frame number for logging/context.
        sip_pdu: The lxml.etree.Element for the SIP protocol.
    Returns:
        Parsed SIP message
    """


    # 1. Find and parse Request-Line or Status-Line
    # These are usually specific fields in PDML.
    # Their 'showname' (or 'show') attribute contains the line.
    try:
        description = sip_pdu.find("field[@name='sip.Request-Line'][@show]").attrib['show']
    except:
        pass
    
    try:
        description = sip_pdu.find("field[@name='sip.Status-Line'][@show]").attrib['show']
    except:
        pass
    
    try:
        description = '\n{0}\n\n{1}'.format(description,
                            sip_pdu.find("field[@name='sip.msg_hdr'][@show]").attrib['show'].replace('  ', '\n'))
    except:
        pass
    
    try:
        sdp_proto_el = sip_pdu.find("field[@name='sip.msg_body']").find("proto[@name='sdp']")
        if sdp_proto_el:
            description = '{0}{1}'.format(description,
                        parse_sdp_from_xml(sdp_proto_el))
    except:
        pass
    return description
    

# --- SDP Parsing from XML ---
def parse_sdp_from_xml(sdp_proto_element: Element):
    """
    Parses an SDP <proto name="sdp"> XML element directly.
    This method iterates over XML child elements to preserve order, crucial for SDP.
    Args:
        sdp_proto_element: The <proto name="sdp"> lxml.etree.Element.
    Returns:
        A string containing parsed SDP information, or None.
    """
    if sdp_proto_element is None:
        return None
    
    sdp_str =''
    # Iterate directly over <field> children of the <proto name="sdp"> element
    for field_el in sdp_proto_element.findall("field"):
        # Use 'show' attribute if 'showname' is not present, as 'show' often has the cleaner value
        sdp_str = '{0}\n{1}'.format(sdp_str, field_el.get("showname", ""))
    return sdp_str
