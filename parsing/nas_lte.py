import logging
import re
import traceback

import yaml
from lxml.etree import Element

from parsing.common import xml2json

nas_lte_req_regex = re.compile(r"nas-eps\..*_type:.*[Rr]equest.*")
nas_lte_message_type_regex = re.compile(r"nas-eps\..*_type:.*: (.*)")
s1ap_message_type_regex = re.compile(r"s1ap.procedureCode: 'procedureCode: id-(.*)'")


NAS_LTE_MESSAGES = ('Attach request (0x41)',
                    'Attach accept (0x42)',
                    'Attach reject (0x44)',
                    'PDN connectivity request (0xd0)',
                    'Activate default EPS bearer context request (0xc1)',
                    'Activate default EPS bearer context accept (0xc2)',
                    'Activate default EPS bearer context reject (0xc3)',
                    'Activate dedicated EPS bearer context request (0xc5)',
                    'Activate dedicated EPS bearer context accept (0xc6)',
                    'Activate dedicated EPS bearer context reject (0xc7)'
                    'Deactivate EPS bearer context request (0xcd)',
                    'Dectivate EPS bearer context accept (0xce)', 
                    'Deativate EPS bearer context reject (0xcf)'
                    )

NAS_MM_LTE_MESSAGES = ('Attach request (0x41)',
                    'Attach accept (0x42)',
                    'Attach reject (0x44)'
                    )

NAS_SM_LTE_MESSAGES = (
                    'PDN connectivity request (0xd0)',
                    'Activate default EPS bearer context request (0xc1)',
                    'Activate default EPS bearer context accept (0xc2)',
                    'Activate default EPS bearer context reject (0xc3)',
                    'Activate dedicated EPS bearer context request (0xc5)',
                    'Activate dedicated EPS bearer context accept (0xc6)',
                    'Activate dedicated EPS bearer context reject (0xc7)'
                    )

def parse_lte_nas_proto_el(frame_number, el: Element, multipart_proto=False):
    if not multipart_proto:
        s1ap_pdu = el.find("field[@name='s1ap.S1AP_PDU']")
    else:
        s1ap_pdu = el
    if s1ap_pdu is None:
        return ''
    nas_4g_protos = find_nas_proto(s1ap_pdu)
    if (nas_4g_protos is None) or (len(nas_4g_protos) == 0):
        return ''

    nas_4g_json_all = []
    for nas_4g_proto in nas_4g_protos:
        nas_4g_dict = nas_4g_proto_to_dict(nas_4g_proto)
        nas_4g_json_all.append(yaml.dump(nas_4g_dict, indent=4, width=1000, sort_keys=False))
    nas_4g_json_str = '\n'.join(nas_4g_json_all)

    # Add NGAP PDU session to the transcription
    try:
        nas_4g_json_str = 'S1AP-PDU: {0}\n{1}'.format(s1ap_pdu.attrib['value'], nas_4g_json_str)
    except:
        try:
            # Some newer Wireshark versions may already include the parsed message
            nas_4g_json_str = 'S1AP-PDU: {0}\n{1}'.format(s1ap_pdu.find('field').attrib['value'], nas_4g_json_str)
        except:
            logging.error('Frame {0}: Could not add S1AP PDU session payload'.format(frame_number))
            traceback.print_exc()

    return nas_4g_json_str


def parse_lte_nas_proto(frame_number, el, multipart_proto=False):
    if not isinstance(el, list):
        return parse_lte_nas_proto_el(frame_number, el, multipart_proto)

    all_json = [parse_lte_nas_proto_el(frame_number, e, multipart_proto) for e in el]
    return '\n'.join(all_json)


def nas_4g_proto_to_dict(nas_4g_proto):
    if (nas_4g_proto is None):
        return {}
    return xml2json(nas_4g_proto)


def find_nas_proto(s1ap_pdu: Element) -> list[Element]:
    if s1ap_pdu is None:
        return None

    # Return also NGAP information
    nas_messages = []
    for child in s1ap_pdu:
        nas_messages.append(child)
    return nas_messages

    # Since sometimes the proto object is empty, I need to do this workaround
    plain_nas = s1ap_pdu.findall(".//field[@show='Plain NAS message']")
    security_nas = s1ap_pdu.findall(".//field[@show='Security protected NAS message']")

    all_nas = plain_nas
    if len(security_nas) > 0:
        all_nas.extend(security_nas)

    if len(all_nas) < 1:
        return None

    return all_nas


