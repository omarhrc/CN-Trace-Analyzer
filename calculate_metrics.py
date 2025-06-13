# -*- coding: utf-8 -*-
"""
Created on Wed Jun  4 06:37:07 2025

@author: omar_
"""
import pandas as pd
import collections
import logging
import os
import os.path
import re

import platform
import glob

from parsing.sip_measurements import SIPMeasurementAggregator
from parsing.diameter_measurements import DiameterMeasurementAggregator
from parsing.pfcp_measurements import PfcpMeasurementAggregator
from parsing.gtp_measurements import GtpMeasurementAggregator
from utils.wireshark import import_pcap_as_dataframe
from parsing import nas_lte
from parsing.s1ap_measurements import ESMProcedureManager, EMMProcedureManager

application_logger = logging.getLogger()
application_logger.setLevel(logging.DEBUG)

debug = False

PROTOCOLS = ['NGAP', 'HTTP/2', 'PFCP', 'GTP', 'Diameter', 'S1AP', 'SIP', 'SDP']
FEATURE_NAMES = ['tps', 'time']

def get_unique_endpoints(packets_df):
    """
    Calculates the number of unique network endpoints from a DataFrame in an optimized way.

    This method is more memory-efficient than creating and concatenating
    two separate DataFrames.

    Args:
        packets_df: A pandas DataFrame with columns 'ip_src', 'port_src',
                    'ip_dst', 'port_dst', and 'transport_protocol'.

    Returns:
        int: The total number of unique endpoints.
    """
    # 1. Stack the source and destination IP addresses and ports into single Series.
    # The transport_protocol Series is duplicated to match the new length.
    ips = pd.concat([packets_df['ip_src'], packets_df['ip_dst']], ignore_index=True)
    ports = pd.concat([packets_df['port_src'], packets_df['port_dst']], ignore_index=True)
    protocols = pd.concat([packets_df['transport_protocol'], packets_df['transport_protocol']], ignore_index=True)

    # 2. Create a new DataFrame from the stacked Series.
    endpoints_df = pd.DataFrame({
        'ip_addr': ips,
        'port': ports,
        'transport_protocol': protocols
    })

    # 3. Drop duplicates and return the count of the remaining unique rows.
    # .shape[0] is a fast way to get the number of rows (the length).
    unique_endpoints = endpoints_df.drop_duplicates()
    unique_string = ','.join(
        unique_endpoints['ip_addr'] + ':' +
        unique_endpoints['port'] + ':' +
        unique_endpoints['transport_protocol']
    )

    return unique_endpoints.shape[0], unique_string

def calculate_total_protocol_duration(protocol, procedure_df):
    if procedure_df is None or len(procedure_df) == 0:
        return 0
    match protocol:
        case 'NGAP' | 'HTTP/2':
            result = calculate_procedure_length_5GC(procedure_df)
        case 'S1AP':
            result = calculate_procedure_length_eps(procedure_df)
        case 'SIP':
            result = calculate_procedure_length_sip(procedure_df)
        case 'PFCP':
            result = calculate_procedure_length_pfcp(procedure_df)
        case 'GTP':
            result = calculate_procedure_length_gtp(procedure_df)
        case 'Diameter':
            result = calculate_procedure_length_diameter(procedure_df)
        case _:
            print(f'Protocol {protocol} not found')
            return 0
    if result is None or len(result) != 2:
        return 0
    if isinstance(result[0], pd.DataFrame):
        return result[0]['length_ms'].sum()

def create_protocol_features(packets_df, protocol, total_duration):
    ''' Calculates features for each protocol '''
    if total_duration == 0:
        return None
    protocol_packets = packets_df[packets_df['protocol'].str.contains(protocol)]
    # Feature 1 - TPS
    transactions_per_second = len(protocol_packets)/total_duration
    if protocol == "SDP":
        return {'SDP_tps': transactions_per_second}
    # Feature 2 - Protocol duration
    total_protocol_duration = calculate_total_protocol_duration(protocol, protocol_packets) / 1000
    if protocol == "SIP":
        return {'SIP_tps': transactions_per_second,
                'SIP_PDD': total_protocol_duration}
    if protocol == "PFCP":
        unique_enpoints_number, unique_endpoints = get_unique_endpoints(protocol_packets)
        return {'PFCP_tps': transactions_per_second,
                'PFCP_time': total_protocol_duration,
                'PFCP_unique_number': unique_enpoints_number,
                'PFCP_unique_endpoint': unique_endpoints
                }
    protocol_feature_names = [f'{protocol}_{feature}' for feature in FEATURE_NAMES]
    feature_values = [transactions_per_second, total_protocol_duration]
    return dict(zip(protocol_feature_names, feature_values))

    
def create_feature_vector(packets_df):
    feature_vector = dict()
    total_duration = packets_df['timestamp'].max() - packets_df['timestamp'].min()
    for protocol in PROTOCOLS:
        feature_vector.update(create_protocol_features(packets_df, protocol, total_duration))
    feature_vector.update({"total_duration":total_duration})
    total_unique_endpoints, _ = get_unique_endpoints(packets_df)
    feature_vector.update({"total_unique_endpoints":total_unique_endpoints})
    return feature_vector


def create_feature_vector_from_file(file_path):
    ''' Converts one pcap file into a vector '''
    packets_df = import_pcap_as_dataframe(
        file_path,
        http2_ports = "32445,5002,5000,32665,80,32077,5006,8080,3000,8081,29502,37904",
        wireshark_version = 'OS',
        platform=platform.system(),
        logging_level=logging.INFO,
        remove_pdml=True)
    
    if len(packets_df) == 0:
        return None
    vector = create_feature_vector(packets_df)
    # Updates vector with information from filename itself
    file_name = os.path.basename(file_path)
    imsi, test, row_id, *_ = file_name.split('_')
    vector.update({"IMSI":imsi, "test":test, "RowID":row_id,
                   "file_path":file_path})
    return vector
    

def create_vectors_from_traces(directory_path, pattern="**.pcap*"):
    """
    Iterates over files in a specified Windows directory matching a pattern.
    Can be recursive if pattern includes '**' and recursive=True.

    Args:
        directory_path (str): The base path to start searching.
        pattern (str): The file pattern to match (e.g., '*.txt', '**.pdf' for recursive).
    """
    if not os.path.isdir(directory_path):
        print(f"Error: Directory not found at '{directory_path}'")
        return

    full_pattern_path = os.path.join(directory_path, pattern)
    print(f"Files matching '{full_pattern_path}':")

    # Use recursive=True if your pattern contains '**' to search subdirectories
    is_recursive_search = '**' in pattern
    result = list()
    try:
        for file_path in glob.glob(full_pattern_path, recursive=is_recursive_search):
            if os.path.isfile(file_path): # Ensure it's a file, not a directory if '**' is used
                print(f"  File: {file_path}")
                # Perform operations on the file
                vector = create_feature_vector_from_file(file_path)
                if vector is not None:
                    vector.update({'file_path':file_path})
                    result.append(vector)
    except Exception as e:
        print(f"An error occurred: {e}")
    result_df = pd.DataFrame(result)
    return result_df


def calculate_procedure_length_eps(packets_df, logging_level=logging.INFO):
    if packets_df is None:
        return None
    procedure_frames = pd.DataFrame()
    for nas_lte_msg in nas_lte.NAS_LTE_MESSAGES:
        procedure_to_add_df = packets_df[packets_df['msg_description'].str.contains(nas_lte_msg,
                                                                         regex=False)]        
        procedure_frames = pd.concat([procedure_frames, procedure_to_add_df])
    procedure_frames.sort_values("datetime", inplace=True)
    procedure_frames.drop_duplicates(inplace=True)

    procedure_frames['MME-UE-S1AP-ID'] = ''
    procedure_frames['ENB-UE-S1AP-ID'] = ''

    def get_id(regex, x, find_all=False):
        try:
            if not find_all:
                match = re.search(regex, x)
                if match is None:
                    return ''
                return match.group(1)
            else:
                match = list(re.finditer(regex, x))
                if len(match) == 0:
                    return ''
                matches = [e for e in match if e is not None]
                matches = [e.group(1) for e in matches]
                matches = '\n'.join(matches)
            return matches
        except:
            return ''

    procedure_frames['MME-UE-S1AP-ID'] = procedure_frames['msg_description'].apply(
        lambda x: get_id(r"'MME-UE-S1AP-ID: ([\d]+)'", x))
    procedure_frames['ENB-UE-S1AP-ID'] = procedure_frames['msg_description'].apply(
        lambda x: get_id(r"'ENB-UE-S1AP-ID: ([\d]+)'", x))

    unique_ran_ids = procedure_frames['ENB-UE-S1AP-ID'].unique()
    logging.debug('Found ENB-UE-S1AP-IDs: {0}'.format(len(unique_ran_ids)))
    logging.debug('Parsing procedures based on ENB_UE_S1AP_ID')

    output_columns = ['ENB_UE_S1AP_ID', 'name', 'length_ms', 'start_frame', 'end_frame',
               'start_timestamp', 'end_timestamp',
               'start_datetime', 'end_datetime']
    procedure_df = pd.DataFrame(columns=output_columns)


    for ran_id in unique_ran_ids:
        rows = procedure_frames[procedure_frames['ENB-UE-S1AP-ID'] == ran_id]
        emm_manager = EMMProcedureManager()
        esm_manager = ESMProcedureManager()
        for row in rows.itertuples():
            emm_manager.process_emm_messages(row.summary,
                                                 timestamp=row.timestamp,
                                                 frame=row.frame_number, date_time=row.datetime)
            esm_manager.process_esm_messages(row.msg_description, row.msg_description,                                                 
                                                 timestamp=row.timestamp, 
                                                 frame=row.frame_number, date_time=row.datetime)
        for description_list in emm_manager.procedure_counters.values():
            procedure_counters_df =pd.DataFrame(description_list, columns=output_columns)
            procedure_counters_df['ENB_UE_S1AP_ID'] = ran_id
            procedure_df = pd.concat([procedure_df, procedure_counters_df], ignore_index=True)
        for description_list in esm_manager.procedure_counters.values():
            procedure_counters_df =pd.DataFrame(description_list, columns=output_columns)
            procedure_counters_df['ENB_UE_S1AP_ID'] = ran_id
            procedure_df = pd.concat([procedure_df, procedure_counters_df], ignore_index=True)

    logging.debug('Parsed {0} procedures'.format(len(procedure_df)))
    return procedure_df, procedure_frames




def calculate_procedure_length_sip(packets_df, first_call_only=True, logging_level=logging.INFO):
    if packets_df is None:
        return None
    procedure_frames = packets_df[packets_df['protocol'].str.contains('SIP', regex=False)]
    # Find UACs
    sip_invite_packets = procedure_frames[procedure_frames['msg_description'].str.contains(r"INVITE sips?:[^ ]+ SIP/2\.0")]
    if len(sip_invite_packets) == 0:
        return None
    sip_uac_df = sip_invite_packets[['ip_src', 'port_src', 'ip_dst', 'port_dst', 'transport_protocol']].copy()
    if first_call_only:
        sip_uac_df = pd.DataFrame(sip_uac_df.head(1))
    sip_uac_keys = set(sip_uac_df.itertuples(index=False, name=None))

    logging.debug("Parsing SIP procedures based on ('ip_src', 'port_src', 'ip_dst', 'port_dst', 'transport_protocol')")
    aggregator = SIPMeasurementAggregator()
    for sip_uac in sip_uac_keys:
        for row in procedure_frames.itertuples():
            if sip_uac in {
                (row.ip_src, row.port_src, row.ip_dst, row.port_dst, row.transport_protocol),
                (row.ip_dst, row.port_dst, row.ip_src, row.port_src, row.transport_protocol)
            }:
                aggregator.process_message((*sip_uac, True),
                                   row.msg_description,
                                   timestamp=row.timestamp,
                                    frame=row.frame_number)
    dataframes = aggregator.get_all_data()
    logging.debug('Parsed {0} calls'.format(len(dataframes['measurements'])))
    return dataframes['measurements'], procedure_frames


def calculate_procedure_length_diameter(packets_df, logging_level=logging.INFO):
    if packets_df is None:
        return None
    procedure_frames = packets_df[packets_df['protocol'].str.contains('Diameter', regex=False)]
    # Find diameter endpoints
    diameter_requests = procedure_frames[procedure_frames['msg_description'].str.contains(r"= Request: Set")]
    if len(diameter_requests) == 0:
        return None
    diameter_requests_df = diameter_requests[['ip_src', 'port_src', 'ip_dst', 'port_dst', 'transport_protocol']].copy()

    diameter_keys = set(diameter_requests_df.itertuples(index=False, name=None))

    logging.debug("Parsing diameter procedures based on ('ip_src', 'port_src', 'ip_dst', 'port_dst', 'transport_protocol')")
    aggregator = DiameterMeasurementAggregator()
    for diameter_peer in diameter_keys:
        for row in procedure_frames.itertuples():
            if diameter_peer in {
                (row.ip_src, row.port_src, row.ip_dst, row.port_dst, row.transport_protocol),
                (row.ip_dst, row.port_dst, row.ip_src, row.port_src, row.transport_protocol)
            }:
                aggregator.process_message((*diameter_peer, True),
                                   row.msg_description,
                                   timestamp=row.timestamp,
                                    frame=row.frame_number)
    dataframes = aggregator.get_all_data()
    logging.debug('Parsed {0} calls'.format(len(dataframes['measurements'])))
    return dataframes['measurements'], procedure_frames

def calculate_procedure_length_pfcp(packets_df, logging_level=logging.INFO):
    if packets_df is None:
        return None
    procedure_frames = packets_df[packets_df['protocol'].str.contains('PFCP', regex=False)]
    # Find PFCP endpoints
    pfcp_requests = procedure_frames[procedure_frames['msg_description'].str.contains(r"Message Type:.*?Request")]
    if len(pfcp_requests) == 0:
        return None
    pfcp_requests_df = pfcp_requests[['ip_src', 'port_src', 'ip_dst', 'port_dst', 'transport_protocol']].copy()

    pfcp_keys = set(pfcp_requests_df.itertuples(index=False, name=None))

    logging.debug("Parsing pfcp procedures based on ('ip_src', 'port_src', 'ip_dst', 'port_dst', 'transport_protocol')")
    aggregator = PfcpMeasurementAggregator()
    for pfcp_peer in pfcp_keys:
        for row in procedure_frames.itertuples():
            if pfcp_peer in {
                (row.ip_src, row.port_src, row.ip_dst, row.port_dst, row.transport_protocol),
                (row.ip_dst, row.port_dst, row.ip_src, row.port_src, row.transport_protocol),
            }:
                aggregator.process_message((*pfcp_peer, True),
                                   row.msg_description,
                                   timestamp=row.timestamp,
                                    frame=row.frame_number)
    dataframes = aggregator.get_all_data()
    logging.debug('Parsed {0} calls'.format(len(dataframes['measurements'])))
    return dataframes['measurements'], procedure_frames


def calculate_procedure_length_gtp(packets_df, logging_level=logging.INFO):
    if packets_df is None:
        return None
    procedure_frames = packets_df[packets_df['protocol'].str.contains('GTP', regex=False)]
    # Find GTP endpoints
    gtp_requests = procedure_frames[procedure_frames['msg_description'].str.contains(r"Message Type:.*?Request")]
    if len(gtp_requests) == 0:
        return None
    gtp_requests_df = gtp_requests[['ip_src', 'port_src', 'ip_dst', 'port_dst', 'transport_protocol']].copy()

    gtp_keys = set(gtp_requests_df.itertuples(index=False, name=None))

    logging.debug("Parsing GTPv2 procedures based on ('ip_src', 'port_src', 'ip_dst', 'port_dst', 'transport_protocol')")
    aggregator = GtpMeasurementAggregator()
    for gtp_peer in gtp_keys:
        for row in procedure_frames.itertuples():
            peer = None
            peer1 = (row.ip_src, row.port_src, row.ip_dst, row.port_dst, row.transport_protocol)
            peer2 = (row.ip_dst, row.port_dst, row.ip_src, row.port_src, row.transport_protocol)
            if gtp_peer == peer1:
                peer = peer1
            if gtp_peer == peer2:
                peer = peer2
            if peer:
                aggregator.process_message(gtp_peer, peer==peer1,
                                   row.msg_description,
                                   timestamp=row.timestamp,
                                    frame=row.frame_number)
    dataframes = aggregator.get_all_data()
    logging.debug('Parsed {0} calls'.format(len(dataframes['measurements'])))
    return dataframes['measurements'], procedure_frames

def calculate_procedure_length_5GC(packets_df):
    procedure_frames = packets_df[
        ((packets_df['summary'] == 'NAS Registration request (0x41)') & (
            ~packets_df['msg_description'].str.contains(r'Security mode complete \(0x5e\)'))) |
        (packets_df['summary'] == 'NAS Registration accept (0x42)') |
        (packets_df['summary'] == 'NAS Registration reject (0x44)') |
        (packets_df['summary'] == 'NAS PDU session establishment request (0xc1)') |
        (packets_df['summary'] == 'NAS PDU session establishment accept (0xc2)') |
        (packets_df['summary_raw'].str.contains('HTTP/2'))
        ].copy()

    procedure_frames['AMF-UE-NGAP-ID'] = ''
    procedure_frames['RAN-UE-NGAP-ID'] = ''
    procedure_frames['HTTP_STREAM'] = ''
    procedure_frames['HTTP_PROCEDURE'] = ''
    procedure_frames['HTTP_TYPE'] = ''

    def get_id(regex, x, find_all=False):
        try:
            if not find_all:
                match = re.search(regex, x)
                if match is None:
                    return ''
                return match.group(1)
            else:
                match = list(re.finditer(regex, x))
                if len(match) == 0:
                    return ''
                matches = [e for e in match if e is not None]
                matches = [e.group(1) for e in matches]
                matches = '\n'.join(matches)
            return matches
        except:
            return ''

    procedure_frames['AMF-UE-NGAP-ID'] = procedure_frames['msg_description'].apply(
        lambda x: get_id(r"'AMF-UE-NGAP-ID: ([\d]+)'", x))
    procedure_frames['RAN-UE-NGAP-ID'] = procedure_frames['msg_description'].apply(
        lambda x: get_id(r"'RAN-UE-NGAP-ID: ([\d]+)'", x))
    procedure_frames['HTTP_STREAM'] = procedure_frames['msg_description'].apply(
        lambda x: get_id(r"HTTP/2 stream: ([\d]+)", x, find_all=True))
    procedure_frames['HTTP_PROCEDURE'] = procedure_frames['msg_description'].apply(
        lambda x: get_id(r":path: (.*)", x, find_all=True))
    procedure_frames['HTTP_TYPE'] = procedure_frames['summary_raw'].apply(
        lambda x: get_id(r"HTTP/2.*(req|rsp)", x))

    unique_ran_ids = procedure_frames['RAN-UE-NGAP-ID'].unique()

    logging.debug('Found RAN-UE-NGAP-IDs: {0}'.format(len(unique_ran_ids)))

    procedures = []
    ProcedureDescription = collections.namedtuple(
        'ProcedureDescription',
        'name RAN_UE_NGAP_ID length_ms start_frame end_frame start_timestamp end_timestamp start_datetime end_datetime')

    logging.debug('Parsing procedures based on RAN_UE_NGAP_ID')

    def row_to_id(_row, reverse=False, index_for_multi_messages=None):
        if not reverse:
            src = _row.ip_src
            dst = _row.ip_dst
        else:
            dst = _row.ip_src
            src = _row.ip_dst
        http_stream = _row.HTTP_STREAM
        if index_for_multi_messages is not None:
            try:
                http_stream = _row.HTTP_STREAM.split('\n')[index_for_multi_messages]
            except:
                logging.error('Could not extract HTTP_STREAM index {0} from row {1}', index_for_multi_messages, row)
                pass
        generated_key = '{0}-{1}-{2}'.format(
            src,
            dst,
            http_stream)
        return generated_key

    for ran_id in unique_ran_ids:
        current_reg_start = 0
        current_reg_start_frame = 0
        current_reg_start_datetime = ''
        current_pdu_session_establishment_start = 0
        current_pdu_session_establishment_start_frame = 0
        current_pdu_session_establishment_start_datetime = ''
        rows = procedure_frames[procedure_frames['RAN-UE-NGAP-ID'] == ran_id]
        current_proc_starts = {}

        # display(rows)
        for row in rows.itertuples():
            if row.summary == 'NAS Registration request (0x41)':
                current_reg_start = row.timestamp
                current_reg_start_frame = row.frame_number
                current_reg_start_datetime = row.datetime
            elif row.summary == 'NAS PDU session establishment request (0xc1)':
                current_pdu_session_establishment_start = row.timestamp
                current_pdu_session_establishment_start_frame = row.frame_number
                current_pdu_session_establishment_start_datetime = row.datetime
            elif row.HTTP_TYPE == 'req':
                # Check if this is a multi-messages HTTP/2
                for idx, summary in enumerate(row.summary.split('\n')):
                    proc_key = row_to_id(row, index_for_multi_messages=idx)
                    current_proc_starts[proc_key] = (row.timestamp, row.frame_number, row.datetime, summary)
                    logging.debug('PUSH: HTTP/2: Frame {0}; HEADER {1}; {2}; HTTP-STREAM {3}; {4}'.format(
                        row.frame_number,
                        idx,
                        summary,
                        ', '.join(row.HTTP_STREAM.split('\n')),
                        proc_key))
            elif row.summary == 'NAS Registration accept (0x42)':
                procedure_time = (row.timestamp - current_reg_start) * 1000
                procedures.append(
                    ProcedureDescription('NAS UE Registration - accept', ran_id,
                                         procedure_time,
                                         current_reg_start_frame,
                                         row.frame_number,
                                         current_reg_start, row.timestamp,
                                         current_reg_start_datetime, row.datetime))
            elif row.summary == 'NAS Registration reject (0x44)':
                procedure_time = (row.timestamp - current_reg_start) * 1000
                procedures.append(
                    ProcedureDescription('NAS UE Registration - reject', ran_id,
                                         procedure_time,
                                         current_reg_start_frame,
                                         row.frame_number,
                                         current_reg_start, row.timestamp,
                                         current_reg_start_datetime, row.datetime))
            elif row.summary == 'NAS PDU session establishment accept (0xc2)':
                procedure_time = (row.timestamp - current_pdu_session_establishment_start) * 1000
                procedures.append(ProcedureDescription(
                    'NAS PDU Session Establishment - accept', ran_id,
                    procedure_time,
                    current_pdu_session_establishment_start_frame,
                    row.frame_number,
                    current_pdu_session_establishment_start, row.timestamp,
                    current_pdu_session_establishment_start_datetime, row.datetime))
            elif row.summary == 'NAS PDU session establishment reject (0xc3)':
                procedure_time = (row.timestamp - current_pdu_session_establishment_start) * 1000
                procedures.append(ProcedureDescription(
                    'NAS PDU Session Establishment - reject', ran_id,
                    procedure_time,
                    current_pdu_session_establishment_start_frame,
                    row.frame_number,
                    current_pdu_session_establishment_start, row.timestamp,
                    current_pdu_session_establishment_start_datetime, row.datetime))
            elif row.HTTP_TYPE == 'rsp':
                key = row_to_id(row, reverse=True)
                if key in current_proc_starts:
                    logging.debug('POP: HTTP/2: Frame {0}; HTTP-STREAM {1}; {2}'.format(
                        row.frame_number,
                        row.HTTP_STREAM,
                        key))
                    start = current_proc_starts[key]
                    procedure_time = (row.timestamp - start[0]) * 1000
                    procedures.append(ProcedureDescription(
                        'HTTP ' + start[3], ran_id,
                        procedure_time,
                        start[1], row.frame_number,
                        start[0], row.timestamp,
                        start[2], row.datetime))
                    current_proc_starts.pop(key)
                else:
                    logging.debug('NO-POP: HTTP/2: Frame {0}; HTTP-STREAM {1}; {2}'.format(
                        row.frame_number,
                        row.HTTP_STREAM,
                        proc_key))

    procedure_df = pd.DataFrame(procedures, columns=['name', 'RAN_UE_NGAP_ID', 'length_ms', 'start_frame', 'end_frame',
                                                     'start_timestamp', 'end_timestamp',
                                                     'start_datetime', 'end_datetime'])

    return procedure_df, procedure_frames
