# -*- coding: utf-8 -*-
"""
Created on Wed Jun  4 06:37:07 2025

@author: omar_
"""
import pandas as pd

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
FEATURE_NAMES = ['tps']

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
    return endpoints_df.drop_duplicates().shape[0]


def create_protocol_features(packets_df, protocol, total_duration):
    ''' Calculates features for each protocol '''
    if total_duration == 0:
        return None
    protocol_packets = packets_df[packets_df['protocol'].str.contains(protocol)]
    # Feature 1 - TPS
    transactions_per_second = len(protocol_packets)/total_duration
    protocol_feature_names = [f'{protocol}_{feature}' for feature in FEATURE_NAMES]
    feature_values = [transactions_per_second]
    return dict(zip(protocol_feature_names, feature_values))

    
def create_feature_vector(packets_df):
    feature_vector = dict()
    total_duration = packets_df['timestamp'].max() - packets_df['timestamp'].min()
    for protocol in PROTOCOLS:
        feature_vector.update(create_protocol_features(packets_df, protocol, total_duration))
    feature_vector.update({"total_duration":total_duration})
    feature_vector.update({"total_unique_endpoints": get_unique_endpoints(packets_df)})
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
