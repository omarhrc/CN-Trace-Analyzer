# -*- coding: utf-8 -*-
"""
Created on Wed Jun  4 06:37:07 2025

@author: omar_
"""
import pandas as pd

from parsing import json_parser
import trace_visualizer
import logging
import os
import os.path
import plotly.graph_objects as go
import bz2
import pickle
import xml.etree.ElementTree as ET
from lxml import etree
import collections
import numpy as np
import re

import argparse
import platform
import sys

import glob

import parsing.http
from utils.files import add_folder_to_file_list
from utils.plantuml import output_files_as_file, plant_uml_jar
from utils.wireshark import import_pdml, call_wireshark
from utils.wireshark import import_pcap_as_dataframe

from parsing import nas_lte
from parsing.common import ProcedureMeasurement
from parsing.s1ap_measurements import ESMProcedureManager, EMMProcedureManager

application_logger = logging.getLogger()
application_logger.setLevel(logging.DEBUG)

debug = False

PROTOCOLS = ['NGAP', 'HTTP/2', 'PFCP', 'GTP', 'Diameter', 'S1AP', 'SIP', 'SDP']


def create_protocol_features(packets_df, protocol, total_duration):
    ''' Calculates features for each protocol '''
    if total_duration == 0:
        return None
    protocol_packets = packets_df[packets_df['protocol'].str.contains(protocol)]
    # Feature 1 - TPS
    transactions_per_second = len(protocol_packets)/total_duration
    feature_names = ['tps']
    protocol_feature_names = [f'{protocol}_{feature}' for feature in feature_names]
    feature_values = [transactions_per_second]
    return dict(zip(protocol_feature_names, feature_values))

    
def create_feature_vector(packets_df):
    feature_vector = dict()
    total_duration = packets_df['timestamp'].max() - packets_df['timestamp'].min()
    for protocol in PROTOCOLS:
        feature_vector.update(create_protocol_features(packets_df, protocol, total_duration))
    feature_vector.update({"total_duration":total_duration})
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
    current_verbosity_level = trace_visualizer.application_logger.level
    trace_visualizer.application_logger.setLevel(logging_level)
    
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

    procedures = []
    ProcedureDescription = collections.namedtuple(
        'ProcedureDescription',
        'name ENB_UE_S1AP_ID length_ms start_frame end_frame start_timestamp end_timestamp start_datetime end_datetime')

    logging.debug('Parsing procedures based on ENB_UE_S1AP_ID')

    emm_manager = EMMProcedureManager()
    esm_manager = ESMProcedureManager()

####################


    for ran_id in unique_ran_ids:
        current_reg_start = 0
        current_reg_start_frame = 0
        current_reg_start_datetime = ''
        current_pdu_session_establishment_start = 0
        current_pdu_session_establishment_start_frame = 0
        current_pdu_session_establishment_start_datetime = ''
        
        current_eps_dedicated_bearer_establishment_start = 0
        current_eps_dedicated_bearer_establishment_start_frame = 0
        current_eps_dedicated_bearer_establishment_start_datetime = ''
        rows = procedure_frames[procedure_frames['ENB-UE-S1AP-ID'] == ran_id]


        # display(rows)
        for row in rows.itertuples():
            emm_manager.process_emm_messages(row.summary,
                                                 timestamp=row.timestamp,
                                                 frame=row.frame_number, date_time=row.datetime)
            esm_manager.process_esm_messages(row.msg_description, row.msg_description,                                                 
                                                 timestamp=row.timestamp, 
                                                 frame=row.frame_number, date_time=row.datetime)
####
            # Mobility Management
            if 'Attach request (0x41)' in row.summary:
                current_reg_start = row.timestamp
                current_reg_start_frame = row.frame_number
                current_reg_start_datetime = row.datetime
            elif 'Attach accept (0x42)'in row.summary:
                procedure_time = (row.timestamp - current_reg_start) * 1000
                procedures.append(
                    ProcedureDescription('NAS UE Attach - accept', ran_id,
                                         procedure_time,
                                         current_reg_start_frame,
                                         row.frame_number,
                                         current_reg_start, row.timestamp,
                                         current_reg_start_datetime, row.datetime))
            elif 'Attach reject (0x44)'in row.summary:
                procedure_time = (row.timestamp - current_reg_start) * 1000
                procedures.append(
                    ProcedureDescription('NAS UE Attach - reject', ran_id,
                                         procedure_time,
                                         current_reg_start_frame,
                                         row.frame_number,
                                         current_reg_start, row.timestamp,
                                         current_reg_start_datetime, row.datetime))
            # Session Management    
            if 'PDN connectivity request (0xd0)'in row.summary:
                current_pdu_session_establishment_start = row.timestamp
                current_pdu_session_establishment_start_frame = row.frame_number
                current_pdu_session_establishment_start_datetime = row.datetime
            elif 'Activate default EPS bearer context request (0xc1)'in row.summary:
                # PDN connectivity accepted. Finish measurement
                procedure_time = (row.timestamp - current_pdu_session_establishment_start) * 1000
                procedures.append(ProcedureDescription(
                    'PDN connectivity - accept', ran_id,
                    procedure_time,
                    current_pdu_session_establishment_start_frame,
                    row.frame_number,
                    current_pdu_session_establishment_start, row.timestamp,
                    current_pdu_session_establishment_start_datetime, row.datetime))
                # Start default EPS bearer measurement                
                current_eps_default_bearer_establishment_start = row.timestamp
                current_eps_default_bearer_establishment_start_frame = row.frame_number
                current_eps_default_bearer_establishment_start_datetime = row.datetime
            elif 'Activate dedicated EPS bearer context request (0xc5)'in row.summary:
                current_eps_dedicated_bearer_establishment_start = row.timestamp
                current_eps_dedicated_bearer_establishment_start_frame = row.frame_number
                current_eps_dedicated_bearer_establishment_start_datetime = row.datetime
            if 'PDN connectivity reject (0xd1)'in row.summary:
                procedure_time = (row.timestamp - current_pdu_session_establishment_start) * 1000
                procedures.append(ProcedureDescription(
                    'PDN connectivity - reject', ran_id,
                    procedure_time,
                    current_pdu_session_establishment_start_frame,
                    row.frame_number,
                    current_pdu_session_establishment_start, row.timestamp,
                    current_pdu_session_establishment_start_datetime, row.datetime))
            elif 'Activate default EPS bearer context accept (0xc2)'in row.summary:
                procedure_time = (row.timestamp - current_eps_default_bearer_establishment_start) * 1000
                procedures.append(ProcedureDescription(
                    'Activate default EPS bearer context - accept', ran_id,
                    procedure_time,
                    current_eps_default_bearer_establishment_start_frame,
                    row.frame_number,
                    current_eps_default_bearer_establishment_start, row.timestamp,
                    current_eps_default_bearer_establishment_start_datetime, row.datetime))
            elif 'Activate default EPS bearer context reject (0xc3)'in row.summary:
                procedure_time = (row.timestamp - current_pdu_session_establishment_start) * 1000
                procedures.append(ProcedureDescription(
                    'Activate default EPS bearer context - reject', ran_id,
                    procedure_time,
                    current_pdu_session_establishment_start_frame,
                    row.frame_number,
                    current_pdu_session_establishment_start, row.timestamp,
                    current_pdu_session_establishment_start_datetime, row.datetime))
            elif 'Activate dedicated EPS bearer context accept (0xc6)'in row.summary:
                procedure_time = (row.timestamp - current_eps_dedicated_bearer_establishment_start) * 1000
                procedures.append(ProcedureDescription(
                    'Activate dedicated EPS bearer context - accept', ran_id,
                    procedure_time,
                    current_eps_dedicated_bearer_establishment_start_frame,
                    row.frame_number,
                    current_eps_dedicated_bearer_establishment_start, row.timestamp,
                    current_eps_dedicated_bearer_establishment_start_datetime, row.datetime))
            elif 'Activate dedicated EPS bearer context reject (0xc7)'in row.summary:
                procedure_time = (row.timestamp - current_eps_dedicated_bearer_establishment_start) * 1000
                procedures.append(ProcedureDescription(
                    'Activate dedicated EPS bearer context - reject', ran_id,
                    procedure_time,
                    current_eps_dedicated_bearer_establishment_start_frame,
                    row.frame_number,
                    current_eps_dedicated_bearer_establishment_start, row.timestamp,
                    current_eps_dedicated_bearer_establishment_start_datetime, row.datetime))

    output_columns = ['ENB_UE_S1AP_ID', 'name', 'length_ms', 'start_frame', 'end_frame',
               'start_timestamp', 'end_timestamp',
               'start_datetime', 'end_datetime']

    procedure_df = pd.DataFrame(columns=output_columns)
    for description_list in emm_manager.procedure_counters.values():
        procedure_df = pd.concat([procedure_df, pd.DataFrame(description_list, columns=output_columns)],
                                 ignore_index=True)
    for description_list in esm_manager.procedure_counters.values():
        procedure_df = pd.concat([procedure_df, pd.DataFrame(description_list, columns=output_columns)],
                                 ignore_index=True)

    logging.debug('Parsed {0} procedures'.format(len(procedure_df)))
    trace_visualizer.application_logger.setLevel(current_verbosity_level)
    return procedure_df, procedure_frames
