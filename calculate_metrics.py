# -*- coding: utf-8 -*-
"""
Created on Wed Jun  4 06:37:07 2025

@author: omar_
"""
import pandas as pd

from parsing import json_parser
import trace_visualizer
import logging
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
import logging
import os.path
import platform
import sys

import parsing.http
from utils.files import add_folder_to_file_list
from utils.plantuml import output_files_as_file, plant_uml_jar
from utils.wireshark import import_pdml, call_wireshark

from parsing import nas_lte
from parsing.common import ProcedureCounter, ESMProcedureCounter, ESMProcedureManager

application_logger = logging.getLogger()
application_logger.setLevel(logging.DEBUG)

debug = False

PROTOCOLS = ['NGAP', 'HTTP/2', 'PFCP', 'GTPv2', 'Diameter', 'RADIUS', "GTP'", 'S1AP', 'SIP']


def create_feature_vector(packets_df, logging_level=logging.INFO):
    current_verbosity_level = application_logger.level
    application_logger.setLevel(logging_level)
    
    for protocol in PROTOCOLS:
        protocol_packets = packets_df[packets_df['protocol'].str.contains(protocol)]
        create_protocol_features(protocol_packets)
 
#    logging.debug('Parsed {0} procedures'.format(len(procedure_df)))
    trace_visualizer.application_logger.setLevel(current_verbosity_level)

def create_protocol_features(protocol_df, protocol, logging_level=logging.INFO):
    current_verbosity_level = application_logger.level
    application_logger.setLevel(logging_level)
    
 
#    logging.debug('Parsed {0} procedures'.format(len(procedure_df)))
    trace_visualizer.application_logger.setLevel(current_verbosity_level)        


def calculate_procedure_length_eps(packets_df, logging_level=logging.INFO):
    current_verbosity_level = trace_visualizer.application_logger.level
    trace_visualizer.application_logger.setLevel(logging_level)

    
    procedure_frames = pd.DataFrame()
    for nas_lte_msg in nas_lte.NAS_LTE_MESSAGES:
#        procedure_to_add_df = packets_df[packets_df['summary'].str.contains(nas_lte_msg, 
#                                                                         regex=False)]
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
#####################

    emm_states = ['emm_deregistered_initial', 'waiting', 'emm_registered', 'emm_deregistered_failed']
    
    emm_attach_counter = ProcedureCounter('Attach')
    emm_attach_counter.add_states(emm_states, ignore_invalid_triggers=True)
    emm_attach_counter.add_transition('Attach request (0x41)', 'emm_deregistered_initial', 'waiting', after='start_procedure_measurement')
    emm_attach_counter.add_transition('Attach accept (0x42)', 'waiting', 'emm_registered', after='end_procedure_measurement')
    emm_attach_counter.add_transition('Attach reject (0x44)', 'waiting', 'emm_deregistered_failed', after='end_procedure_measurement')
    emm_attach_counter.reset_measurement('emm_deregistered_initial')

    esm_states = ['esm_pdn_initial', 'waiting', 'default_bearer_initial', 'dedicated_bearer_initial',
                  'accept', 'reject']
    
    esm_pdn_connectivity = ESMProcedureCounter()
    esm_pdn_connectivity.reset_measurement('esm_pdn_initial')
    
    
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
#########
            emm_attach_counter.check_and_trigger(row.summary,                                                 
                                                 timestamp=row.timestamp, 
                                                 frame=row.frame_number, date_time=row.datetime)
            emm_attach_counters = emm_attach_counter.get_all_counters()
#            if emm_attach_counter.is_measurement_finished():
#                emm_attach_procedure_time = emm_attach_counter.get_measurement()
#                emm_attach_counter.reset_measurement('emm_deregistered_initial')
#########
            esm_pdn_connectivity.check_and_trigger(row.summary,                                                 
                                                 timestamp=row.timestamp, 
                                                 frame=row.frame_number, date_time=row.datetime)
            
            esm_pdn_connectivity_counters = esm_pdn_connectivity.get_all_counters()
                # measurement not reset because the counter keeps state
            
####        

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

    procedure_df = pd.DataFrame(procedures, columns=['name', 'ENB_UE_S1AP_ID', 'length_ms', 'start_frame', 'end_frame',
                                                     'start_timestamp', 'end_timestamp',
                                                     'start_datetime', 'end_datetime'])

    logging.debug('Parsed {0} procedures'.format(len(procedure_df)))
    trace_visualizer.application_logger.setLevel(current_verbosity_level)
    return procedure_df, procedure_frames
