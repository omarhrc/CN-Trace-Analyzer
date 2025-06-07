import logging
import re
import xml
from enum import Enum
from typing import NamedTuple
from xml.etree import ElementTree as ET
from collections import Counter, namedtuple, defaultdict
from transitions import Machine, State, Transition
from copy import deepcopy

from parsing.common import ProcedureMeasurement

class EsmMeasurement(ProcedureMeasurement):
    ''' Base class for ESM measurements'''    
    def __init__(self, procedure_name=None):
        ProcedureMeasurement.__init__(self,
                                states=self.esm_states,
                                transitions=self.esm_transitions,
                                procedure_name=procedure_name)

    
class EsmInitialPdnMeas(EsmMeasurement):
    ''' Measurement for initial PDN procedure'''
    esm_states = ['esm_pdn_initial', 'waiting', 'esm_pdn_fail', 'default_bearer_initial']

    esm_transitions = [
        ['PDN connectivity request (0xd0)', 'esm_pdn_initial', 'waiting', None, None, None, 'start_procedure_measurement'],
        ['PDN connectivity reject (0xd1)', 'waiting', 'esm_pdn_fail', None, None, None, 'end_procedure_measurement'],
        ['Activate default EPS bearer context request (0xc1)', 'waiting', 'default_bearer_initial', None, None, None, 'end_procedure_measurement'],
    ]      
              
    def __init__(self, procedure_name=None):
        ProcedureMeasurement.__init__(self,
                                  states=self.esm_states,
                                  transitions=self.esm_transitions, initial_state='esm_pdn_initial',
                                  procedure_name=procedure_name)

            
class EsmDefaultBearerActivationMeas(EsmMeasurement):
    ''' Measurement for default bearer activation'''
    esm_states = ['default_bearer_initial', 'waiting',
                  'default_bearer_established', 'default_bearer_reject']

    esm_transitions = [
        ['Activate default EPS bearer context request (0xc1)', 'default_bearer_initial', 'waiting', None, None, None, 'start_procedure_measurement'],
        ['Activate default EPS bearer context accept (0xc2)', 'waiting', 'default_bearer_established', None, None, None, 'end_procedure_measurement'],
        ['Activate default EPS bearer context reject (0xc3)', 'waiting', 'default_bearer_reject', None, None, None, 'end_procedure_measurement'],
    ]                    
    
    def __init__(self, procedure_name=None):
        ProcedureMeasurement.__init__(self,
                                  states=self.esm_states,
                                  transitions=self.esm_transitions, initial_state='default_bearer_initial',
                                  procedure_name=procedure_name)

class EsmDedicatedBearerActivationMeas(EsmMeasurement):
    ''' Measurement for dedicated bearer activation'''
    esm_states = ['default_bearer_established', 'waiting',
                  'dedicated_bearer_established', 'dedicated_bearer_reject']

    esm_transitions = [
        ['Activate dedicated EPS bearer context request (0xc5)', 'default_bearer_established', 'waiting', None, None, None, 'start_procedure_measurement'],
        ['Activate dedicated EPS bearer context accept (0xc6)', 'waiting', 'dedicated_bearer_established', None, None, None, 'end_procedure_measurement'],
        ['Activate dedicated EPS bearer context reject (0xc7)', 'waiting', 'dedicated_bearer_reject', None, None, None, 'end_procedure_measurement'],
    ]                    

    def __init__(self, procedure_name=None):
        ProcedureMeasurement.__init__(self,
                                  states=self.esm_states,
                                  transitions=self.esm_transitions, initial_state='default_bearer_established',
                                  procedure_name=procedure_name)


class EsmDedicatedBearerDectivationMeas(EsmMeasurement):
    ''' Measurement for dedicated bearer deactivation'''
    esm_states = ['dedicated_bearer_established', 'waiting',
                  'dedicated_bearer_deactivated', 'dedicated_deactivation_reject']

    esm_transitions = [
        ['Deactivate EPS bearer context request (0xcd)', 'dedicated_bearer_established', 'waiting', None, None, None, 'start_procedure_measurement'],
        ['Dectivate EPS bearer context accept (0xce)', 'waiting', 'dedicated_bearer_deactivated', None, None, None, 'end_procedure_measurement'],
        ['Deativate EPS bearer context reject (0xcf)', 'waiting', 'dedicated_deactivation_reject', None, None, None, 'end_procedure_measurement']
        ]
 
    def __init__(self, procedure_name=None):
        ProcedureMeasurement.__init__(self,
                                  states=self.esm_states,
                                  transitions=self.esm_transitions, initial_state='dedicated_bearer_established',
                                  procedure_name=procedure_name)


class ESMProcedureManager():
    ''' Manages esm sessions  and processes all messages'''
    
    def __init__(self):
         self.sessions = dict()
         self.nas_lte_sm_seq_regex = re.compile(r"nas-eps.seq_no:.*Sequence number: (.*)'")
         self.nas_lte_sm_msg_regex = re.compile(r"nas-eps\..*_type:.*NAS EPS session management messages: (.*)'")
         self.procedure_counters = defaultdict(list)

     
    def process_esm_messages(self, msg_description, row_summary, **kwargs):
        ''' Loops over current message '''
        before_index = 0
        for sm_msg_match in re.finditer(self.nas_lte_sm_msg_regex, msg_description):
            finished_measurements = list()
            # find session and message type
            before_sm_msg = msg_description[before_index:sm_msg_match.start()]
            sm_msg = sm_msg_match.group(1)
            sm_seq_match = re.search(self.nas_lte_sm_seq_regex, before_sm_msg)
            before_index = sm_msg_match.end()
            if sm_seq_match is None:
                session = "dummy" #Dummy session value
            else:
                session = sm_seq_match.group(1) 

            # Dispatch message to existing or new measurement object
            
            # Keep processing
            msg_prefix = ' '.join(sm_msg.split()[0:2]) # Retrieves first two words
            measurement_to_update = None
            try:
                measurement_to_update = self.sessions[session]
                if (measurement_to_update.procedure_name == 'PDN connectivity'):
                    measurement_to_update.check_and_trigger(sm_msg, **kwargs)
                    if measurement_to_update.is_measurement_finished():
                        for procedure, description_list in measurement_to_update.get_all_counters().items():
                            self.procedure_counters[procedure].extend(description_list)
                        self.sessions.pop(session)
                    measurement_to_update = self.sessions[session] =  EsmDefaultBearerActivationMeas('Activate default bearer')
            except KeyError:
                # Create corresponding object
                match msg_prefix:
                    case 'PDN connectivity':    # This case should always come here!
                       self.sessions[session] =  EsmInitialPdnMeas('PDN connectivity')
                       measurement_to_update = self.sessions[session]
                    case 'Activate default':                    
                        # Handles standing PDN connectivity requests
                        for standing_session, measurement in self.sessions.items():
                            if measurement.procedure_name == 'PDN connectivity':
                                measurement.check_and_trigger(sm_msg, **kwargs)
                                if measurement.is_measurement_finished():
                                    finished_measurements.append((standing_session, measurement))
                        self.sessions[session] =  EsmDefaultBearerActivationMeas('Activate default bearer')
                        measurement_to_update = self.sessions[session]
                    case 'Activate dedicated':
                        pass    # TO DO: Not reliable yet
#                        self.sessions[session] =  EsmDedicatedBearerActivationMeas('Activate dedicated bearer')
                    case 'Deactivate EPS':
                        pass    # TO DO: Not reliable yet
#                        self.sessions[session] =  EsmDedicatedBearerDectivationMeas('Deactivate EPS bearer')
                    case _:
                        print(f"ESM message not supported: {sm_msg}")
                        continue
            if measurement_to_update:
                measurement_to_update.check_and_trigger(sm_msg, **kwargs)
                if measurement_to_update.is_measurement_finished():
                    finished_measurements.append((session, measurement_to_update))

            for session, measurement in finished_measurements:
                for procedure, description_list in measurement.get_all_counters().items():
                    self.procedure_counters[procedure].extend(description_list)
                self.sessions.pop(session)


class EmmMeasurement(ProcedureMeasurement):
    ''' Base class for EMM measurements'''

    def __init__(self, procedure_name=None):
        ProcedureMeasurement.__init__(self,
                                      states=self.emm_states,
                                      transitions=self.emm_transitions,
                                      procedure_name=procedure_name,
                                      initial_state='emm_deregistered_initial')

class EmmAttachMeas(EmmMeasurement):
    ''' Measurement for EMM Attach procedure'''
    emm_states = ['emm_deregistered_initial', 'waiting', 'emm_registered', 'emm_deregistered_failed']

    emm_transitions = [
        ['Attach request (0x41)', 'emm_deregistered_initial', 'waiting',  None, None, None, 'start_procedure_measurement'],
        ['Attach accept (0x42)', 'waiting', 'emm_registered',  None, None, None, 'end_procedure_measurement'],
        ['Attach reject (0x44)', 'waiting', 'emm_deregistered_failed', None, None, None, 'end_procedure_measurement']
    ]

class EMMProcedureManager():
    ''' Manages emm counters'''

    def __init__(self):
        self.attach_measurement = EmmAttachMeas(procedure_name='Attach procedure')
        self.attach_measurement.reset_measurement('emm_deregistered_initial')
        self.procedure_counters = defaultdict(list)

    def process_emm_messages(self, row_summary, **kwargs):
        self.attach_measurement.check_and_trigger(row_summary,
                          timestamp=kwargs["timestamp"],
                          frame=kwargs["frame"], date_time=kwargs["date_time"])

        if self.attach_measurement.is_measurement_finished():
            for procedure, description_list in self.attach_measurement.get_all_counters().items():
                self.procedure_counters[procedure].extend(description_list)
            self.attach_measurement.reset_measurement('emm_deregistered_initial')
