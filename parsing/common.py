import logging
import re
import xml
from enum import Enum
from typing import NamedTuple
from xml.etree import ElementTree as ET
from collections import Counter, namedtuple, defaultdict
from transitions import Machine, State, Transition
from copy import deepcopy


def xml2json(root: xml.etree.ElementTree.Element) -> dict:
    """
    Parse XML ElementTree to dictionary
    :param root: The element root to be parsed
    :return: A Dictionary containing the parsed element structure for which some attributes are shown.
    None if nothing was parsed
    """
    def recursiv(the_root: xml.etree.ElementTree.Element):
        # No need to do anything if the list is empty
        if the_root is None:
            return None
        out = {}
        children_list = list(the_root)
        number_of_children = len(children_list)
        child_name_counter = {}
        for child in children_list:
            child_name = child.attrib["name"]
            # logging.debug(f'Element name: {child_name}')
            # Avoid '' child name if possible
            if child_name == '' and 'show' in child.attrib:
                child_name = child.attrib['show']

            number_of_grandchildren = len(list(child))

            # In some cases, you can have repeated keys, e.g. several TACs, see #28
            original_child_name = child_name
            if child_name not in child_name_counter:
                child_name_counter[child_name] = 1
            else:
                child_name_counter[child_name] = child_name_counter[child_name] + 1
                child_name = '{0} ({1})'.format(child_name, child_name_counter[child_name])

            if number_of_grandchildren > 0:
                if child_name not in out:
                    out[child_name] = []
                child_to_traverse = child

                # Recursively call this function
                data_to_append = recursiv(child_to_traverse)

                # Make the JSON smaller by removing non-useful tags
                if (original_child_name == 'ngap.ProtocolIE_Field_element' or original_child_name == '') and (
                        number_of_children == 1):
                    return data_to_append

                # Reduce arrays of length 1 in dictionary
                for key, value in data_to_append.items():
                    if len(value) == 1:
                        data_to_append[key] = value[0]

                # Reduce dictionaries of length 1 with empty key
                if (len(data_to_append) == 1) and ('' in data_to_append):
                    data_to_append = data_to_append['']

                out[child_name].append(data_to_append)
            else:
                try:
                    if 'showname' in child.attrib:
                        field_content = child.attrib["showname"]
                    elif 'show' in child.attrib:
                        field_content = child.attrib["show"]
                    else:
                        field_content = ''

                    out[child_name] = field_content
                except:
                    logging.debug('ERROR: could not find "showname" attribute for following element')
                    child_str = ET.tostring(child)
                    logging.debug(child_str)
                    out[child_name] = 'ERROR'
        return out

    parsed_tree = recursiv(root)
    return parsed_tree


class PacketDescription(NamedTuple):
    """Describes a packet for the PlantUML visualization"""
    ip_src: str
    ip_dst: str
    port_src: str
    port_dst: str
    transport_protocol: str
    frame_number: str
    protocols_str: str
    msg_description: str
    timestamp: float
    timestamp_offsett: float

CounterDescription = namedtuple('CounterDescription',
                                'counter_name timestamp frame date_time')

ProcedureDescription = namedtuple(
        'ProcedureDescription',
        'key procedure length_ms start_frame end_frame start_timestamp end_timestamp start_datetime end_datetime')

class PacketType(Enum):
    """Describes Packet types"""
    UNKNOWN = 0
    IPv4 = 1
    IPv6 = 2
    CUSTOM = 3

    
class ProcedureMeasurement(Machine):
    ''' Base class to keep procedure measurement
        state transitions based on received messages
    '''
    def __init__(self, procedure_name=None, 
                 states=None, transitions=None, initial_state=None):
        ''' class init '''
        Machine.__init__(self)
        self.initialize_state_machine(states, transitions)
        self.procedure_name = procedure_name
        self.reset_measurement()
        self.procedure_counters = defaultdict(list)
        if initial_state:
            self.set_state(initial_state)        

    def initialize_state_machine(self, states, transitions):
        if states and transitions:
            self.add_states(states, ignore_invalid_triggers=True)
            self.add_transitions(transitions)
  
    def reset_measurement(self, initial_state=None):
        self.start_message = None
        self.success_message = None
        self.failed_message = None
        self.outcome = None
        self.success = None
        if initial_state:
            self.set_state(initial_state)
        
    def start_procedure_measurement(self, **kwargs):
#        self.reset_measurement()
        self.start_message = CounterDescription(counter_name=kwargs['counter_name'],
                                                timestamp=kwargs['timestamp'],
                                                frame=kwargs['frame'],
                                                date_time=kwargs['date_time'],
                                                )
    
    def end_procedure_measurement(self, append_measurement=True, **kwargs):
        self.outcome = CounterDescription(counter_name=kwargs['counter_name'],
                                            timestamp=kwargs['timestamp'],
                                            frame=kwargs['frame'],
                                            date_time=kwargs['date_time'],
                                            )
        self.success = True
        if 'fail' in kwargs['counter_name'] or 'reject' in kwargs['counter_name']:
            self.success = False
        
        if append_measurement:
            self.procedure_counters[kwargs['counter_name']].append(self.get_measurement())
        
    def is_measurement_finished(self):
        return bool(self.outcome)
    
    def get_measurement(self):
        procedure_time = (self.outcome.timestamp - self.start_message.timestamp) * 1000
        return ProcedureDescription(key=None, 
                                    procedure=self.procedure_name, 
                                    length_ms=procedure_time, 
                                    start_frame=self.start_message.frame, 
                                    end_frame=self.outcome.frame, 
                                    start_timestamp=self.start_message.timestamp, 
                                    end_timestamp=self.outcome.timestamp,
                                    start_datetime=self.start_message.date_time, 
                                    end_datetime=self.outcome.date_time)
    
    def set_procedure_name(self, newname):
        self.procedure_name = newname
        
    def check_and_trigger(self, row_summary, **kwargs):
        for current_valid_trigger in self.get_triggers(self.state):
            if current_valid_trigger in row_summary:
                counter_name = current_valid_trigger
                if 'counter_name' in kwargs.keys():
                    self.trigger(current_valid_trigger, **kwargs)
                else:
                    self.trigger(current_valid_trigger, counter_name=counter_name, **kwargs)
                break

    def get_all_counters(self):
        return self.procedure_counters


