# sip_measurements.py

import logging
import re
from datetime import datetime
from enum import Enum
from collections import defaultdict, namedtuple
import pandas as pd  # Added pandas for DataFrame output
from parsing.common import ProcedureDescription, ProcedureMeasurement


class SipMessageType(Enum):
    """Enumerates the types of SIP messages for processing."""
    INVITE = "INVITE"
    PROVISIONAL_RESPONSE = "1xx"
    SUCCESS_RESPONSE = "2xx"
    ACK = "ACK"
    BYE = "BYE"
    CANCEL = "CANCEL"
    REGISTER = "REGISTER"
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"
    GLOBAL_FAILURE = "6xx"
    REQUEST_TIMEOUT = "408"
    SERVER_TIMEOUT = "504"
    UPDATE = "UPDATE"
    UNKNOWN = "UNKNOWN"


class SIPCallSetupMeasurement(ProcedureMeasurement):
    """
    Measures SIP Call Setup Time (Time to Ringing) using a state machine that tracks a specific CSeq transaction.
    The measurement is from the first INVITE to the first 180 Ringing response.
    """
    states = ['INITIAL', 'INVITE_SENT', 'PROCEEDING', 'WAITING_FOR_ACK', 'SUCCESS', 'FAILED']
    transitions = [
        {'trigger': 'event_invite', 'source': 'INITIAL', 'dest': 'INVITE_SENT', 'after': 'start_procedure_measurement'},
        # A new event to specifically capture the 180 Ringing time without ending the state machine
        {'trigger': 'event_ringing', 'source': ['INVITE_SENT', 'PROCEEDING'], 'dest': 'PROCEEDING',
         'after': 'capture_ringing_time'},
        {'trigger': 'event_provisional', 'source': ['INVITE_SENT', 'PROCEEDING'], 'dest': 'PROCEEDING'},
        {'trigger': 'event_success_resp', 'source': ['INVITE_SENT', 'PROCEEDING'], 'dest': 'WAITING_FOR_ACK'},
        {'trigger': 'event_ack', 'source': 'WAITING_FOR_ACK', 'dest': 'SUCCESS', 'after': 'end_procedure_measurement'},
        {'trigger': 'event_failure', 'source': '*', 'dest': 'FAILED', 'after': 'end_procedure_measurement'},
    ]

    def __init__(self, call_id: str, is_caller: bool, procedure_name="SIP Time to Ringing (INVITE to 180)"):
        self.call_id = call_id
        self.is_caller = is_caller
        super().__init__(procedure_name=procedure_name, states=self.states, transitions=self.transitions,
                         initial_state='INITIAL')
        self.reset_measurement(initial_state='INITIAL')

    def reset_measurement(self, initial_state=None):
        self.state = initial_state or 'INITIAL'
        self.start_message = None
        self.ringing_message = None  # To store the time of the 180 Ringing
        self.outcome = None
        self.termination_reason = None
        self.success = False
        self.monitored_cseq = None
        self.monitored_method = None

    def start_procedure_measurement(self, **kwargs):
        self.start_message = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])

    def capture_ringing_time(self, **kwargs):
        """Captures the timestamp of the first 180 Ringing response."""
        if self.ringing_message is None:  # Only capture the first one
            self.ringing_message = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])
            logging.debug(f"[{self.call_id}] Captured ringing time at {kwargs['timestamp']}")

    def end_procedure_measurement(self, **kwargs):
        """This method is called at the final end of the call (ACK or Failure) to determine overall success."""
        self.outcome = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])
        self.termination_reason = kwargs.get('counter_name')
        self.success = self.state == 'SUCCESS'
        logging.debug(f"[{self.call_id}] Call transaction finished in state {self.state}. Success: {self.success}")

    def is_measurement_finished(self):
        # The overall transaction is finished only on a final success or failure.
        return self.outcome is not None

    def get_measurement(self):
        """
        Generates the measurement data. The procedure time is now calculated
        from INVITE to 180 Ringing. Returns None if 180 was never received.
        """
        if not self.ringing_message or not self.start_message:
            return None  # No measurement if we never got a 180 ringing.

        start_ts, start_frame, start_dt = self.start_message
        ring_ts, ring_frame, ring_dt = self.ringing_message
        procedure_time = (ring_ts - start_ts) * 1000

        return ProcedureDescription(key=None, procedure=self.procedure_name, length_ms=procedure_time,
                                    start_frame=start_frame, end_frame=ring_frame,
                                    start_timestamp=start_ts, end_timestamp=ring_ts,
                                    start_datetime=start_dt, end_datetime=ring_dt)

    def get_valid_sources_for_trigger(self, trigger_name: str) -> list:
        valid_sources = []
        for transition in self.transitions:
            if transition['trigger'] == trigger_name:
                source = transition['source']
                if source == '*':
                    return self.states
                if isinstance(source, list):
                    valid_sources.extend(source)
                else:
                    valid_sources.append(source)
        return valid_sources

    def process_sip_message(self, message_type: SipMessageType, sip_response_code: int = None, cseq_number: int = None,
                            cseq_method: str = None, **kwargs):
        if message_type == SipMessageType.INVITE and self.state == 'INITIAL' and self.is_caller:
            self.monitored_cseq = cseq_number
            self.monitored_method = cseq_method.upper() if cseq_method else None
        elif self.monitored_cseq is not None:
            is_response = sip_response_code is not None
            if is_response or (message_type == SipMessageType.CANCEL and self.is_caller):
                if cseq_number != self.monitored_cseq or (cseq_method and cseq_method.upper() != self.monitored_method):
                    return

        event, counter_name = self._get_event_for_message(message_type, sip_response_code)
        if event and self.state in self.get_valid_sources_for_trigger(event):
            self.trigger(event, counter_name=counter_name, **kwargs)

    def _get_event_for_message(self, msg_type: SipMessageType, code: int = None) -> tuple:
        if self.is_caller:
            if msg_type == SipMessageType.INVITE: return 'event_invite', "INVITE Request"
            if msg_type == SipMessageType.ACK: return 'event_ack', "ACK Request"
            if msg_type == SipMessageType.CANCEL: return 'event_failure', "CANCEL Request"

        # Special handling for 180 Ringing to trigger the time capture
        if msg_type == SipMessageType.PROVISIONAL_RESPONSE:
            if code == 180:
                return 'event_ringing', "180 Ringing"
            return 'event_provisional', f"1xx Response ({code})"

        if msg_type == SipMessageType.SUCCESS_RESPONSE: return 'event_success_resp', f"2xx Response ({code})"

        error_map = {SipMessageType.CLIENT_ERROR: f"4xx Client Error ({code})",
                     SipMessageType.SERVER_ERROR: f"5xx Server Error ({code})",
                     SipMessageType.GLOBAL_FAILURE: f"6xx Global Failure ({code})",
                     SipMessageType.REQUEST_TIMEOUT: "408 Request Timeout",
                     SipMessageType.SERVER_TIMEOUT: "504 Server Timeout",
                     SipMessageType.BYE: "BYE Received (During Setup)"}
        if msg_type in error_map and self.state not in ['SUCCESS', 'FAILED']:
            return 'event_failure', error_map[msg_type]

        return None, None


class SIPRegistrationSuccessRateMeasurement:
    """A simple accumulator for SIP registration success and failure statistics."""

    def __init__(self, name="SIP Registration Success Rate"):
        self.name = name
        self.reset()

    def record_registration_attempt(self): self.total_registrations_attempted += 1

    def record_registration_success(self): self.total_registrations_successful += 1

    def record_registration_failure(self, reason: str):
        self.total_registrations_failed += 1
        self.failure_reasons[reason] += 1

    def get_success_rate(self) -> float:
        if not self.total_registrations_attempted: return 0.0
        return (self.total_registrations_successful / self.total_registrations_attempted) * 100

    def get_statistics(self) -> dict:
        return {"Total Registrations Attempted": self.total_registrations_attempted,
                "Total Registrations Successful": self.total_registrations_successful,
                "Total Registrations Failed": self.total_registrations_failed,
                "Success Rate (%)": f"{self.get_success_rate():.2f}",
                "Failure Reasons": dict(self.failure_reasons)}

    def reset(self):
        self.total_registrations_attempted = 0
        self.total_registrations_successful = 0
        self.total_registrations_failed = 0
        self.failure_reasons = defaultdict(int)


class SIPRegistrationMeasurement(ProcedureMeasurement):
    """Measures SIP Registration Time using a state machine."""
    states = ['INITIAL', 'REGISTER_SENT', 'SUCCESS', 'FAILED']
    transitions = [
        {'trigger': 'event_register', 'source': 'INITIAL', 'dest': 'REGISTER_SENT',
         'after': 'start_procedure_measurement'},
        {'trigger': 'event_success_resp', 'source': 'REGISTER_SENT', 'dest': 'SUCCESS',
         'after': 'end_procedure_measurement'},
        {'trigger': 'event_failure', 'source': 'REGISTER_SENT', 'dest': 'FAILED', 'after': 'end_procedure_measurement'},
    ]

    def __init__(self, call_id: str, cseq: int, is_caller: bool):
        self.call_id = call_id
        self.is_caller = is_caller
        super().__init__(procedure_name="SIP Registration", states=self.states, transitions=self.transitions,
                         initial_state='INITIAL')
        self.reset_measurement(initial_state='INITIAL')
        self.monitored_cseq = cseq
        self.monitored_method = "REGISTER"

    def reset_measurement(self, initial_state=None):
        self.state = initial_state or 'INITIAL'
        self.start_message = None;
        self.outcome = None;
        self.termination_reason = None;
        self.success = False

    def start_procedure_measurement(self, **kwargs):
        self.start_message = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])

    def end_procedure_measurement(self, **kwargs):
        self.outcome = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])
        self.termination_reason = kwargs.get('counter_name')
        self.success = self.state == 'SUCCESS'

    def is_measurement_finished(self):
        return self.outcome is not None

    def get_measurement(self):
        if not self.is_measurement_finished() or not self.start_message: return None
        start_ts, start_frame, start_dt = self.start_message
        end_ts, end_frame, end_dt = self.outcome
        return ProcedureDescription(key=None, procedure="SIP Registration", length_ms=(end_ts - start_ts) * 1000,
                                    start_frame=start_frame, end_frame=end_frame, start_timestamp=start_ts,
                                    end_timestamp=end_ts, start_datetime=start_dt, end_datetime=end_dt)

    def get_valid_sources_for_trigger(self, trigger_name: str) -> list:
        valid_sources = []
        for transition in self.transitions:
            if transition['trigger'] == trigger_name:
                source = transition['source']
                if source == '*':
                    return self.states
                if isinstance(source, list):
                    valid_sources.extend(source)
                else:
                    valid_sources.append(source)
        return valid_sources

    def process_sip_message(self, message_type: SipMessageType, cseq_number: int, cseq_method: str, **kwargs):
        if not (cseq_number == self.monitored_cseq and cseq_method.upper() == self.monitored_method):
            return
        event, counter_name = self._get_event_for_message(message_type, kwargs.get('sip_response_code'))
        if event and self.state in self.get_valid_sources_for_trigger(event):
            self.trigger(event, counter_name=counter_name, **kwargs)

    def _get_event_for_message(self, msg_type: SipMessageType, code: int = None) -> tuple:
        if self.is_caller and msg_type == SipMessageType.REGISTER: return 'event_register', "REGISTER Request"
        if msg_type == SipMessageType.SUCCESS_RESPONSE: return 'event_success_resp', f"2xx Response ({code})"
        if msg_type in [SipMessageType.CLIENT_ERROR, SipMessageType.SERVER_ERROR, SipMessageType.GLOBAL_FAILURE]:
            return 'event_failure', f"Error Response ({code})"
        return None, None


class SIPCallSuccessRateMeasurement:
    """A simple accumulator for SIP call success and failure statistics."""

    def __init__(self, name="SIP Call Success Rate"):
        self.name = name
        self.reset()

    def record_call_attempt(self): self.total_calls_attempted += 1

    def record_call_success(self): self.total_calls_successful += 1

    def record_call_failure(self, reason: str):
        self.total_calls_failed += 1
        self.failure_reasons[reason] += 1

    def get_success_rate(self) -> float:
        if not self.total_calls_attempted: return 0.0
        return (self.total_calls_successful / self.total_calls_attempted) * 100

    def get_statistics(self) -> dict:
        return {"Total Calls Attempted": self.total_calls_attempted,
                "Total Calls Successful": self.total_calls_successful, "Total Calls Failed": self.total_calls_failed,
                "Success Rate (%)": f"{self.get_success_rate():.2f}", "Failure Reasons": dict(self.failure_reasons)}

    def reset(self):
        self.total_calls_attempted = 0
        self.total_calls_successful = 0
        self.total_calls_failed = 0
        self.failure_reasons = defaultdict(int)


class SIPFlowManager:
    """Manages multiple concurrent SIP procedure measurements for a single flow."""

    def __init__(self, flow_key: tuple = None):
        self.flow_key = flow_key
        self.active_call_setups: dict[str, SIPCallSetupMeasurement] = {}
        self.active_registrations: dict[str, SIPRegistrationMeasurement] = {}
        self.completed_procedures: list[ProcedureDescription] = []
        self.call_success_rate_tracker = SIPCallSuccessRateMeasurement()
        self.registration_success_rate_tracker = SIPRegistrationSuccessRateMeasurement()
        self.sip_protocol_counters = defaultdict(int)

    def _process_call_message(self, call_id: str, message_type: SipMessageType, is_caller: bool, **kwargs):
        measurement = self.active_call_setups.get(call_id)
        if not measurement and message_type == SipMessageType.INVITE and is_caller:
            measurement = SIPCallSetupMeasurement(call_id=call_id, is_caller=True)
            self.active_call_setups[call_id] = measurement
            self.call_success_rate_tracker.record_call_attempt()
        if measurement:
            measurement.process_sip_message(message_type=message_type, is_caller=is_caller, **kwargs)
            # The measurement object lives until the call fails or gets a 2xx OK + ACK
            if measurement.is_measurement_finished():
                if measurement.success:
                    self.call_success_rate_tracker.record_call_success()
                else:
                    self.call_success_rate_tracker.record_call_failure(measurement.termination_reason)
                # get_measurement() will correctly calculate time to 180, or return None if no 180 was seen.
                if completed_data := measurement.get_measurement():
                    self.completed_procedures.append(completed_data._replace(key=self.flow_key))
                del self.active_call_setups[call_id]

    def _process_registration_message(self, call_id: str, message_type: SipMessageType, is_caller: bool, **kwargs):
        cseq_num = kwargs.get('cseq_number')
        reg_key = f"{call_id}_{cseq_num}"
        measurement = self.active_registrations.get(reg_key)
        if not measurement and message_type == SipMessageType.REGISTER and is_caller:
            measurement = SIPRegistrationMeasurement(call_id=call_id, cseq=cseq_num, is_caller=True)
            event, counter_name = measurement._get_event_for_message(message_type, kwargs.get('sip_response_code'))
            if event and measurement.state in measurement.get_valid_sources_for_trigger(event):
                measurement.trigger(event, counter_name=counter_name, **kwargs)
            self.active_registrations[reg_key] = measurement
            self.registration_success_rate_tracker.record_registration_attempt()
        elif measurement and not is_caller:
            measurement.process_sip_message(message_type=message_type, cseq_number=cseq_num, **kwargs)
        if measurement and measurement.is_measurement_finished():
            if measurement.success:
                self.registration_success_rate_tracker.record_registration_success()
            else:
                self.registration_success_rate_tracker.record_registration_failure(measurement.termination_reason)
            if completed_data := measurement.get_measurement():
                self.completed_procedures.append(completed_data._replace(key=self.flow_key))
            del self.active_registrations[reg_key]

    def process_sip_message(self, message_type: SipMessageType, **kwargs):
        """Routes a SIP message to the correct procedure processor."""
        self.sip_protocol_counters[message_type.value] += 1
        if code := kwargs.get('sip_response_code'): self.sip_protocol_counters[f"SIP_Response_{code}"] += 1

        cseq_method = (kwargs.get('cseq_method') or "UNKNOWN").upper()
        if cseq_method in ["INVITE", "ACK", "CANCEL", "BYE"]:
            self._process_call_message(message_type=message_type, **kwargs)
        elif cseq_method == "REGISTER":
            self._process_registration_message(message_type=message_type, **kwargs)

    def get_all_completed_procedures(self) -> list[ProcedureDescription]:
        return self.completed_procedures

    def get_call_success_rate_statistics(self) -> dict:
        return self.call_success_rate_tracker.get_statistics()

    def get_registration_success_rate_statistics(self) -> dict:
        return self.registration_success_rate_tracker.get_statistics()

    def get_protocol_counters(self) -> dict:
        return dict(self.sip_protocol_counters)


class SIPMeasurementAggregator:
    """
    Manages SIP measurements across multiple traffic flows and returns data as pandas DataFrames.
    """

    def __init__(self):
        self.managers: dict[tuple, SIPFlowManager] = {}

    def _get_or_create_manager(self, key: tuple) -> SIPFlowManager:
        if key not in self.managers:
            logging.info(f"Creating new SIPFlowManager for key: {key}")
            self.managers[key] = SIPFlowManager(flow_key=key)
        return self.managers[key]

    def _parse_sip_message(self, raw_message: str) -> dict:
        info = {'call_id': None, 'message_type': SipMessageType.UNKNOWN, 'sip_response_code': None, 'cseq_number': None,
                'cseq_method': None}
        if not (
        call_id_match := re.search(r'^(?:Call-ID|i):\s*(.*)$', raw_message, re.IGNORECASE | re.MULTILINE)): return info
        info['call_id'] = call_id_match.group(1).strip()
        if (cseq_match := re.search(r"^CSeq:\s*(\d+)\s+(.*)$", raw_message, re.IGNORECASE | re.MULTILINE)):
            info['cseq_number'] = int(cseq_match.group(1))
            info['cseq_method'] = cseq_match.group(2).strip()

        first_line = raw_message.strip().splitlines()[0]
        if (req_match := re.match(r"^(INVITE|ACK|BYE|CANCEL|UPDATE|REGISTER)", first_line, re.IGNORECASE)):
            msg_str = req_match.group(1).upper()
            if hasattr(SipMessageType, msg_str): info['message_type'] = SipMessageType[msg_str]
        elif (resp_match := re.match(r"^SIP/2\.0\s+(\d{3})", first_line)):
            code = int(resp_match.group(1))
            info['sip_response_code'] = code
            if 100 <= code < 200:
                info['message_type'] = SipMessageType.PROVISIONAL_RESPONSE
            elif 200 <= code < 300:
                info['message_type'] = SipMessageType.SUCCESS_RESPONSE
            elif code == 408:
                info['message_type'] = SipMessageType.REQUEST_TIMEOUT
            elif 400 <= code < 500:
                info['message_type'] = SipMessageType.CLIENT_ERROR
            elif code == 504:
                info['message_type'] = SipMessageType.SERVER_TIMEOUT
            elif 500 <= code < 600:
                info['message_type'] = SipMessageType.SERVER_ERROR
            elif 600 <= code < 700:
                info['message_type'] = SipMessageType.GLOBAL_FAILURE
        return info

    def process_message(self, key: tuple, raw_sip_message: str, timestamp: float, frame: int):
        *_, is_caller = key
        manager = self._get_or_create_manager(key)
        parsed_info = self._parse_sip_message(raw_sip_message)
        if not parsed_info.get('call_id') or not parsed_info.get('cseq_number'):
            logging.warning(f"Could not find Call-ID or CSeq for key {key}. Skipping message.");
            return
        manager.process_sip_message(
            is_caller=is_caller, timestamp=timestamp, frame=frame, date_time=datetime.fromtimestamp(timestamp),
            **parsed_info)

    def get_all_data(self) -> dict[str, pd.DataFrame]:
        all_measurements, all_call_stats, all_reg_stats, all_counters = [], [], [], []
        for key, manager in self.managers.items():
            all_measurements.extend(manager.get_all_completed_procedures())
            call_stats_data = manager.get_call_success_rate_statistics()
            if call_stats_data.get("Total Calls Attempted", 0) > 0:
                call_stats_data['flow_key'] = key;
                all_call_stats.append(call_stats_data)
            reg_stats_data = manager.get_registration_success_rate_statistics()
            if reg_stats_data.get("Total Registrations Attempted", 0) > 0:
                reg_stats_data['flow_key'] = key;
                all_reg_stats.append(reg_stats_data)
            counters_data = manager.get_protocol_counters()
            counters_data['flow_key'] = key;
            all_counters.append(counters_data)

        df_measurements = pd.DataFrame(all_measurements) if all_measurements else pd.DataFrame(
            columns=ProcedureDescription._fields)
        df_call_stats = pd.DataFrame(all_call_stats) if all_call_stats else pd.DataFrame()
        df_reg_stats = pd.DataFrame(all_reg_stats) if all_reg_stats else pd.DataFrame()
        df_counters = pd.DataFrame(all_counters).fillna(0).astype(int,
                                                                  errors='ignore') if all_counters else pd.DataFrame()

        for df in [df_call_stats, df_reg_stats, df_counters]:
            if 'flow_key' in df.columns: df.set_index('flow_key', inplace=True)

        return {"measurements": df_measurements, "call_statistics": df_call_stats,
                "registration_statistics": df_reg_stats, "counters": df_counters}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    pd.set_option('display.width', 1000);
    pd.set_option('display.max_columns', 15)

    aggregator = SIPMeasurementAggregator()
    flow_key_1 = ('192.168.1.10', 5060, '10.0.0.2', 5060, 'UDP', True)

    # --- Message Templates ---
    raw_invite_tpl = "INVITE sip:bob@biloxi.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} INVITE\r\n"
    raw_180_tpl = "SIP/2.0 180 Ringing\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} INVITE\r\n"
    raw_183_tpl = "SIP/2.0 183 Session Progress\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} INVITE\r\n"
    raw_200ok_invite_tpl = "SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} INVITE\r\n"
    raw_ack_tpl = "ACK sip:bob@biloxi.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} ACK\r\n"
    raw_register_tpl = "REGISTER sip:registrar.biloxi.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} REGISTER\r\n"
    raw_200ok_register_tpl = "SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} REGISTER\r\n"
    raw_401_auth_tpl = "SIP/2.0 401 Unauthorized\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} REGISTER\r\n"

    # --- Simulation ---
    ts = datetime.now().timestamp()

    logging.info("\n--- Simulating a successful call with 180 Ringing (should produce a measurement) ---")
    aggregator.process_message(flow_key_1, raw_invite_tpl.format(call_id='call-1', cseq_num=1), ts, 100)
    aggregator.process_message(flow_key_1, raw_180_tpl.format(call_id='call-1', cseq_num=1), ts + 0.15,
                               101)  # 150ms to ringing
    aggregator.process_message(flow_key_1, raw_200ok_invite_tpl.format(call_id='call-1', cseq_num=1), ts + 1.0, 104)
    aggregator.process_message(flow_key_1, raw_ack_tpl.format(call_id='call-1', cseq_num=1), ts + 1.1, 105)

    logging.info("\n--- Simulating a successful call without 180 Ringing (should NOT produce a measurement) ---")
    aggregator.process_message(flow_key_1, raw_invite_tpl.format(call_id='call-2', cseq_num=1), ts + 2.0, 200)
    aggregator.process_message(flow_key_1, raw_183_tpl.format(call_id='call-2', cseq_num=1), ts + 2.2, 201)
    aggregator.process_message(flow_key_1, raw_200ok_invite_tpl.format(call_id='call-2', cseq_num=1), ts + 3.0, 204)
    aggregator.process_message(flow_key_1, raw_ack_tpl.format(call_id='call-2', cseq_num=1), ts + 3.1, 205)

    logging.info("\n--- Simulating a failed registration ---")
    aggregator.process_message(flow_key_1, raw_register_tpl.format(call_id='reg-1', cseq_num=10), ts + 4.0, 300)
    aggregator.process_message(flow_key_1, raw_401_auth_tpl.format(call_id='reg-1', cseq_num=10), ts + 4.2, 301)

    # --- Display Aggregated DataFrame Results ---
    logging.info("\n--- Aggregated DataFrame Results ---")
    dataframes = aggregator.get_all_data()

    print("\n--- Completed Measurements (Time to Ringing and Registrations) ---")
    print(dataframes["measurements"])

    print("\n\n--- Call Statistics by Flow ---")
    print(dataframes["call_statistics"])

    print("\n\n--- Registration Statistics by Flow ---")
    print(dataframes["registration_statistics"])

    print("\n\n--- Protocol Counters by Flow ---")
    print(dataframes["counters"])
