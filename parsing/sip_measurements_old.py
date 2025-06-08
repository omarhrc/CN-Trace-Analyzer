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
    CLIENT_ERROR = "4xx"
    SERVER_ERROR = "5xx"
    GLOBAL_FAILURE = "6xx"
    REQUEST_TIMEOUT = "408"
    SERVER_TIMEOUT = "504"
    UPDATE = "UPDATE"
    UNKNOWN = "UNKNOWN"


class SIPCallSetupMeasurement(ProcedureMeasurement):
    """
    Measures SIP Call Setup Time using a state machine that tracks a specific CSeq transaction.
    """
    states = ['INITIAL', 'INVITE_SENT', 'PROCEEDING', 'WAITING_FOR_ACK', 'SUCCESS', 'FAILED']
    transitions = [
        {'trigger': 'event_invite', 'source': 'INITIAL', 'dest': 'INVITE_SENT', 'after': 'start_procedure_measurement'},
        {'trigger': 'event_provisional', 'source': ['INVITE_SENT', 'PROCEEDING'], 'dest': 'PROCEEDING'},
        {'trigger': 'event_success_resp', 'source': ['INVITE_SENT', 'PROCEEDING'], 'dest': 'WAITING_FOR_ACK'},
        {'trigger': 'event_ack', 'source': 'WAITING_FOR_ACK', 'dest': 'SUCCESS', 'after': 'end_procedure_measurement'},
        {'trigger': 'event_failure', 'source': '*', 'dest': 'FAILED', 'after': 'end_procedure_measurement'},
    ]

    def __init__(self, call_id: str, is_caller: bool, procedure_name="SIP Call Setup"):
        self.call_id = call_id
        self.is_caller = is_caller
        super().__init__(procedure_name=procedure_name, states=self.states, transitions=self.transitions,
                         initial_state='INITIAL')
        self.reset_measurement(initial_state='INITIAL')

    def reset_measurement(self, initial_state=None):
        self.state = initial_state or 'INITIAL'
        self.start_message = None
        self.outcome = None
        self.termination_reason = None
        self.success = False
        self.monitored_cseq = None
        self.monitored_method = None

    def start_procedure_measurement(self, **kwargs):
        self.start_message = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])

    def end_procedure_measurement(self, **kwargs):
        self.outcome = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])
        self.termination_reason = kwargs.get('counter_name')
        self.success = self.state == 'SUCCESS'
        logging.debug(f"[{self.call_id}] Call setup ended in state {self.state}. Success: {self.success}")

    def is_measurement_finished(self):
        return self.outcome is not None

    def get_measurement(self):
        if not self.is_measurement_finished() or not self.start_message: return None
        start_ts, start_frame, start_dt = self.start_message
        end_ts, end_frame, end_dt = self.outcome
        procedure_time = (end_ts - start_ts) * 1000
        return ProcedureDescription(key=None, procedure="SIP Call Setup", length_ms=procedure_time,
                                    start_frame=start_frame, end_frame=end_frame,
                                    start_timestamp=start_ts, end_timestamp=end_ts,
                                    start_datetime=start_dt, end_datetime=end_dt)

    def check_and_trigger(self, event, **kwargs):
        if event == 'event_invite' and self.state == 'INITIAL':
            self.state = 'INVITE_SENT'; self.start_procedure_measurement(**kwargs)
        elif event == 'event_provisional' and self.state in ['INVITE_SENT', 'PROCEEDING']:
            self.state = 'PROCEEDING'
        elif event == 'event_success_resp' and self.state in ['INVITE_SENT', 'PROCEEDING']:
            self.state = 'WAITING_FOR_ACK'
        elif event == 'event_ack' and self.state == 'WAITING_FOR_ACK':
            self.state = 'SUCCESS'; self.end_procedure_measurement(**kwargs)
        elif event == 'event_failure':
            self.state = 'FAILED'; self.end_procedure_measurement(**kwargs)

    def process_sip_message(self, message_type: SipMessageType, sip_response_code: int = None, cseq_number: int = None,
                            cseq_method: str = None, **kwargs):
        """Processes a SIP message, validating it against the monitored CSeq transaction."""
        # Start monitoring the CSeq of the first INVITE for this measurement instance.
        if message_type == SipMessageType.INVITE and self.state == 'INITIAL' and self.is_caller:
            self.monitored_cseq = cseq_number
            self.monitored_method = cseq_method.upper() if cseq_method else None
        # If we have started monitoring, all subsequent relevant messages must match the CSeq.
        elif self.monitored_cseq is not None:
            is_response = sip_response_code is not None
            # Responses and CANCEL requests must match the CSeq number and original method.
            if is_response or (message_type == SipMessageType.CANCEL and self.is_caller):
                if cseq_number != self.monitored_cseq or (cseq_method and cseq_method.upper() != self.monitored_method):
                    logging.debug(
                        f"[{self.call_id}] Ignoring message with CSeq {cseq_number} {cseq_method} - does not match monitored transaction {self.monitored_cseq} {self.monitored_method}.")
                    return

        event, counter_name = self._get_event_for_message(message_type, sip_response_code)
        if event:
            self.check_and_trigger(event, counter_name=counter_name, **kwargs)
        else:
            logging.debug(f"[{self.call_id}] No transition for message {message_type.value} in state {self.state}")

    def _get_event_for_message(self, msg_type: SipMessageType, code: int = None) -> tuple:
        # The logic here remains the same, as the CSeq validation happens before this is called.
        if self.is_caller:
            if msg_type == SipMessageType.INVITE: return 'event_invite', "INVITE Request"
            if msg_type == SipMessageType.ACK: return 'event_ack', "ACK Request"
            if msg_type == SipMessageType.CANCEL: return 'event_failure', "CANCEL Request"
        if msg_type == SipMessageType.PROVISIONAL_RESPONSE: return 'event_provisional', f"1xx Response ({code})"
        if msg_type == SipMessageType.SUCCESS_RESPONSE: return 'event_success_resp', f"2xx Response ({code})"
        error_map = {SipMessageType.CLIENT_ERROR: f"4xx Client Error ({code})",
                     SipMessageType.SERVER_ERROR: f"5xx Server Error ({code})",
                     SipMessageType.GLOBAL_FAILURE: f"6xx Global Failure ({code})",
                     SipMessageType.REQUEST_TIMEOUT: f"408 Request Timeout",
                     SipMessageType.SERVER_TIMEOUT: f"504 Server Timeout",
                     SipMessageType.BYE: "BYE Received (During Setup)"}
        if msg_type in error_map and self.state not in ['SUCCESS', 'FAILED']: return 'event_failure', error_map[
            msg_type]
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


class SIPCallSetupManager:
    """Manages multiple concurrent SIP call setup measurements."""

    def __init__(self, flow_key: tuple = None):
        self.flow_key = flow_key
        self.active_call_setups: dict[str, SIPCallSetupMeasurement] = {}
        self.completed_call_setups: list[ProcedureDescription] = []
        self.call_success_rate_tracker = SIPCallSuccessRateMeasurement()
        self.sip_protocol_counters = defaultdict(int)

    def process_sip_message(self, call_id: str, message_type: SipMessageType, is_caller: bool,
                            sip_response_code: int = None, **kwargs):
        """Routes a SIP message to the correct measurement instance, creating one if necessary."""
        self.sip_protocol_counters[message_type.value] += 1
        if sip_response_code: self.sip_protocol_counters[f"SIP_Response_{sip_response_code}"] += 1
        measurement = self.active_call_setups.get(call_id)
        if not measurement and message_type == SipMessageType.INVITE and is_caller:
            measurement = SIPCallSetupMeasurement(call_id=call_id, is_caller=True)
            self.active_call_setups[call_id] = measurement
            self.call_success_rate_tracker.record_call_attempt()
        if measurement:
            measurement.process_sip_message(message_type, sip_response_code, is_caller=is_caller, **kwargs)
            if measurement.is_measurement_finished():
                if measurement.success:
                    self.call_success_rate_tracker.record_call_success()
                else:
                    self.call_success_rate_tracker.record_call_failure(measurement.termination_reason)
                if completed_data := measurement.get_measurement():
                    stamped_data = completed_data._replace(key=self.flow_key)
                    self.completed_call_setups.append(stamped_data)
                del self.active_call_setups[call_id]

    def get_all_completed_measurements(self) -> list[ProcedureDescription]:
        return self.completed_call_setups

    def get_call_success_rate_statistics(self) -> dict:
        return self.call_success_rate_tracker.get_statistics()

    def get_protocol_counters(self) -> dict:
        return dict(self.sip_protocol_counters)


class SIPMeasurementAggregator:
    """
    Manages SIP measurements across multiple traffic flows and returns data as pandas DataFrames.
    The key is a tuple of (ip_src, port_src, ip_dst, port_dst, transport_protocol, is_caller).
    """

    def __init__(self):
        self.managers: dict[tuple, SIPCallSetupManager] = {}

    def _get_or_create_manager(self, key: tuple) -> SIPCallSetupManager:
        if key not in self.managers:
            logging.info(f"Creating new SIPCallSetupManager for key: {key}")
            self.managers[key] = SIPCallSetupManager(flow_key=key)
        return self.managers[key]

    def _parse_sip_message(self, raw_message: str) -> dict:
        """Parses a raw SIP message to extract Call-ID, CSeq, message type, and status code."""
        info = {'call_id': None, 'message_type': SipMessageType.UNKNOWN, 'sip_response_code': None, 'cseq_number': None,
                'cseq_method': None}
        if not (
        call_id_match := re.search(r"^Call-ID:\s*(.*)$", raw_message, re.IGNORECASE | re.MULTILINE)): return info
        info['call_id'] = call_id_match.group(1).strip()
        if (cseq_match := re.search(r"^CSeq:\s*(\d+)\s+(.*)$", raw_message, re.IGNORECASE | re.MULTILINE)):
            info['cseq_number'] = int(cseq_match.group(1))
            info['cseq_method'] = cseq_match.group(2).strip()

        first_line = raw_message.strip().splitlines()[0]
        if (req_match := re.match(r"^(INVITE|ACK|BYE|CANCEL|UPDATE)", first_line, re.IGNORECASE)):
            if hasattr(SipMessageType, (msg_str := req_match.group(1).upper())): info['message_type'] = SipMessageType[
                msg_str]
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
        """Processes a raw SIP message for a given flow key."""
        # Unpack the 6-element key
        ip_src, port_src, ip_dst, port_dst, transport_protocol, is_caller = key
        manager = self._get_or_create_manager(key)
        parsed_info = self._parse_sip_message(raw_sip_message)
        if not parsed_info.get('call_id') or not parsed_info.get('cseq_number'):
            logging.warning(f"Could not find Call-ID or CSeq for key {key}. Skipping message.");
            return
        manager.process_sip_message(
            call_id=parsed_info['call_id'], message_type=parsed_info['message_type'],
            is_caller=is_caller, sip_response_code=parsed_info['sip_response_code'],
            timestamp=timestamp, frame=frame, date_time=datetime.fromtimestamp(timestamp),
            cseq_number=parsed_info['cseq_number'], cseq_method=parsed_info['cseq_method'])

    def get_all_data(self) -> dict[str, pd.DataFrame]:
        """Aggregates all data and returns it as a dictionary of pandas DataFrames."""
        all_measurements, all_stats, all_counters = [], [], []
        for key, manager in self.managers.items():
            all_measurements.extend(manager.get_all_completed_measurements())
            stats_data = manager.get_call_success_rate_statistics();
            stats_data['flow_key'] = key;
            all_stats.append(stats_data)
            counters_data = manager.get_protocol_counters();
            counters_data['flow_key'] = key;
            all_counters.append(counters_data)
        df_measurements = pd.DataFrame(all_measurements) if all_measurements else pd.DataFrame(
            columns=ProcedureDescription._fields)
        df_stats = pd.DataFrame(all_stats) if all_stats else pd.DataFrame()
        df_counters = pd.DataFrame(all_counters).fillna(0).astype(int,
                                                                  errors='ignore') if all_counters else pd.DataFrame()
        if 'flow_key' in df_stats.columns: df_stats.set_index('flow_key', inplace=True)
        if 'flow_key' in df_counters.columns: df_counters.set_index('flow_key', inplace=True)
        return {"measurements": df_measurements, "statistics": df_stats, "counters": df_counters}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    pd.set_option('display.width', 1000);
    pd.set_option('display.max_columns', 15)

    logging.info("\n--- Testing SIPMeasurementAggregator with CSeq Tracking ---")
    aggregator = SIPMeasurementAggregator()
    # Updated flow_key_1 to be a 6-element tuple
    flow_key_1 = ('192.168.1.10', 5060, '10.0.0.2', 5060, 'UDP', True)

    # --- Message Templates ---
    # Note the CSeq in each message
    raw_invite_tpl = "INVITE sip:bob@biloxi.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} INVITE\r\n"
    raw_update_tpl = "UPDATE sip:bob@biloxi.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} UPDATE\r\n"
    raw_183_tpl = "SIP/2.0 183 Session Progress\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} INVITE\r\n"
    raw_200ok_update_tpl = "SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} UPDATE\r\n"
    raw_200ok_invite_tpl = "SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} INVITE\r\n"
    raw_ack_tpl = "ACK sip:bob@biloxi.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} ACK\r\n"

    # --- Simulation: INVITE with an intervening UPDATE ---
    # The measurement should ignore the UPDATE and its 200 OK, and correctly use the 183 and final 200 OK for the INVITE.
    logging.info("\n--- Simulating call with an intervening UPDATE request ---")
    ts = datetime.now().timestamp()
    call_id = 'cseq-test-call'
    aggregator.process_message(flow_key_1, raw_invite_tpl.format(call_id=call_id, cseq_num=1), ts, 100)
    aggregator.process_message(flow_key_1, raw_183_tpl.format(call_id=call_id, cseq_num=1), ts + 0.2, 101)
    # This UPDATE and its response should be ignored by the INVITE measurement instance
    aggregator.process_message(flow_key_1, raw_update_tpl.format(call_id=call_id, cseq_num=2), ts + 0.3, 102)
    aggregator.process_message(flow_key_1, raw_200ok_update_tpl.format(call_id=call_id, cseq_num=2), ts + 0.4, 103)
    # This is the real end of the INVITE transaction
    aggregator.process_message(flow_key_1, raw_200ok_invite_tpl.format(call_id=call_id, cseq_num=1), ts + 1.0, 104)
    aggregator.process_message(flow_key_1, raw_ack_tpl.format(call_id=call_id, cseq_num=1), ts + 1.1, 105)

    # --- Display Aggregated DataFrame Results ---
    logging.info("\n--- Aggregated DataFrame Results ---")
    dataframes = aggregator.get_all_data()
    print("\n--- Completed Measurements ---")
    print(dataframes["measurements"])
    print("\n\n--- Call Statistics by Flow ---")
    print(dataframes["statistics"])
    print("\n\n--- Protocol Counters by Flow ---")
    print(dataframes["counters"])