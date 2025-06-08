# sip_measurements.py

import logging
import re
from datetime import datetime
from enum import Enum
from collections import defaultdict

from parsing.common import ProcedureMeasurement, ProcedureDescription


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
    UNKNOWN = "UNKNOWN"


class SIPCallSetupMeasurement(ProcedureMeasurement):
    """
    Measures SIP Call Setup Time using a simplified state machine.
    This tracks the procedure from the initial INVITE to a final state of SUCCESS or FAILED.
    """
    # Simplified states for the call setup procedure
    states = ['INITIAL', 'INVITE_SENT', 'PROCEEDING', 'WAITING_FOR_ACK', 'SUCCESS', 'FAILED']

    # Consolidated transitions for the state machine
    transitions = [
        {'trigger': 'event_invite', 'source': 'INITIAL', 'dest': 'INVITE_SENT', 'after': 'start_procedure_measurement'},
        {'trigger': 'event_provisional', 'source': ['INVITE_SENT', 'PROCEEDING'], 'dest': 'PROCEEDING'},
        {'trigger': 'event_success_resp', 'source': ['INVITE_SENT', 'PROCEEDING'], 'dest': 'WAITING_FOR_ACK'},
        {'trigger': 'event_ack', 'source': 'WAITING_FOR_ACK', 'dest': 'SUCCESS', 'after': 'end_procedure_measurement'},
        {'trigger': 'event_failure', 'source': '*', 'dest': 'FAILED', 'after': 'end_procedure_measurement'},
    ]

    def __init__(self, call_id: str, is_caller: bool, procedure_name="SIP Call Setup"):
        """Initializes the state machine and measurement attributes."""
        self.call_id = call_id
        self.is_caller = is_caller  # True for User Agent Client (UAC), False for User Agent Server (UAS)
        self.termination_reason = None

        super().__init__(
            procedure_name=procedure_name,
            states=self.states,
            transitions=self.transitions,
            initial_state='INITIAL'
        )
        self.reset_measurement(initial_state='INITIAL')

    def reset_measurement(self, initial_state=None):
        """Resets the measurement to its initial state."""
        super().reset_measurement(initial_state or 'INITIAL')
        self.termination_reason = None
        self.success = False

    def end_procedure_measurement(self, append_measurement=True, **kwargs):
        """Finalizes the measurement and records the outcome."""
        super().end_procedure_measurement(append_measurement=True, **kwargs)
        self.termination_reason = kwargs.get('counter_name')
        self.success = self.state == 'SUCCESS'
        logging.debug(f"[{self.call_id}] Call setup ended in state {self.state}. Success: {self.success}")

    def process_sip_message(self, message_type: SipMessageType, sip_response_code: int = None, **kwargs):
        """
        Processes a SIP message to trigger the appropriate state transition.
        """
        event, counter_name = self._get_event_for_message(message_type, sip_response_code)

        if event:
            # The 'check_and_trigger' method is inherited from ProcedureMeasurement
            self.check_and_trigger(event, counter_name=counter_name, **kwargs)
        else:
            logging.debug(f"[{self.call_id}] No transition for message {message_type.value} in state {self.state}")

    def _get_event_for_message(self, msg_type: SipMessageType, code: int = None) -> tuple:
        """Maps a SIP message type to a state machine event and a counter name."""
        # Mapping for success and provisional paths, restricted to the caller (UAC)
        if self.is_caller:
            if msg_type == SipMessageType.INVITE:
                return 'event_invite', "INVITE Request"
            if msg_type == SipMessageType.ACK:
                return 'event_ack', "ACK Request"
            if msg_type == SipMessageType.CANCEL:
                return 'event_failure', "CANCEL Request"

        # Mapping for responses and other events
        if msg_type == SipMessageType.PROVISIONAL_RESPONSE:
            return 'event_provisional', f"1xx Response ({code})"
        if msg_type == SipMessageType.SUCCESS_RESPONSE:
            return 'event_success_resp', f"2xx Response ({code})"

        # All error types are mapped to a single failure event
        error_map = {
            SipMessageType.CLIENT_ERROR: f"4xx Client Error ({code})",
            SipMessageType.SERVER_ERROR: f"5xx Server Error ({code})",
            SipMessageType.GLOBAL_FAILURE: f"6xx Global Failure ({code})",
            SipMessageType.REQUEST_TIMEOUT: f"408 Request Timeout",
            SipMessageType.SERVER_TIMEOUT: f"504 Server Timeout",
            SipMessageType.BYE: "BYE Received (During Setup)"
        }
        if msg_type in error_map and self.state not in ['SUCCESS', 'FAILED']:
            return 'event_failure', error_map[msg_type]

        return None, None


class SIPCallSuccessRateMeasurement:
    """A simple accumulator for SIP call success and failure statistics."""

    def __init__(self, name="SIP Call Success Rate"):
        self.name = name
        self.reset()

    def record_call_attempt(self):
        self.total_calls_attempted += 1

    def record_call_success(self):
        self.total_calls_successful += 1

    def record_call_failure(self, reason: str):
        self.total_calls_failed += 1
        self.failure_reasons[reason] += 1

    def get_success_rate(self) -> float:
        if not self.total_calls_attempted:
            return 0.0
        return (self.total_calls_successful / self.total_calls_attempted) * 100

    def get_statistics(self) -> dict:
        return {
            "Total Calls Attempted": self.total_calls_attempted,
            "Total Calls Successful": self.total_calls_successful,
            "Total Calls Failed": self.total_calls_failed,
            "Success Rate (%)": f"{self.get_success_rate():.2f}",
            "Failure Reasons": dict(self.failure_reasons)
        }

    def reset(self):
        self.total_calls_attempted = 0
        self.total_calls_successful = 0
        self.total_calls_failed = 0
        self.failure_reasons = defaultdict(int)


class SIPCallSetupManager:
    """Manages multiple concurrent SIP call setup measurements."""

    def __init__(self):
        self.active_call_setups: dict[str, SIPCallSetupMeasurement] = {}
        self.completed_call_setups: list[ProcedureDescription] = []
        self.call_success_rate_tracker = SIPCallSuccessRateMeasurement()
        self.sip_protocol_counters = defaultdict(int)

    def process_sip_message(self, call_id: str, message_type: SipMessageType,
                            is_caller: bool, sip_response_code: int = None, **kwargs):
        """
        Routes a SIP message to the correct measurement instance, creating one if necessary.
        """
        self.sip_protocol_counters[message_type.value] += 1
        if sip_response_code:
            self.sip_protocol_counters[f"SIP_Response_{sip_response_code}"] += 1

        measurement = self.active_call_setups.get(call_id)

        # A new measurement is created only for an INVITE from the caller's side.
        if not measurement and message_type == SipMessageType.INVITE and is_caller:
            measurement = SIPCallSetupMeasurement(call_id=call_id, is_caller=True)
            self.active_call_setups[call_id] = measurement
            self.call_success_rate_tracker.record_call_attempt()

        if measurement:
            measurement.process_sip_message(message_type, sip_response_code, **kwargs)

            # If the measurement has concluded, collect the results and clean up.
            if measurement.is_measurement_finished():
                if measurement.success:
                    self.call_success_rate_tracker.record_call_success()
                else:
                    self.call_success_rate_tracker.record_call_failure(measurement.termination_reason)

                if completed_data := measurement.get_measurement():
                    self.completed_call_setups.append(completed_data)

                del self.active_call_setups[call_id]

    def get_all_completed_measurements(self) -> list[ProcedureDescription]:
        """Returns all completed SIP call setup measurements."""
        return self.completed_call_setups

    def get_call_success_rate_statistics(self) -> dict:
        """Returns overall SIP call success rate statistics."""
        return self.call_success_rate_tracker.get_statistics()


class SIPMeasurementAggregator:
    """
    Manages SIP measurements across multiple traffic flows.
    Each flow is defined by a unique key and gets its own SIPCallSetupManager.
    """

    def __init__(self):
        """Initializes the aggregator with a dictionary to hold managers per key."""
        self.managers: dict[tuple, SIPCallSetupManager] = {}

    def _get_or_create_manager(self, key: tuple) -> SIPCallSetupManager:
        """Retrieves an existing manager for a key or creates a new one."""
        if key not in self.managers:
            logging.info(f"Creating new SIPCallSetupManager for key: {key}")
            self.managers[key] = SIPCallSetupManager()
        return self.managers[key]

    def _parse_sip_message(self, raw_message: str) -> dict:
        """
        Parses a raw SIP message string to extract the Call-ID, message type, and status code.
        """
        info = {'call_id': None, 'message_type': SipMessageType.UNKNOWN, 'sip_response_code': None}

        # Use regex to find the Call-ID header
        call_id_match = re.search(r"^Call-ID:\s*(.*)$", raw_message, re.IGNORECASE | re.MULTILINE)
        if call_id_match:
            info['call_id'] = call_id_match.group(1).strip()
        else:
            return info  # Cannot proceed without a Call-ID

        first_line = raw_message.splitlines()[0]

        # Check for a request type (e.g., INVITE, ACK)
        req_match = re.match(r"^(INVITE|ACK|BYE|CANCEL|UPDATE)", first_line, re.IGNORECASE)
        if req_match:
            msg_str = req_match.group(1).upper()
            if hasattr(SipMessageType, msg_str):
                info['message_type'] = SipMessageType[msg_str]
            return info

        # Check for a response type (e.g., SIP/2.0 200 OK)
        resp_match = re.match(r"^SIP/2\.0\s+(\d{3})", first_line)
        if resp_match:
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
        """
        Processes a raw SIP message for a given flow key.

        Args:
            key (tuple): A tuple uniquely identifying the flow, e.g., (ip, port, proto, is_caller).
            raw_sip_message (str): The raw SIP message content as a string.
            timestamp (float): The timestamp of the message capture.
            frame (int): The frame number of the message capture.
        """
        _, _, _, is_caller = key
        manager = self._get_or_create_manager(key)

        parsed_info = self._parse_sip_message(raw_sip_message)
        if not parsed_info['call_id']:
            logging.warning(f"Could not find Call-ID for key {key}. Skipping message.")
            return

        manager.process_sip_message(
            call_id=parsed_info['call_id'],
            message_type=parsed_info['message_type'],
            is_caller=is_caller,
            sip_response_code=parsed_info['sip_response_code'],
            timestamp=timestamp,
            frame=frame,
            date_time=datetime.fromtimestamp(timestamp)
        )

    def get_data_by_key(self, key: tuple) -> dict:
        """Retrieves all measurements and counters for a specific key."""
        if key in self.managers:
            manager = self.managers[key]
            return {
                "completed_measurements": manager.get_all_completed_measurements(),
                "success_rate_stats": manager.get_call_success_rate_statistics(),
                "protocol_counters": manager.get_protocol_counters(),
            }
        return {}

    def get_all_data(self) -> dict:
        """Retrieves all data from all managers, structured by their keys."""
        return {str(key): self.get_data_by_key(key) for key in self.managers}


# Example usage for testing
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # --- New Aggregator Example ---
    logging.info("\n--- Testing SIPMeasurementAggregator ---")
    aggregator = SIPMeasurementAggregator()

    # Define two different traffic flows
    flow_key_1 = ('192.168.1.10', 5060, 'UDP', True)  # Caller 1
    flow_key_2 = ('10.0.0.5', 5060, 'UDP', True)  # Caller 2

    # Message templates
    raw_invite_tpl = "INVITE sip:bob@biloxi.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\n"
    raw_ok_tpl = "SIP/2.0 200 OK\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\n"
    raw_ack_tpl = "ACK sip:bob@biloxi.com SIP/2.0\r\nCall-ID: {call_id}\r\nCSeq: 1 ACK\r\n"
    raw_fail_tpl = "SIP/2.0 404 Not Found\r\nCall-ID: {call_id}\r\nCSeq: 1 INVITE\r\n"

    # Process a successful call on flow 1
    ts1 = datetime.now().timestamp()
    aggregator.process_message(flow_key_1, raw_invite_tpl.format(call_id='call-abc'), ts1, 100)
    aggregator.process_message(flow_key_1, raw_ok_tpl.format(call_id='call-abc'), ts1 + 0.5, 101)
    aggregator.process_message(flow_key_1, raw_ack_tpl.format(call_id='call-abc'), ts1 + 0.6, 102)

    # Process a failed call on flow 2
    ts2 = datetime.now().timestamp()
    aggregator.process_message(flow_key_2, raw_invite_tpl.format(call_id='call-xyz'), ts2, 200)
    aggregator.process_message(flow_key_2, raw_fail_tpl.format(call_id='call-xyz'), ts2 + 0.2, 201)

    # Process another successful call on flow 1
    ts3 = datetime.now().timestamp()
    aggregator.process_message(flow_key_1, raw_invite_tpl.format(call_id='call-def'), ts3, 300)
    aggregator.process_message(flow_key_1, raw_ok_tpl.format(call_id='call-def'), ts3 + 0.4, 301)
    aggregator.process_message(flow_key_1, raw_ack_tpl.format(call_id='call-def'), ts3 + 0.5, 302)

    # --- Display Aggregated Results ---
    logging.info("\n--- Aggregated Results ---")
    all_results = aggregator.get_all_data()

    import json

    print(json.dumps(all_results, default=str, indent=2))