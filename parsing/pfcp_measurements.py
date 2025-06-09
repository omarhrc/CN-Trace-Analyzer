# pfcp_measurements.py

import logging
import re
from datetime import datetime
from enum import Enum
from collections import defaultdict, namedtuple
import pandas as pd
from parsing.common import ProcedureDescription, ProcedureMeasurement


class PfcpMessageType(Enum):
    """Enumerates the high-level types of PFCP messages."""
    REQUEST = "Request"
    RESPONSE = "Response"
    UNKNOWN = "Unknown"


class PfcpProcedureMeasurement(ProcedureMeasurement):
    """
    Measures PFCP transaction response time.
    A transaction is identified by its Sequence Number.
    """
    states = ['INITIAL', 'REQUEST_SENT', 'SUCCESS', 'FAILED']
    transitions = [
        {'trigger': 'event_request', 'source': 'INITIAL', 'dest': 'REQUEST_SENT',
         'after': 'start_procedure_measurement'},
        {'trigger': 'event_success_response', 'source': 'REQUEST_SENT', 'dest': 'SUCCESS',
         'after': 'end_procedure_measurement'},
        {'trigger': 'event_failure_response', 'source': 'REQUEST_SENT', 'dest': 'FAILED',
         'after': 'end_procedure_measurement'},
    ]

    def __init__(self, sequence_number: int, procedure_name: str):
        self.sequence_number = sequence_number
        super().__init__(procedure_name=procedure_name, states=self.states, transitions=self.transitions,
                         initial_state='INITIAL')
        self.reset_measurement()

    def reset_measurement(self, initial_state='INITIAL'):
        """Resets the state for a new measurement."""
        self.state = initial_state
        self.start_message = None
        self.outcome = None
        self.termination_reason = None
        self.success = False

    def start_procedure_measurement(self, **kwargs):
        """Captures the start time of the procedure."""
        self.start_message = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])

    def end_procedure_measurement(self, **kwargs):
        """Captures the end time and result of the procedure."""
        self.outcome = (kwargs['timestamp'], kwargs['frame'], kwargs['date_time'])
        self.termination_reason = kwargs.get('counter_name')
        self.success = self.state == 'SUCCESS'
        logging.debug(f"[{self.sequence_number}] PFCP transaction ended. Success: {self.success}")

    def is_measurement_finished(self):
        """Checks if the measurement has concluded."""
        return self.outcome is not None

    def get_measurement(self) -> ProcedureDescription:
        """Returns the completed measurement data."""
        if not self.is_measurement_finished() or not self.start_message:
            return None
        start_ts, start_frame, start_dt = self.start_message
        end_ts, end_frame, end_dt = self.outcome
        procedure_time = (end_ts - start_ts) * 1000
        return ProcedureDescription(
            key=None, procedure=self.procedure_name, length_ms=procedure_time,
            start_frame=start_frame, end_frame=end_frame,
            start_timestamp=start_ts, end_timestamp=end_ts,
            start_datetime=start_dt, end_datetime=end_dt
        )

    def get_valid_sources_for_trigger(self, trigger_name: str) -> list:
        """Finds all valid source states for a given trigger from the transitions table."""
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

    def process_response(self, cause: str, **kwargs):
        """Processes a PFCP Response message based on its Cause IE."""
        if cause.lower() == 'request accepted':
            event, counter_name = 'event_success_response', "Success (Request Accepted)"
        else:
            event, counter_name = 'event_failure_response', f"Failure ({cause})"

        if self.state in self.get_valid_sources_for_trigger(event):
            self.trigger(event, counter_name=counter_name, **kwargs)


class PfcpSuccessRateMeasurement:
    """A simple accumulator for PFCP transaction success and failure statistics."""

    def __init__(self, name="PFCP Success Rate"):
        self.name = name
        self.reset()

    def record_attempt(self): self.total_transactions_attempted += 1

    def record_success(self): self.total_transactions_successful += 1

    def record_failure(self, reason: str):
        self.total_transactions_failed += 1
        self.failure_reasons[reason] += 1

    def get_success_rate(self) -> float:
        if not self.total_transactions_attempted: return 0.0
        return (self.total_transactions_successful / self.total_transactions_attempted) * 100

    def get_statistics(self) -> dict:
        return {
            "Total Transactions Attempted": self.total_transactions_attempted,
            "Total Transactions Successful": self.total_transactions_successful,
            "Total Transactions Failed": self.total_transactions_failed,
            "Success Rate (%)": f"{self.get_success_rate():.2f}",
            "Failure Reasons": dict(self.failure_reasons)
        }

    def reset(self):
        self.total_transactions_attempted = 0
        self.total_transactions_successful = 0
        self.total_transactions_failed = 0
        self.failure_reasons = defaultdict(int)


class PfcpFlowManager:
    """Manages multiple concurrent PFCP transaction measurements for a single flow."""

    def __init__(self, flow_key: tuple):
        self.flow_key = flow_key
        self.active_transactions: dict[int, PfcpProcedureMeasurement] = {}  # Keyed by Sequence Number
        self.completed_procedures: list[ProcedureDescription] = []
        self.success_rate_tracker = PfcpSuccessRateMeasurement()
        self.protocol_counters = defaultdict(int)

    def process_pfcp_message(self, message_type: PfcpMessageType, full_message_type: str, sequence_number: int,
                             cause: str = None, **kwargs):
        """Routes a PFCP message to the correct measurement instance."""
        self.protocol_counters[full_message_type] += 1
        if cause:
            self.protocol_counters[f"Cause-{cause}"] += 1

        if message_type == PfcpMessageType.REQUEST:
            if sequence_number in self.active_transactions:
                logging.warning(f"Duplicate Sequence Number {sequence_number} seen in a new request. Overwriting.")

            # Procedure name is the base name, e.g., "PFCP Session Establishment"
            procedure_name = full_message_type.replace(" Request", "")
            measurement = PfcpProcedureMeasurement(sequence_number, procedure_name)
            measurement.trigger('event_request', **kwargs)
            self.active_transactions[sequence_number] = measurement
            self.success_rate_tracker.record_attempt()

        elif message_type == PfcpMessageType.RESPONSE:
            measurement = self.active_transactions.get(sequence_number)
            if not measurement:
                logging.warning(f"Received a response for an unknown Sequence Number: {sequence_number}")
                return

            measurement.process_response(cause, **kwargs)
            if measurement.is_measurement_finished():
                if measurement.success:
                    self.success_rate_tracker.record_success()
                else:
                    self.success_rate_tracker.record_failure(measurement.termination_reason)

                if completed_data := measurement.get_measurement():
                    self.completed_procedures.append(completed_data._replace(key=self.flow_key))

                del self.active_transactions[sequence_number]

    def get_all_completed_procedures(self) -> list[ProcedureDescription]:
        return self.completed_procedures

    def get_success_rate_statistics(self) -> dict:
        return self.success_rate_tracker.get_statistics()

    def get_protocol_counters(self) -> dict:
        return dict(self.protocol_counters)


class PfcpMeasurementAggregator:
    """
    Manages PFCP measurements across multiple traffic flows and returns data as pandas DataFrames.
    """

    def __init__(self):
        self.managers: dict[tuple, PfcpFlowManager] = {}

    def _get_or_create_manager(self, key: tuple) -> PfcpFlowManager:
        if key not in self.managers:
            logging.info(f"Creating new PfcpFlowManager for key: {key}")
            self.managers[key] = PfcpFlowManager(flow_key=key)
        return self.managers[key]

    def _parse_pfcp_message(self, raw_message: str) -> dict:
        """
        Simulates parsing of a PFCP message.
        """
        info = {'message_type': PfcpMessageType.UNKNOWN, 'full_message_type': 'Unknown',
                'sequence_number': None, 'cause': None, 'node_id': None}

        if type_match := re.search(r"Message Type:\s*(.+)", raw_message, re.IGNORECASE):
            info['full_message_type'] = type_match.group(1).strip()
            if "Response" in info['full_message_type']:
                info['message_type'] = PfcpMessageType.RESPONSE
            elif "Request" in info['full_message_type']:
                info['message_type'] = PfcpMessageType.REQUEST

        if seq_match := re.search(r"Sequence Number:\s*(\d+)", raw_message, re.IGNORECASE):
            info['sequence_number'] = int(seq_match.group(1))

        if cause_match := re.search(r"Cause:\s*(.+)", raw_message, re.IGNORECASE):
            info['cause'] = cause_match.group(1).strip()

        if node_id_match := re.search(r"Node ID.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw_message, re.IGNORECASE):
            info['node_id'] = node_id_match.group(1).strip()

        return info

    def process_message(self, key: tuple, raw_pfcp_message: str, timestamp: float, frame: int):
        """Processes a raw PFCP message for a given flow key after validating the Node ID."""
        ip_src, _, ip_dst, _, _, _ = key
        manager = self._get_or_create_manager(key)
        parsed_info = self._parse_pfcp_message(raw_pfcp_message)

        # Validate required fields are present
        if parsed_info.get('sequence_number') is None:
            logging.warning(f"Could not find Sequence Number for key {key}. Skipping message.")
            return

        # Validate Node ID against the flow endpoints
        node_id = parsed_info.get('node_id')
        if node_id:
            if parsed_info['message_type'] == PfcpMessageType.REQUEST and node_id != ip_src:
                # Request's Node ID must match the source IP of the flow, discard otherwise
                return
            if parsed_info['message_type'] == PfcpMessageType.RESPONSE and node_id != ip_dst:
                # Response's Node ID must match the destination IP of the flow, discard otherwise
                return

        manager.process_pfcp_message(
            timestamp=timestamp, frame=frame, date_time=datetime.fromtimestamp(timestamp), **parsed_info
        )

    def get_all_data(self) -> dict[str, pd.DataFrame]:
        """Aggregates all data and returns it as a dictionary of pandas DataFrames."""
        all_measurements, all_stats, all_counters = [], [], []
        for key, manager in self.managers.items():
            all_measurements.extend(manager.get_all_completed_procedures())
            stats_data = manager.get_success_rate_statistics()
            if stats_data.get("Total Transactions Attempted", 0) > 0:
                stats_data['flow_key'] = key
                all_stats.append(stats_data)

            counters_data = manager.get_protocol_counters()
            counters_data['flow_key'] = key
            all_counters.append(counters_data)

        # Create DataFrames
        df_measurements = pd.DataFrame(all_measurements) if all_measurements else pd.DataFrame(
            columns=ProcedureDescription._fields)
        df_stats = pd.DataFrame(all_stats) if all_stats else pd.DataFrame()
        df_counters = pd.DataFrame(all_counters).fillna(0).astype(int,
                                                                  errors='ignore') if all_counters else pd.DataFrame()

        for df in [df_stats, df_counters]:
            if 'flow_key' in df.columns: df.set_index('flow_key', inplace=True)

        return {"measurements": df_measurements, "statistics": df_stats, "counters": df_counters}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    pd.set_option('display.width', 1000)
    pd.set_option('display.max_columns', 15)
    pd.set_option('display.max_rows', 50)

    aggregator = PfcpMeasurementAggregator()

    # --- Define multiple flow keys for testing ---
    flow_key_1 = ('2001:db8:1:1::1', 8805, '2001:db8:2:2::1', 8805, 'UDP', True)  # SMF 1 -> UPF 1
    flow_key_2 = ('2001:db8:3:3::1', 8805, '2001:db8:4:4::1', 8805, 'UDP', True)  # SMF 2 -> UPF 2

    # --- Mock PFCP Message Templates with Node ID ---
    est_req_tpl = "Message Type: PFCP Session Establishment Request\nNode ID: {node_id}\nSequence Number: {seq}"
    est_rsp_tpl = "Message Type: PFCP Session Establishment Response\nNode ID: {node_id}\nSequence Number: {seq}\nCause: Request Accepted"
    mod_req_tpl = "Message Type: PFCP Session Modification Request\nNode ID: {node_id}\nSequence Number: {seq}"
    mod_rsp_fail_tpl = "Message Type: PFCP Session Modification Response\nNode ID: {node_id}\nSequence Number: {seq}\nCause: Mandatory IE missing"
    del_req_tpl = "Message Type: PFCP Session Deletion Request\nNode ID: {node_id}\nSequence Number: {seq}"
    del_rsp_tpl = "Message Type: PFCP Session Deletion Response\nNode ID: {node_id}\nSequence Number: {seq}\nCause: Request Accepted"

    ts = datetime.now().timestamp()

    # --- Simulation Test Cases ---
    logging.info("\n--- Test Case 1: Standard successful and failed transactions on Flow 1 ---")
    aggregator.process_message(flow_key_1, est_req_tpl.format(seq=101, node_id=flow_key_1[0]), ts, 10)
    aggregator.process_message(flow_key_1, est_rsp_tpl.format(seq=101, node_id=flow_key_1[2]), ts + 0.005, 11)
    aggregator.process_message(flow_key_1, mod_req_tpl.format(seq=102, node_id=flow_key_1[0]), ts + 1.0, 20)
    aggregator.process_message(flow_key_1, mod_rsp_fail_tpl.format(seq=102, node_id=flow_key_1[2]), ts + 1.015, 21)

    logging.info("\n--- Test Case 2: Transactions on a separate flow (Flow 2) ---")
    aggregator.process_message(flow_key_2, est_req_tpl.format(seq=1, node_id=flow_key_2[0]), ts + 2.0, 30)
    aggregator.process_message(flow_key_2, est_rsp_tpl.format(seq=1, node_id=flow_key_2[2]), ts + 2.008, 31)
    aggregator.process_message(flow_key_2, del_req_tpl.format(seq=2, node_id=flow_key_2[0]), ts + 3.0, 40)
    aggregator.process_message(flow_key_2, del_rsp_tpl.format(seq=2, node_id=flow_key_2[2]), ts + 3.004, 41)

    logging.info("\n--- Test Case 3: Out-of-order response ---")
    aggregator.process_message(flow_key_1, est_rsp_tpl.format(seq=301, node_id=flow_key_1[2]), ts + 4.0, 50)
    aggregator.process_message(flow_key_1, est_req_tpl.format(seq=301, node_id=flow_key_1[0]), ts + 4.1, 51)

    logging.info("\n--- Test Case 4: Duplicate request (Retransmission) ---")
    aggregator.process_message(flow_key_1, mod_req_tpl.format(seq=401, node_id=flow_key_1[0]), ts + 5.0, 60)
    aggregator.process_message(flow_key_1, mod_req_tpl.format(seq=401, node_id=flow_key_1[0]), ts + 5.5, 61)
    # The response here has an incorrect node ID and should be discarded
    aggregator.process_message(flow_key_1, est_rsp_tpl.format(seq=401, node_id="1.2.3.4"), ts + 5.6, 62)

    logging.info("\n--- Test Case 5: Unmatched response (No request ever sent) ---")
    aggregator.process_message(flow_key_2, del_rsp_tpl.format(seq=999, node_id=flow_key_2[2]), ts + 6.0, 70)

    logging.info("\n--- Test Case 6: Mismatched Node ID on Request ---")
    # This request has a node ID that does not match the source of flow_key_1, so it should be discarded
    aggregator.process_message(flow_key_1, est_req_tpl.format(seq=501, node_id="1.2.3.4"), ts + 7.0, 80)
    # This response will be ignored as the request was never processed.
    aggregator.process_message(flow_key_1, est_rsp_tpl.format(seq=501, node_id=flow_key_1[2]), ts + 7.1, 81)

    # --- Display Aggregated DataFrame Results ---
    logging.info("\n--- Aggregated DataFrame Results ---")
    dataframes = aggregator.get_all_data()

    print("\n\n--- Completed Measurements (PFCP Transactions) ---")
    print(dataframes["measurements"])

    print("\n\n--- Transaction Statistics by Flow ---")
    print(dataframes["statistics"])

    print("\n\n--- Protocol Counters by Flow ---")
    print(dataframes["counters"])

    print("\n\n--- Verifying Final State (Active Transactions) ---")
    print(
        f"Flow 1: {sorted([t.sequence_number for t in aggregator.managers[flow_key_1].active_transactions.values()])}")
    print(
        f"Flow 2: {sorted([t.sequence_number for t in aggregator.managers[flow_key_2].active_transactions.values()])}")

