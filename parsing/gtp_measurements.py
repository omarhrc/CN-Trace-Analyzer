# gtp_measurements.py

import logging
import re
from datetime import datetime
from enum import Enum
from collections import defaultdict, namedtuple
import pandas as pd
from parsing.common import ProcedureDescription, ProcedureMeasurement


class GtpMessageType(Enum):
    """Enumerates the high-level types of GTP messages."""
    REQUEST = "Request"
    RESPONSE = "Response"
    UNKNOWN = "Unknown"


class GtpProcedureMeasurement(ProcedureMeasurement):
    """
    Measures GTPv2 transaction response time.
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
        logging.debug(f"[{self.sequence_number}] GTP transaction ended. Success: {self.success}")

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
        """Processes a GTP Response message based on its Cause value."""
        if cause.lower() == 'request accepted':
            event, counter_name = 'event_success_response', "Success (Request Accepted)"
        else:
            event, counter_name = 'event_failure_response', f"Failure ({cause})"

        if self.state in self.get_valid_sources_for_trigger(event):
            self.trigger(event, counter_name=counter_name, **kwargs)


class GtpSuccessRateMeasurement:
    """A simple accumulator for GTPv2 transaction success and failure statistics."""

    def __init__(self, name="GTPv2 Success Rate"):
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


class GtpFlowManager:
    """Manages multiple concurrent GTPv2 transaction measurements for a single flow."""

    def __init__(self, flow_key: tuple):
        self.flow_key = flow_key
        self.active_transactions: dict[int, GtpProcedureMeasurement] = {}  # Keyed by Sequence Number
        self.completed_procedures: list[ProcedureDescription] = []
        self.success_rate_tracker = GtpSuccessRateMeasurement()
        self.protocol_counters = defaultdict(int)

    def process_gtp_message(self, message_type: GtpMessageType, full_message_type: str, sequence_number: int,
                            cause: str = None, **kwargs):
        """Routes a GTP message to the correct measurement instance."""
        self.protocol_counters[full_message_type] += 1
        if cause:
            self.protocol_counters[f"Cause-{cause}"] += 1

        if message_type == GtpMessageType.REQUEST:
            if sequence_number in self.active_transactions:
                logging.warning(f"Duplicate Sequence Number {sequence_number} seen in a new request. Overwriting.")

            procedure_name = full_message_type.replace(" Request", "")
            measurement = GtpProcedureMeasurement(sequence_number, procedure_name)
            measurement.trigger('event_request', **kwargs)
            self.active_transactions[sequence_number] = measurement
            self.success_rate_tracker.record_attempt()

        elif message_type == GtpMessageType.RESPONSE:
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


class GtpMeasurementAggregator:
    """
    Manages GTPv2 measurements across multiple traffic flows and returns data as pandas DataFrames.
    """

    def __init__(self):
        self.managers: dict[tuple, GtpFlowManager] = {}

    def _get_or_create_manager(self, key: tuple) -> GtpFlowManager:
        if key not in self.managers:
            logging.info(f"Creating new GtpFlowManager for key: {key}")
            self.managers[key] = GtpFlowManager(flow_key=key)
        return self.managers[key]

    def _parse_gtp_message(self, raw_message: str) -> dict:
        """
        Simulates parsing of a GTPv2 message from a human-readable format.
        """
        info = {'message_type': GtpMessageType.UNKNOWN, 'full_message_type': 'Unknown',
                'sequence_number': None, 'cause': None}

        if type_match := re.search(r"Message Type:\s*(.+)", raw_message, re.IGNORECASE):
            info['full_message_type'] = type_match.group(1).strip()
            if "Response" in info['full_message_type']:
                info['message_type'] = GtpMessageType.RESPONSE
            elif "Request" in info['full_message_type']:
                info['message_type'] = GtpMessageType.REQUEST

        if seq_match := re.search(r'Sequence Number:\s*(?:0x[0-9a-fA-F]+)\s*\((\d+)\)', raw_message, re.IGNORECASE):
            info['sequence_number'] = int(seq_match.group(1))

        if cause_match := re.search(r"Cause:\s*(.+)", raw_message, re.IGNORECASE):
            info['cause'] = cause_match.group(1).strip()

        return info

    def process_message(self, key: tuple, msg_from_flow_originator: bool, raw_gtp_message: str, timestamp: float,
                        frame: int):
        """
        Processes a raw GTPv2 message for a given flow key, validating its direction.
        - msg_from_flow_originator: True if the message comes from the flow's source IP/port.
        """
        parsed_info = self._parse_gtp_message(raw_gtp_message)

        # Validate the direction of the message before creating a manager.
        message_type = parsed_info.get('message_type')
        if message_type == GtpMessageType.REQUEST and not msg_from_flow_originator:
            return  # Silently discard request coming from the wrong direction.
        if message_type == GtpMessageType.RESPONSE and msg_from_flow_originator:
            return  # Silently discard response coming from the wrong direction.

        # If direction is valid, only then get or create the manager.
        manager = self._get_or_create_manager(key)

        if parsed_info.get('sequence_number') is None:
            logging.warning(f"Could not find Sequence Number for key {key}. Skipping message.")
            return

        manager.process_gtp_message(
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

    aggregator = GtpMeasurementAggregator()

    # --- Define flow keys for testing ---
    flow_key_1 = ('10.10.10.1', 2123, '20.20.20.1', 2123, 'UDP', True)  # MME 1 -> SGW 1
    flow_key_2 = ('10.10.10.2', 2123, '20.20.20.2', 2123, 'UDP', True)  # MME 2 -> SGW 2

    # --- Mock GTPv2 Message Templates ---
    cs_req_tpl = "Message Type: Create Session Request\nSequence Number: {seq}"
    cs_rsp_tpl = "Message Type: Create Session Response\nSequence Number: {seq}\nCause: Request Accepted"
    mb_req_tpl = "Message Type: Modify Bearer Request\nSequence Number: {seq}"
    mb_rsp_fail_tpl = "Message Type: Modify Bearer Response\nSequence Number: {seq}\nCause: Context not found"

    ts = datetime.now().timestamp()

    # --- Simulation Test Cases ---
    logging.info("\n--- Test Case 1: Successful Create Session on Flow 1 ---")
    aggregator.process_message(flow_key_1, True, cs_req_tpl.format(seq=1001), ts, 1)
    aggregator.process_message(flow_key_1, False, cs_rsp_tpl.format(seq=1001), ts + 0.012, 2)  # 12ms

    logging.info("\n--- Test Case 2: Failed Modify Bearer on Flow 1 ---")
    aggregator.process_message(flow_key_1, True, mb_req_tpl.format(seq=1002), ts + 0.1, 3)
    aggregator.process_message(flow_key_1, False, mb_rsp_fail_tpl.format(seq=1002), ts + 0.130, 4)  # 30ms

    logging.info("\n--- Test Case 3: Successful transaction on Flow 2 ---")
    aggregator.process_message(flow_key_2, True, cs_req_tpl.format(seq=2001), ts + 0.2, 5)
    aggregator.process_message(flow_key_2, False, cs_rsp_tpl.format(seq=2001), ts + 0.215, 6)  # 15ms

    logging.info("\n--- Test Case 4: Retransmitted request followed by response ---")
    aggregator.process_message(flow_key_1, True, mb_req_tpl.format(seq=1004), ts + 0.4, 9)
    aggregator.process_message(flow_key_1, True, mb_req_tpl.format(seq=1004), ts + 0.42, 10)  # Retransmission
    aggregator.process_message(flow_key_1, False, cs_rsp_tpl.format(seq=1004), ts + 0.450, 11)  # Successful response

    logging.info("\n--- Test Case 5: Mismatched message direction (should be ignored) ---")
    # This is a request, but we are telling process_message it's from the destination (False). It should be discarded.
    aggregator.process_message(flow_key_1, False, cs_req_tpl.format(seq=3001), ts + 1.0, 12)
    # This response is from the originator (True), which is also wrong and should be discarded.
    aggregator.process_message(flow_key_1, True, cs_rsp_tpl.format(seq=3001), ts + 1.01, 13)

    # --- Display Aggregated DataFrame Results ---
    logging.info("\n--- Aggregated DataFrame Results ---")
    dataframes = aggregator.get_all_data()

    print("\n\n--- Completed Measurements (GTPv2 Transactions) ---")
    print(dataframes["measurements"])

    print("\n\n--- Transaction Statistics by Flow ---")
    print(dataframes["statistics"])

    print("\n\n--- Protocol Counters by Flow ---")
    print(dataframes["counters"])

    print("\n\n--- Verifying Final State (Active Transactions) ---")
    if flow_key_1 in aggregator.managers:
        print(
            f"Flow 1: {sorted([t.sequence_number for t in aggregator.managers[flow_key_1].active_transactions.values()])}")
    else:
        print("Flow 1: No active transactions.")
    if flow_key_2 in aggregator.managers:
        print(
            f"Flow 2: {sorted([t.sequence_number for t in aggregator.managers[flow_key_2].active_transactions.values()])}")
    else:
        print("Flow 2: No active transactions.")
