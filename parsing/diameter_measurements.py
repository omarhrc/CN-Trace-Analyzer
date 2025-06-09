import logging
import re
from datetime import datetime
from enum import Enum
from collections import defaultdict, namedtuple
import pandas as pd
from parsing.common import ProcedureDescription, ProcedureMeasurement


class DiameterMessageType(Enum):
    """Enumerates the types of Diameter messages for processing."""
    REQUEST = "Request"
    ANSWER = "Answer"
    UNKNOWN = "Unknown"


class DiameterProcedureMeasurement(ProcedureMeasurement):
    """
    Measures Diameter transaction response time using a simple state machine.
    A transaction is identified by its Hop-by-Hop Identifier.
    """
    states = ['INITIAL', 'REQUEST_SENT', 'SUCCESS', 'FAILED']
    transitions = [
        {'trigger': 'event_request', 'source': 'INITIAL', 'dest': 'REQUEST_SENT',
         'after': 'start_procedure_measurement'},
        {'trigger': 'event_success_answer', 'source': 'REQUEST_SENT', 'dest': 'SUCCESS',
         'after': 'end_procedure_measurement'},
        {'trigger': 'event_failure_answer', 'source': 'REQUEST_SENT', 'dest': 'FAILED',
         'after': 'end_procedure_measurement'},
    ]

    def __init__(self, hop_by_hop_id: str, command_code: str):
        self.hop_by_hop_id = hop_by_hop_id
        self.command_code = command_code
        procedure_name = f"Diameter {self.command_code}"
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
        logging.debug(f"[{self.hop_by_hop_id}] Diameter transaction ended. Success: {self.success}")

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

    def process_answer(self, result_code: int, **kwargs):
        """Processes a Diameter Answer message."""
        if 2000 <= result_code < 3000:
            event, counter_name = 'event_success_answer', f"Success ({result_code})"
        else:
            event, counter_name = 'event_failure_answer', f"Failure ({result_code})"

        if self.state in self.get_valid_sources_for_trigger(event):
            self.trigger(event, counter_name=counter_name, **kwargs)


class DiameterSuccessRateMeasurement:
    """A simple accumulator for Diameter transaction success and failure statistics."""

    def __init__(self, name="Diameter Success Rate"):
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


class DiameterFlowManager:
    """Manages multiple concurrent Diameter transaction measurements for a single flow."""

    def __init__(self, flow_key: tuple):
        self.flow_key = flow_key
        self.active_transactions: dict[str, DiameterProcedureMeasurement] = {}
        self.completed_procedures: list[ProcedureDescription] = []
        self.success_rate_tracker = DiameterSuccessRateMeasurement()
        self.protocol_counters = defaultdict(int)

    def process_diameter_message(self, message_type: DiameterMessageType, hop_by_hop_id: str, command_code: str,
                                 result_code: int = None, **kwargs):
        """Routes a Diameter message to the correct measurement instance."""
        self.protocol_counters[command_code] += 1
        if result_code:
            self.protocol_counters[f"Result-Code-{result_code}"] += 1

        if message_type == DiameterMessageType.REQUEST:
            if hop_by_hop_id in self.active_transactions:
                logging.warning(f"Duplicate Hop-by-Hop-ID {hop_by_hop_id} seen in a new request. Overwriting.")

            measurement = DiameterProcedureMeasurement(hop_by_hop_id, command_code)
            measurement.trigger('event_request', **kwargs)  # Start the measurement
            self.active_transactions[hop_by_hop_id] = measurement
            self.success_rate_tracker.record_attempt()

        elif message_type == DiameterMessageType.ANSWER:
            measurement = self.active_transactions.get(hop_by_hop_id)
            if not measurement:
                logging.warning(f"Received an answer for an unknown Hop-by-Hop-ID: {hop_by_hop_id}")
                return

            measurement.process_answer(result_code, **kwargs)
            if measurement.is_measurement_finished():
                if measurement.success:
                    self.success_rate_tracker.record_success()
                else:
                    self.success_rate_tracker.record_failure(measurement.termination_reason)

                if completed_data := measurement.get_measurement():
                    self.completed_procedures.append(completed_data._replace(key=self.flow_key))

                del self.active_transactions[hop_by_hop_id]

    def get_all_completed_procedures(self) -> list[ProcedureDescription]:
        return self.completed_procedures

    def get_success_rate_statistics(self) -> dict:
        return self.success_rate_tracker.get_statistics()

    def get_protocol_counters(self) -> dict:
        return dict(self.protocol_counters)


class DiameterMeasurementAggregator:
    """
    Manages Diameter measurements across multiple traffic flows and returns data as pandas DataFrames.
    """

    def __init__(self):
        self.managers: dict[tuple, DiameterFlowManager] = {}

    def _get_or_create_manager(self, key: tuple) -> DiameterFlowManager:
        if key not in self.managers:
            logging.info(f"Creating new DiameterFlowManager for key: {key}")
            self.managers[key] = DiameterFlowManager(flow_key=key)
        return self.managers[key]

    def _parse_diameter_message(self, raw_message: str) -> dict:
        """
        Simulates parsing of a Diameter message. In a real scenario, this would handle binary AVPs.
        Here, we use regex on a simplified string format for demonstration.
        """
        info = {'message_type': DiameterMessageType.UNKNOWN, 'hop_by_hop_id': None, 'command_code': 'Unknown',
                'result_code': None}

        if hbh_match := re.search(r"Hop-by-Hop Identifier:\s*(\S+)", raw_message, re.IGNORECASE):
            info['hop_by_hop_id'] = hbh_match.group(1)

        if cmd_match := re.search(r"Command Code: (.*?)\s*\((\d+)\)", raw_message, re.IGNORECASE):
            info['command_code'] = cmd_match.group(2)  # e.g., '272'

        # 'Request: Set' determines message type
        if re.search(r"Request: Set", raw_message, re.IGNORECASE):
            info['message_type'] = DiameterMessageType.REQUEST
        else:
            info['message_type'] = DiameterMessageType.ANSWER

        if rc_match := re.search(r"Result-Code: (.*?)\s*\((\d+)\)", raw_message, re.IGNORECASE):
            info['result_code'] = int(rc_match.group(2)) # e.g., 2001

        return info

    def process_message(self, key: tuple, raw_diameter_message: str, timestamp: float, frame: int):
        """Processes a raw Diameter message for a given flow key."""
        manager = self._get_or_create_manager(key)
        parsed_info = self._parse_diameter_message(raw_diameter_message)

        if not parsed_info.get('hop_by_hop_id'):
            logging.warning(f"Could not find Hop-by-Hop-ID for key {key}. Skipping message.")
            return

        manager.process_diameter_message(
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

    aggregator = DiameterMeasurementAggregator()
    # A key representing a specific Diameter client-server flow
    flow_key = ('10.1.1.1', 3868, '10.2.2.2', 3868, 'SCTP', True)

    # --- Mock Diameter Message Templates (ADJUSTED FOR NEW REGEX) ---
    # Credit-Control-Request (CCR)
    ccr_tpl = """
    Request: Set
    Hop-by-Hop Identifier: {hbh_id}
    Command Code: Credit-Control (272)
    """
    # Credit-Control-Answer (CCA) - Success
    cca_success_tpl = """
    Request: Not Set
    Hop-by-Hop Identifier: {hbh_id}
    Command Code: Credit-Control (272)
    Result-Code: DIAMETER_SUCCESS (2001)
    """
    # Credit-Control-Answer (CCA) - Failure
    cca_failure_tpl = """
    Request: Not Set
    Hop-by-Hop Identifier: {hbh_id}
    Command Code: Credit-Control (272)
    Result-Code: DIAMETER_USER_UNKNOWN (5030)
    """

    ts = datetime.now().timestamp()

    # --- Simulation (No changes needed here) ---
    logging.info("\n--- Simulating a successful Diameter transaction ---")
    aggregator.process_message(flow_key, ccr_tpl.format(hbh_id='111'), ts, 10)
    aggregator.process_message(flow_key, cca_success_tpl.format(hbh_id='111'), ts + 0.05, 11)

    logging.info("\n--- Simulating a failed Diameter transaction ---")
    aggregator.process_message(flow_key, ccr_tpl.format(hbh_id='222'), ts + 1.0, 20)
    aggregator.process_message(flow_key, cca_failure_tpl.format(hbh_id='222'), ts + 1.15, 21)

    logging.info("\n--- Simulating another successful transaction ---")
    aggregator.process_message(flow_key, ccr_tpl.format(hbh_id='333'), ts + 2.0, 30)
    aggregator.process_message(flow_key, cca_success_tpl.format(hbh_id='333'), ts + 2.06, 31)

    # --- Display Aggregated DataFrame Results ---
    logging.info("\n--- Aggregated DataFrame Results ---")
    dataframes = aggregator.get_all_data()

    print("\n--- Completed Measurements (Transactions) ---")
    print(dataframes["measurements"])

    print("\n\n--- Transaction Statistics by Flow ---")
    print(dataframes["statistics"])

    print("\n\n--- Protocol Counters by Flow ---")
    print(dataframes["counters"])