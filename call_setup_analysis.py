import pandas as pd
import sys
import os
import re
import subprocess
import numpy as np
import argparse
import json
from glob import glob
from io import StringIO
from typing import Tuple, Dict, Optional, List


def load_node_map(filepath: str) -> Optional[Tuple[Dict, Dict]]:
    """
    Loads a map of IPs to names and a map of specific names to a canonical name.

    Args:
        filepath: The path to the hosts file.

    Returns:
        A tuple containing (ip_to_specific_name, specific_name_to_canonical_name),
        or (None, None) if the file is not found.
    """
    if not os.path.exists(filepath):
        print(f"[!] Error: Hosts file not found at '{filepath}'")
        return None, None

    ip_to_specific_name, specific_name_to_canonical_name = {}, {}
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, canonical_name = parts[0], parts[1]
                        specific_name = parts[2] if len(parts) > 2 else canonical_name
                        ip_to_specific_name[ip] = specific_name
                        specific_name_to_canonical_name[specific_name] = canonical_name
    except Exception as e:
        print(f"[!] Error reading hosts file: {e}")
        return None, None

    print(f"[*] Loaded {len(ip_to_specific_name)} IP-to-Node mappings from '{filepath}'")
    return ip_to_specific_name, specific_name_to_canonical_name


def load_cdr_data(filepath: str) -> Optional[Dict]:
    """
    Loads CDR data from an Excel file, creating a map from RowID to call details.

    Args:
        filepath: The path to the CDR Excel file.

    Returns:
        A dictionary containing CDR entries and the average duration, or None on failure.
    """
    if not filepath or not os.path.exists(filepath):
        print(f"[*] CDR file not provided or not found. Non-SIP traces will be skipped.")
        return None

    print(f"[*] Loading CDR data from '{filepath}'...")
    try:
        df = pd.read_excel(filepath)

        duration_col_name = "Call Setup Duration"
        required_cols = ["RowID", "Call Setup Start (Dialing)", duration_col_name]

        legacy_duration_col = "Call Setup Duration (OptionD) [s]"
        if duration_col_name not in df.columns and legacy_duration_col in df.columns:
            print(f"[*] Note: Found legacy column name '{legacy_duration_col}'. Using it for this run.")
            duration_col_name = legacy_duration_col
            required_cols = ["RowID", "Call Setup Start (Dialing)", legacy_duration_col]

        if not all(col in df.columns for col in required_cols):
            print(f"[!] Error: CDR file '{filepath}' must contain columns: {required_cols}")
            return None

        start_col = "Call Setup Start (Dialing)"

        average_duration = df[duration_col_name].mean()
        if pd.isna(average_duration):
            print(
                f"[!] Warning: Could not calculate average from '{duration_col_name}'. Non-SIP traces with missing durations will be skipped.")
            average_duration = np.nan

        df[start_col] = pd.to_datetime(df[start_col], errors='coerce')
        df['RowID'] = df['RowID'].astype(str)

        cdr_data = {'__average_duration__': average_duration, 'entries': {}}

        for index, row in df.iterrows():
            row_id = row['RowID']
            start_time = row[start_col]
            duration = row[duration_col_name]

            if pd.notna(row_id) and pd.notna(start_time):
                cdr_data['entries'][row_id] = {
                    'start': start_time,
                    'duration': duration if pd.notna(duration) else np.nan
                }

        print(f"[*] Loaded {len(cdr_data['entries'])} CDR entries. Average duration: {average_duration:.4f}s")
        return cdr_data

    except Exception as e:
        print(f"[!] Error loading or processing CDR file: {e}")
        return None


def get_tshark_data(pcap_file: str) -> pd.DataFrame:
    """
    Runs a single, comprehensive tshark command to get all necessary fields from a pcap file.

    Args:
        pcap_file: The path to the pcap file.

    Returns:
        A pandas DataFrame containing the parsed packet data, or an empty DataFrame on error.
    """
    print(f"[*] Reading all relevant packets from {os.path.basename(pcap_file)}...")

    tshark_filter = "sip or s1ap or ngap or pfcp or gtpv2 or diameter or http2"
    fields = [
        "frame.number", "frame.time_epoch", "frame.protocols", "_ws.col.Info",
        "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
        "sip.Call-ID", "sip.from.tag",
        "diameter.applicationId", "diameter.cmd.code", "diameter.Session-Id",
        "diameter.hopbyhopid", "diameter.endtoendid",
        "http2.headers.path", "http2.headers.method", "http2.streamid", "http2.headers.status", "json",
        "ngap.AMF_UE_NGAP_ID", "ngap.RAN_UE_NGAP_ID",
        "s1ap.MME_UE_S1AP_ID", "s1ap.ENB_UE_S1AP_ID",
        "pfcp.seid", "pfcp.seqno", "pfcp.msg_type",  # Corrected PFCP fields
        "gtpv2.seq", "gtpv2.message_type", "gtpv2.teid"
    ]

    command = ["tshark", "-r", pcap_file, "-Y", tshark_filter, "-T", "fields", "-E", "separator=\t", "-E",
               "occurrence=f"]
    for field in fields:
        command.extend(["-e", field])

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, encoding='utf-8', errors='ignore')

        if result.stderr:
            print(f"      [d] Tshark STDERR for {os.path.basename(pcap_file)}:\n          {result.stderr.strip()}")

        if result.returncode != 0 and "aren't valid" not in result.stderr:
            print(f"      [!] Tshark command exited with non-zero code ({result.returncode})")

        if not result.stdout:
            print(
                f"      [!] No tshark output for {os.path.basename(pcap_file)}. This might be due to an invalid field or no matching packets.")
            return pd.DataFrame()

        df = pd.read_csv(StringIO(result.stdout), sep='\t', header=None, names=fields, na_values=[''],
                         keep_default_na=True, quoting=3)
        return df
    except FileNotFoundError:
        print("[!] CRITICAL ERROR: 'tshark' command not found. Please ensure it's in your system's PATH.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An error occurred while running tshark: {e}")
        return pd.DataFrame()


def prepare_dataframe(df: pd.DataFrame, ip_to_specific_name: dict, specific_to_canonical: dict) -> pd.DataFrame:
    """
    Cleans and prepares the raw DataFrame from tshark, adding timestamps and node names.

    Args:
        df: The raw DataFrame from get_tshark_data.
        ip_to_specific_name: Mapping of IP to specific node name.
        specific_to_canonical: Mapping of specific node name to canonical name.

    Returns:
        A cleaned and enriched pandas DataFrame.
    """
    if df.empty:
        return df

    master = df.copy()
    print(f"[*] Preparing data for {len(master)} parsed packets...")

    master['timestamp'] = pd.to_datetime(master['frame.time_epoch'], unit='s', errors='coerce')
    master['app_id'] = pd.to_numeric(master['diameter.applicationId'], errors='coerce')
    master['cmd_code'] = pd.to_numeric(master['diameter.cmd.code'], errors='coerce')
    master['http2.streamid'] = pd.to_numeric(master['http2.streamid'], errors='coerce')
    master['pfcp.msg_type'] = pd.to_numeric(master['pfcp.msg_type'], errors='coerce')  # Corrected PFCP field
    master['gtpv2.message_type'] = pd.to_numeric(master['gtpv2.message_type'], errors='coerce')

    master['src_ip'] = np.where(master['ip.src'].notna(), master['ip.src'], master['ipv6.src'])
    master['dst_ip'] = np.where(master['ip.dst'].notna(), master['ip.dst'], master['ipv6.dst'])

    master['src_node'] = master['src_ip'].map(ip_to_specific_name).fillna(master['src_ip'])
    master['dst_node'] = master['dst_ip'].map(ip_to_specific_name).fillna(master['dst_ip'])
    master['src_canonical_node'] = master['src_node'].map(specific_to_canonical).fillna(master['src_node'])
    master['dst_canonical_node'] = master['dst_node'].map(specific_to_canonical).fillna(master['dst_node'])

    PROTOCOLS_OF_INTEREST = ['SIP', 'HTTP2', 'DIAMETER', 'PFCP', 'NGAP', 'S1AP', 'GTPV2']

    def find_primary_protocol(protocol_string: str) -> str:
        packet_protocols = str(protocol_string).upper().split(':')
        for protocol in PROTOCOLS_OF_INTEREST:
            if protocol in packet_protocols:
                return protocol
        return 'UNKNOWN'

    master['protocol'] = master['frame.protocols'].apply(find_primary_protocol)
    master.rename(columns={'_ws.col.Info': 'info'}, inplace=True)
    master.sort_values(by='timestamp', inplace=True, ignore_index=True)
    master.dropna(subset=['timestamp', 'src_ip', 'dst_ip'], inplace=True)

    return master


def analyze_domain_time(domain_df: pd.DataFrame) -> Tuple[float, Dict[str, float]]:
    """
    Calculates per-node processing time. For request/response protocols, it's the
    request-to-response time. For flow-based SIP, it's the time between a node
    receiving a packet and sending the next one.

    Args:
        domain_df: A DataFrame filtered to include only packets for a specific domain.

    Returns:
        A tuple containing (total_domain_time, dictionary_of_node_contributions).
    """
    if domain_df.empty:
        return 0.0, {}

    node_processing_time = {}

    # --- 1. Flow-based protocol (SIP) ---
    flow_df = domain_df[domain_df['protocol'] == 'SIP'].copy().sort_values(by='timestamp', ignore_index=True)
    if not flow_df.empty:
        last_arrival_at = {}
        for index, row in flow_df.iterrows():
            src_node = row['src_canonical_node']
            dst_node = row['dst_canonical_node']
            timestamp = row['timestamp']
            if src_node in last_arrival_at:
                processing_time = (timestamp - last_arrival_at[src_node]).total_seconds()
                if processing_time >= 0:
                    node_processing_time[src_node] = node_processing_time.get(src_node, 0) + processing_time
                del last_arrival_at[src_node]
            if dst_node:
                last_arrival_at[dst_node] = timestamp

    # --- 2. Request/Response Protocols ---
    req_res_df = domain_df[domain_df['protocol'] != 'SIP'].copy()

    # --- HTTP/2 ---
    h2_df = req_res_df[req_res_df['protocol'] == 'HTTP2'].copy()
    if not h2_df.empty and 'http2.streamid' in h2_df.columns:
        h2_df.dropna(subset=['http2.streamid'], inplace=True)
        requests = h2_df[h2_df['http2.headers.method'].notna()].drop_duplicates(subset=['http2.streamid'], keep='first')
        responses = h2_df[h2_df['http2.headers.status'].notna()].drop_duplicates(subset=['http2.streamid'],
                                                                                 keep='first')
        if not requests.empty and not responses.empty:
            merged = pd.merge(requests[['timestamp', 'http2.streamid', 'dst_canonical_node']],
                              responses[['timestamp', 'http2.streamid', 'src_canonical_node']], on='http2.streamid',
                              suffixes=('_req', '_res'))
            valid = merged[merged['dst_canonical_node'] == merged['src_canonical_node']].copy()
            valid['delta'] = (valid['timestamp_res'] - valid['timestamp_req']).dt.total_seconds()
            valid = valid[valid['delta'] >= 0]
            for _, row in valid.iterrows():
                node_processing_time[row['dst_canonical_node']] = node_processing_time.get(row['dst_canonical_node'],
                                                                                           0) + row['delta']

    # --- Diameter ---
    dia_df = req_res_df[req_res_df['protocol'] == 'DIAMETER'].copy()
    if not dia_df.empty and 'diameter.hopbyhopid' in dia_df.columns:
        requests = dia_df[~dia_df['info'].str.contains("answer", case=False, na=False)].drop_duplicates(
            subset=['diameter.hopbyhopid'], keep='first')
        answers = dia_df[dia_df['info'].str.contains("answer", case=False, na=False)].drop_duplicates(
            subset=['diameter.hopbyhopid'], keep='first')
        if not requests.empty and not answers.empty:
            merged = pd.merge(requests[['timestamp', 'diameter.hopbyhopid', 'dst_canonical_node']],
                              answers[['timestamp', 'diameter.hopbyhopid', 'src_canonical_node']],
                              on='diameter.hopbyhopid', suffixes=('_req', '_ans'))
            valid = merged[merged['dst_canonical_node'] == merged['src_canonical_node']].copy()
            valid['delta'] = (valid['timestamp_ans'] - valid['timestamp_req']).dt.total_seconds()
            valid = valid[valid['delta'] >= 0]
            for _, row in valid.iterrows():
                node_processing_time[row['dst_canonical_node']] = node_processing_time.get(row['dst_canonical_node'],
                                                                                           0) + row['delta']

    # --- RAN Protocols (NGAP/S1AP) ---
    for proto, id_cols, req_str, res_str in [
        ('NGAP', ['ngap.AMF_UE_NGAP_ID', 'ngap.RAN_UE_NGAP_ID'], "Request", "Response"),
        ('S1AP', ['s1ap.MME_UE_S1AP_ID', 's1ap.ENB_UE_S1AP_ID'], "Request", "Response")]:
        ran_df = req_res_df[req_res_df['protocol'] == proto].copy()
        if not ran_df.empty:
            ran_df.dropna(subset=id_cols, inplace=True)
            if ran_df.empty: continue
            requests = ran_df[ran_df['info'].str.contains(req_str, na=False)].sort_values('timestamp')
            responses = ran_df[ran_df['info'].str.contains(res_str, na=False)].sort_values('timestamp')
            if not requests.empty and not responses.empty:
                unmatched_responses = responses.to_dict('records')
                for _, request in requests.iterrows():
                    for i, response in enumerate(unmatched_responses):
                        if (response['timestamp'] > request['timestamp'] and response[id_cols[0]] == request[
                            id_cols[0]] and response[id_cols[1]] == request[id_cols[1]]):
                            delta = (response['timestamp'] - request['timestamp']).total_seconds()
                            node_processing_time[request['dst_canonical_node']] = node_processing_time.get(
                                request['dst_canonical_node'], 0) + delta
                            unmatched_responses.pop(i)
                            break

    # --- PFCP ---
    pfcp_df = req_res_df[req_res_df['protocol'] == 'PFCP'].copy()
    if not pfcp_df.empty and 'pfcp.seid' in pfcp_df.columns:
        pfcp_df.dropna(subset=['pfcp.seid', 'pfcp.seqno', 'pfcp.msg_type'], inplace=True)
        requests = pfcp_df[pfcp_df['pfcp.msg_type'].isin([50, 52, 54])].drop_duplicates(['pfcp.seid', 'pfcp.seqno'])
        responses = pfcp_df[pfcp_df['pfcp.msg_type'].isin([51, 53, 55])].drop_duplicates(['pfcp.seid', 'pfcp.seqno'])
        if not requests.empty and not responses.empty:
            merged = pd.merge(requests, responses, on=['pfcp.seid', 'pfcp.seqno'], suffixes=('_req', '_res'))
            valid = merged[merged['pfcp.msg_type_res'] == merged['pfcp.msg_type_req'] + 1].copy()
            valid['delta'] = (valid['timestamp_res'] - valid['timestamp_req']).dt.total_seconds()
            valid = valid[valid['delta'] >= 0]
            for _, row in valid.iterrows():
                node_processing_time[row['dst_canonical_node_req']] = node_processing_time.get(
                    row['dst_canonical_node_req'], 0) + row['delta']

    # --- GTPv2 ---
    gtpv2_df = req_res_df[req_res_df['protocol'] == 'GTPV2'].copy()
    if not gtpv2_df.empty and 'gtpv2.seq' in gtpv2_df.columns:
        gtpv2_df.dropna(subset=['gtpv2.seq', 'gtpv2.teid', 'gtpv2.message_type'], inplace=True)
        requests = gtpv2_df[gtpv2_df['gtpv2.message_type'].isin([32, 34])].drop_duplicates(['gtpv2.teid', 'gtpv2.seq'])
        responses = gtpv2_df[gtpv2_df['gtpv2.message_type'].isin([33, 35])].drop_duplicates(['gtpv2.teid', 'gtpv2.seq'])
        if not requests.empty and not responses.empty:
            merged = pd.merge(requests, responses, on=['gtpv2.teid', 'gtpv2.seq'], suffixes=('_req', '_res'))
            valid = merged[merged['gtpv2.message_type_res'] == merged['gtpv2.message_type_req'] + 1].copy()
            valid['delta'] = (valid['timestamp_res'] - valid['timestamp_req']).dt.total_seconds()
            valid = valid[valid['delta'] >= 0]
            for _, row in valid.iterrows():
                node_processing_time[row['dst_canonical_node_req']] = node_processing_time.get(
                    row['dst_canonical_node_req'], 0) + row['delta']

    total_time = sum(node_processing_time.values())
    return total_time, node_processing_time


def analyze_rx_timing(analysis_window_df: pd.DataFrame) -> float:
    """
    Analyzes Diameter Rx timing by pairing AAR/AAA and returns the sum of transaction times.

    Args:
        analysis_window_df: The DataFrame containing packets in the analysis window.

    Returns:
        The sum of time deltas (in seconds) for all completed AAR-AAA pairs.
    """
    AAR_CODE = 265
    RX_APP_ID = 16777236

    rx_df = analysis_window_df[
        (analysis_window_df['app_id'] == RX_APP_ID) &
        (analysis_window_df['cmd_code'] == AAR_CODE) &
        (analysis_window_df['diameter.hopbyhopid'].notna())
        ].copy()

    if rx_df.empty: return 0.0

    requests = rx_df[~rx_df['info'].str.contains("answer", case=False, na=False)]
    answers = rx_df[rx_df['info'].str.contains("answer", case=False, na=False)]

    if requests.empty or answers.empty: return 0.0

    merge_cols = ['diameter.Session-Id', 'diameter.hopbyhopid', 'diameter.endtoendid']
    merged = pd.merge(requests[['timestamp'] + merge_cols], answers[['timestamp'] + merge_cols], on=merge_cols,
                      suffixes=('_req', '_ans'))
    if merged.empty: return 0.0

    merged = merged[merged['timestamp_ans'] > merged['timestamp_req']]
    if merged.empty: return 0.0

    merged['delta'] = (merged['timestamp_ans'] - merged['timestamp_req']).dt.total_seconds()
    return merged['delta'].sum()


def analyze_h2_pcf_timing(analysis_window_df: pd.DataFrame) -> Tuple[float, int]:
    """
    Analyzes HTTP/2 timing by pairing deduplicated PCF notifications with deduplicated
    SM Policy control messages and summing the transaction times.

    Args:
        analysis_window_df: The DataFrame for the analysis window.

    Returns:
        A tuple of (total_time, matched_pairs_count).
    """
    total_time = 0.0
    h2_df = analysis_window_df[analysis_window_df['protocol'] == 'HTTP2'].copy()
    h2_df.dropna(subset=['http2.headers.path'], inplace=True)
    if h2_df.empty: return 0.0, 0

    notification_path = "/notifications/pcf/policycontrol-update/v1/referenceid/"
    policy_control_path = "/npcf-smpolicycontrol/v1/sm-policies/"

    all_notifications = h2_df[h2_df['http2.headers.path'].str.startswith(notification_path)]
    all_policies = h2_df[h2_df['http2.headers.path'].str.startswith(policy_control_path)]

    unique_notifications = all_notifications.drop_duplicates(subset=['http2.headers.path', 'json'],
                                                             keep='first').sort_values(by='timestamp')
    unique_policies = all_policies.drop_duplicates(subset=['http2.headers.path', 'json'], keep='first').sort_values(
        by='timestamp')

    if unique_notifications.empty or unique_policies.empty:
        return 0.0, 0

    unmatched_policies = unique_policies.to_dict('records')
    matched_pairs = 0

    for idx, notification in unique_notifications.iterrows():
        for i, policy in enumerate(unmatched_policies):
            if policy['timestamp'] > notification['timestamp']:
                delta = (policy['timestamp'] - notification['timestamp']).total_seconds()
                total_time += delta
                matched_pairs += 1
                unmatched_policies.pop(i)
                break

    return total_time, matched_pairs


def analyze_ngap_radio_timing(analysis_window_df: pd.DataFrame) -> Tuple[float, int]:
    """
    Analyzes NGAP timing by pairing PDUSessionResourceModifyRequest with a
    corresponding Response and summing the transaction times.

    Args:
        analysis_window_df: The DataFrame for the analysis window.

    Returns:
        A tuple of (total_time, matched_pairs_count).
    """
    total_time = 0.0
    ngap_df = analysis_window_df[analysis_window_df['protocol'] == 'NGAP'].copy()

    amf_id_col = 'ngap.AMF_UE_NGAP_ID'
    ran_id_col = 'ngap.RAN_UE_NGAP_ID'

    ngap_df.dropna(subset=[amf_id_col, ran_id_col], inplace=True)
    if ngap_df.empty:
        return 0.0, 0

    requests = ngap_df[ngap_df['info'].str.contains("PDUSessionResourceModifyRequest", na=False)].sort_values(
        by='timestamp')
    responses = ngap_df[ngap_df['info'].str.contains("PDUSessionResourceModifyResponse", na=False)].sort_values(
        by='timestamp')

    if requests.empty or responses.empty:
        return 0.0, 0

    unmatched_responses = responses.to_dict('records')
    matched_pairs = 0

    for idx, request in requests.iterrows():
        for i, response in enumerate(unmatched_responses):
            if response['timestamp'] > request['timestamp'] and \
                    response[amf_id_col] == request[amf_id_col] and \
                    response[ran_id_col] == request[ran_id_col]:
                delta = (response['timestamp'] - request['timestamp']).total_seconds()
                total_time += delta
                matched_pairs += 1
                unmatched_responses.pop(i)
                break

    return total_time, matched_pairs


def analyze_s1ap_radio_timing(analysis_window_df: pd.DataFrame) -> Tuple[float, int]:
    """
    Analyzes S1AP timing by pairing E-RABSetupRequest with a
    corresponding Response and summing the transaction times.

    Args:
        analysis_window_df: The DataFrame for the analysis window.

    Returns:
        A tuple of (total_time, matched_pairs_count).
    """
    total_time = 0.0
    s1ap_df = analysis_window_df[analysis_window_df['protocol'] == 'S1AP'].copy()

    mme_id_col = 's1ap.MME_UE_S1AP_ID'
    enb_id_col = 's1ap.ENB_UE_S1AP_ID'

    s1ap_df.dropna(subset=[mme_id_col, enb_id_col], inplace=True)
    if s1ap_df.empty:
        return 0.0, 0

    requests = s1ap_df[s1ap_df['info'].str.contains("E-RABSetupRequest", na=False)].sort_values(by='timestamp')
    responses = s1ap_df[s1ap_df['info'].str.contains("E-RABSetupResponse", na=False)].sort_values(by='timestamp')

    if requests.empty or responses.empty:
        return 0.0, 0

    unmatched_responses = responses.to_dict('records')
    matched_pairs = 0

    for idx, request in requests.iterrows():
        for i, response in enumerate(unmatched_responses):
            if response['timestamp'] > request['timestamp'] and \
                    response[mme_id_col] == request[mme_id_col] and \
                    response[enb_id_col] == request[enb_id_col]:
                delta = (response['timestamp'] - request['timestamp']).total_seconds()
                total_time += delta
                matched_pairs += 1
                unmatched_responses.pop(i)
                break

    return total_time, matched_pairs


def process_pcap_file(pcap_file: str, ip_to_specific: dict, specific_to_canonical: dict, cdr_data: dict) -> Optional[
    Dict]:
    """
    Processes a single pcap file and returns a dictionary of results.
    """
    raw_df = get_tshark_data(pcap_file)
    if raw_df.empty:
        print(f"[!] Could not read any relevant packets from {os.path.basename(pcap_file)}. Skipping.")
        return None

    master_df = prepare_dataframe(raw_df, ip_to_specific, specific_to_canonical)
    if master_df.empty:
        print(f"[!] DataFrame is empty after preparation for {os.path.basename(pcap_file)}. Skipping.")
        return None

    IMS_DIAMETER_APP_IDS = {16777216, 16777236, 4, 16777217}

    invite_mask = master_df['info'].str.startswith("Request: INVITE", na=False)
    all_invites = master_df[invite_mask]

    call_setup_time = 0.0
    one_way_network_time = 0.0

    row_id_match = re.search(r'(Row\d+)', os.path.basename(pcap_file), re.IGNORECASE)
    row_id = row_id_match.group(1) if row_id_match else None

    if not all_invites.empty:
        print(f"[*] SIP INVITE found. Using SIP messages to define analysis window.")
        start_packet = all_invites.iloc[0]
        last_invite_packet = all_invites.iloc[-1]

        calling_party_ip = start_packet['src_ip']
        start_time = start_packet['timestamp']
        last_invite_time = last_invite_packet['timestamp']

        one_way_network_time = (last_invite_time - start_time).total_seconds()

        all_ringings = master_df[master_df['info'].str.contains("180 Ringing", na=False)]
        end_packet_df = all_ringings[all_ringings['dst_ip'] == calling_party_ip]

        if end_packet_df.empty:
            print(
                f"\n[!] Found INVITE but no '180 Ringing' for originator in {os.path.basename(pcap_file)}. Skipping file.")
            return None

        end_packet = end_packet_df.iloc[0]
        end_time = end_packet['timestamp']
        call_setup_time = (end_time - start_time).total_seconds()
        analysis_window_df = master_df[
            (master_df['timestamp'] >= start_time) & (master_df['timestamp'] <= end_time)].copy()

    else:
        print(f"[*] No SIP INVITE found. Using CDR data to define analysis window.")

        if not cdr_data:
            print("[!] No SIP and no CDR data loaded. Cannot define analysis window. Skipping.")
            return None

        if not row_id or row_id not in cdr_data['entries']:
            print(f"[!] No SIP and RowID '{row_id}' not found in CDR data. Cannot define analysis window. Skipping.")
            return None

        entry = cdr_data['entries'][row_id]
        start_time = entry['start']
        duration = entry['duration']

        if pd.isna(duration):
            duration = cdr_data.get('__average_duration__')
            if pd.isna(duration):
                print(f"[!] No SIP and no valid duration found for RowID '{row_id}' (and no average). Skipping.")
                return None
            print(f"    RowID '{row_id}' has no duration, using average: {duration:.4f}s")
        else:
            print(f"    Found RowID '{row_id}', using CDR start time '{start_time}' and duration: {duration:.4f}s")

        call_setup_time = duration
        end_time = start_time + pd.Timedelta(seconds=duration)
        analysis_window_df = master_df[
            (master_df['timestamp'] >= start_time) & (master_df['timestamp'] <= end_time)].copy()
        one_way_network_time = 0.0

    if analysis_window_df.empty:
        print(f"[!] No packets found in the determined analysis window for {os.path.basename(pcap_file)}. Skipping.")
        return None

    # --- Analyze Domains for Per-Node Contributions ---
    ims_mask = (analysis_window_df['protocol'] == 'SIP') | \
               ((analysis_window_df['protocol'] == 'DIAMETER') & (
                   analysis_window_df['app_id'].isin(IMS_DIAMETER_APP_IDS)))
    _, ims_node_contrib = analyze_domain_time(analysis_window_df[ims_mask])

    max_ims_time = 0.0
    max_ims_node = ""
    if ims_node_contrib:
        max_ims_node = max(ims_node_contrib, key=ims_node_contrib.get)
        max_ims_time = ims_node_contrib[max_ims_node]

    pc_base_protocols = ['HTTP2', 'PFCP', 'NGAP', 'S1AP', 'GTPV2']
    pc_mask = (analysis_window_df['protocol'].isin(pc_base_protocols)) | \
              ((analysis_window_df['protocol'] == 'DIAMETER') & (
                  ~analysis_window_df['app_id'].isin(IMS_DIAMETER_APP_IDS)))
    _, pc_node_contrib = analyze_domain_time(analysis_window_df[pc_mask])

    max_5gc_time = 0.0
    max_5gc_node = ""
    if pc_node_contrib:
        max_5gc_node = max(pc_node_contrib, key=pc_node_contrib.get)
        max_5gc_time = pc_node_contrib[max_5gc_node]

    # --- Analyze Transaction Timings ---
    total_rx_time = analyze_rx_timing(analysis_window_df)
    total_h2_pcf_time, h2_pairs_found = analyze_h2_pcf_timing(analysis_window_df)
    total_ngap_time, ngap_pairs_found = analyze_ngap_radio_timing(analysis_window_df)
    total_s1ap_time, s1ap_pairs_found = analyze_s1ap_radio_timing(analysis_window_df)

    # --- Compile results ---
    file_results = {
        "RowID": row_id,
        "File": os.path.basename(pcap_file),
        "Call Setup Time": call_setup_time,
        "One-way network time": one_way_network_time,
        "Max IMS Nodal Time": max_ims_time,
        "Max IMS Node": max_ims_node,
        "Max 5GC Nodal Time": max_5gc_time,
        "Max 5GC Node": max_5gc_node,
        "Total NGAP Time": total_ngap_time,
        "Total S1AP Time": total_s1ap_time,
        "Total Radio Time": total_ngap_time + total_s1ap_time,
        "Total Rx Time": total_rx_time,
        "Total PCF Notification-Policy Time": total_h2_pcf_time,
    }

    for node, time in ims_node_contrib.items():
        file_results[f"IMS: {node}"] = time

    for node, time in pc_node_contrib.items():
        file_results[f"5GC: {node}"] = time

    if not all_invites.empty:
        print(f"[+] Successfully processed {os.path.basename(pcap_file)}. Call Setup Time: {call_setup_time:.4f}s")
        print(f"    One-way network time (first to last INVITE): {one_way_network_time:.4f}s.")
    else:
        print(f"[+] Successfully processed {os.path.basename(pcap_file)} (PC-only, using CDR time).")

    if total_rx_time > 0:
        print(f"    Total Rx transaction time: {total_rx_time:.4f}s.")
    if h2_pairs_found > 0:
        print(f"    Found and timed {h2_pairs_found} unique H2 Notification-Policy pair(s).")
        print(f"    Total PCF Notification-Policy transaction time: {total_h2_pcf_time:.4f}s.")
    if ngap_pairs_found > 0:
        print(f"    Found and timed {ngap_pairs_found} NGAP PDU Session Modify pair(s).")
        print(f"    Total NGAP transaction time: {total_ngap_time:.4f}s.")
    if s1ap_pairs_found > 0:
        print(f"    Found and timed {s1ap_pairs_found} S1AP E-RAB Setup pair(s).")
        print(f"    Total S1AP transaction time: {total_s1ap_time:.4f}s.")

    return file_results


def main():
    """
    Main function to parse arguments, find files, process them, and write to Excel.
    """
    parser = argparse.ArgumentParser(
        description="Analyze call setup time from pcap files and export to Excel.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("hosts_file", help="Path to the hosts file for IP-to-name mapping.")
    parser.add_argument("pcap_directory", help="Directory containing pcap files to process (searches for '*.pcap*').")
    parser.add_argument("--cdr", help="Optional path to the CDR Excel file for advanced analysis.")
    parser.add_argument("-o", "--output", default="call_setup_analysis.xlsx", help="Name of the output Excel file.")

    args = parser.parse_args()

    ip_to_specific, specific_to_canonical = load_node_map(args.hosts_file)
    if not ip_to_specific:
        sys.exit(1)

    cdr_data = load_cdr_data(args.cdr)
    if cdr_data is None and args.cdr:
        sys.exit(1)

    pcap_files = glob(os.path.join(args.pcap_directory, '*.pcap*'))
    if not pcap_files:
        print(f"[!] No files matching '*.pcap*' found in directory '{args.pcap_directory}'.")
        sys.exit(1)

    print(f"\n[*] Found {len(pcap_files)} pcap files to analyze.")

    all_results = []
    for i, pcap_file in enumerate(pcap_files):
        print("\n" + "=" * 50)
        print(f"--- Processing file {i + 1}/{len(pcap_files)}: {os.path.basename(pcap_file)} ---")
        result = process_pcap_file(pcap_file, ip_to_specific, specific_to_canonical, cdr_data)
        if result:
            all_results.append(result)

    if not all_results:
        print("\n[!] No files could be processed successfully. No output file will be generated.")
        sys.exit(1)

    print("\n" + "=" * 50)
    print("[*] Consolidating results and writing to Excel...")

    final_df = pd.DataFrame(all_results)

    primary_cols = [
        "RowID", "File", "Call Setup Time", "One-way network time",
        "Max IMS Nodal Time", "Max IMS Node",
        "Max 5GC Nodal Time", "Max 5GC Node",
        "Total Radio Time", "Total NGAP Time", "Total S1AP Time",
        "Total Rx Time", "Total PCF Notification-Policy Time"
    ]
    other_cols = [col for col in final_df.columns if col not in primary_cols]

    final_df = final_df[primary_cols + sorted(other_cols)]

    try:
        final_df.to_excel(args.output, index=False, engine='openpyxl')
        print(f"\n[SUCCESS] Analysis complete. Results saved to '{args.output}'")
    except ImportError:
        print("\n[!] Error: The 'openpyxl' library is required to write Excel files.")
        print("    Please install it using: pip install openpyxl")
    except Exception as e:
        print(f"\n[!] An error occurred while writing the Excel file: {e}")


if __name__ == "__main__":
    try:
        import openpyxl
    except ImportError:
        print("\n[!] The 'openpyxl' library is required to write Excel files.")
        print("    Please install it using: pip install openpyxl")
        sys.exit(1)

    main()
