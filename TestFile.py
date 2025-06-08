# Generic imports
import pandas as pd
import plotly
import plotly.graph_objects as go

# 5G visualization logic
import trace_plotting
from utils.wireshark import import_pcap_as_dataframe
from utils.pcaputils import split_pcapng_by_excel_times
#from trace_plotting import generate_scatterplots_for_wireshark_traces
from calculate_metrics import create_vectors_from_traces, calculate_procedure_length_eps, calculate_procedure_length_sip
import logging
import re
import platform
import os.path

# Wireshark trace with 5GC messages
#wireshark_trace = 'D:\\Temp\\free5gc.pcap'
wireshark_trace = '.\\doc\\volte_calls_2.pcapng'
#wireshark_trace = '.\\doc\\s1ap_volte.pcapng'
#wireshark_trace = 'D:\\Temp\\SIP MT offnet.pcap'
#wireshark_trace = 'D:\\Temp\\registration_open5gs.pcapng'
#wireshark_trace = 'D:\\Temp\\EPC_dedicated_bearers.pcapng'


pcapng_input_dir = r'C:\Telstra\CN_Traces\Input\Wireshark_traces'  # e.g., 'C:/Captures' or './captures'
excel_filepath = r'C:\Telstra\CN_Traces\Input\Drive_CDRs\test_times.xlsx'  # e.g., 'C:/Tests/test_plan.xlsx' or './test_times.xlsx'
output_split_dir = r'C:\Telstra\CN_Traces\Output' # e.g., 'C:/SplitCaptures' or './split_captures'
output_vector_file = r'vectors.xlsx'


packets_df = import_pcap_as_dataframe(
    wireshark_trace,
    http2_ports = "32445,5002,5000,32665,80,32077,5006,8080,3000,8081,29502,37904",
    wireshark_version = 'OS',
    platform=platform.system(),
    logging_level=logging.INFO,
    remove_pdml=False)

#print(packets_df)

#feature_vector = create_feature_vector(packets_df)
#plot_data = generate_scatterplots_for_wireshark_traces(packets_df)

#procedure_df, procedure_frames_df = calculate_procedure_length_eps(packets_df, logging_level=logging.DEBUG)
procedure_df, procedure_frames_df = calculate_procedure_length_sip(packets_df)
print(procedure_df, procedure_frames_df)

# split_pcapng_by_excel_times(pcapng_input_dir, excel_filepath, output_split_dir)
# result_df = create_vectors_from_traces(output_split_dir)
# output_file_path = os.path.join(output_split_dir, output_vector_file)
# result_df.to_excel(output_file_path, sheet_name="vectors", index=False)
