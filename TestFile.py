# Generic imports
import pandas as pd
import plotly
import plotly.graph_objects as go

# 5G visualization logic
import trace_plotting
from utils.wireshark import import_pcap_as_dataframe
from utils.pcaputils import split_pcapng_by_excel_times
#from trace_plotting import generate_scatterplots_for_wireshark_traces
from calculate_metrics import create_vectors_from_traces, calculate_procedure_length_eps
from calculate_metrics import calculate_procedure_length_sip, calculate_procedure_length_diameter, calculate_procedure_length_pfcp
from calculate_metrics import calculate_procedure_length_gtp, create_feature_vector

import logging
import re
import platform
import os.path

# Wireshark trace with 5GC messages
wireshark_trace = '.\\doc\\free5gc.pcap'
#wireshark_trace = '.\\doc\\volte_calls_2.pcapng'
#wireshark_trace = '.\\doc\\s1ap_volte.pcapng'
#wireshark_trace = 'D:\\Temp\\SIP MT offnet.pcap'
#wireshark_trace = 'D:\\Temp\\registration_open5gs.pcapng'
#wireshark_trace = '.\\doc\\EPC_dedicated_bearers.pcapng'
#wireshark_trace = '.\\doc\\GTPv2.pcap'
#wireshark_trace = '.\\doc\\GTPv2_update.pcap'

pcapng_input_dir = r'C:\Telstra\CN_Traces\Input\Wireshark_traces\Test1'  # e.g., 'C:/Captures' or './captures'
pcapng_input_dirs = [r'C:\Telstra\CN_Traces\Input\Wireshark_traces\Test1',
                     r'C:\Telstra\CN_Traces\Input\Wireshark_traces\Test2']# e.g., 'C:/Captures' or './captures'
#excel_filepath = r'C:\Telstra\CN_Traces\Input\Drive_CDRs\Test\one_side_timestamps.xlsx'  # e.g., 'C:/Tests/test_plan.xlsx' or './test_times.xlsx'
excel_filepath = r'C:\Telstra\CN_Traces\Input\Drive_CDRs\Test\two_side_timestamps.xlsx'  # e.g., 'C:/Tests/test_plan.xlsx' or './test_times.xlsx'
output_split_dir = r'C:\Telstra\CN_Traces\Output\Test1'
output_split_dirs = [r'C:\Telstra\CN_Traces\Output\Test1',
                    r'C:\Telstra\CN_Traces\Output\Test2'] # e.g., 'C:/SplitCaptures' or './split_captures'
test_name = 'interactivity'
output_vector_file = r'vectors.xlsx'


# packets_df = import_pcap_as_dataframe(
#     wireshark_trace,
#     http2_ports = "32445,5002,5000,32665,80,32077,5006,8080,3000,8081,29502,37904",
#     wireshark_version = 'OS',
#     platform=platform.system(),
#     logging_level=logging.INFO,
#     remove_pdml=False)
#
# print(packets_df)

#feature_vector = create_feature_vector(packets_df)
#plot_data = generate_scatterplots_for_wireshark_traces(packets_df)

#procedure_5gc_df, procedure_5gc_frames_df =  trace_plotting.calculate_procedure_length(packets_df)
#print(procedure_5gc_df)
#procedure_df, procedure_frames_df = calculate_procedure_length_eps(packets_df, logging_level=logging.DEBUG)
#procedure_df, procedure_frames_df = calculate_procedure_length_sip(packets_df)
#procedure_diam_df, procedure_diam_frames_df = calculate_procedure_length_diameter(packets_df)
#print(procedure_diam_df)
#procedure_df, procedure_frames_df = calculate_procedure_length_pfcp(packets_df)
#procedure_gtp_df, procedure_gtp_frames_df = calculate_procedure_length_gtp(packets_df)
#print(procedure_gtp_df)
#print(procedure_df, procedure_frames_df)

split_pcapng_by_excel_times(pcapng_input_dirs, excel_filepath, output_split_dirs, test_name)
#result_df = create_vectors_from_traces(output_split_dir)
#output_file_path = os.path.join(output_split_dir, output_vector_file)
#result_df.to_excel(output_file_path, sheet_name="vectors", index=False)
