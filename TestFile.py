# Generic imports
import pandas as pd
import plotly
import plotly.graph_objects as go

# 5G visualization logic
import trace_plotting
from utils.wireshark import import_pcap_as_dataframe
from trace_plotting import generate_scatterplots_for_wireshark_traces
from calculate_metrics import create_vectors_from_traces
import logging
import re
import platform

# Wireshark trace with 5GC messages
#wireshark_trace = 'D:\\Temp\\free5gc.pcap'
#wireshark_trace = 'D:\\Temp\\volte_calls_2.pcapng'
#wireshark_trace = 'D:\\Temp\\s1ap_volte.pcapng'
wireshark_trace = 'D:\\Temp\\SIP MT offnet.pcap'
#wireshark_trace = 'D:\\Temp\\registration_open5gs.pcapng'
#wireshark_trace = 'D:\\Temp\\EPC_dedicated_bearers.pcapng'

file_directory = 'D:\\Temp\\'

# packets_df = import_pcap_as_dataframe(
#     wireshark_trace,
#     http2_ports = "32445,5002,5000,32665,80,32077,5006,8080,3000,8081,29502,37904",
#     wireshark_version = 'OS',
#     platform=platform.system(),
#     logging_level=logging.INFO,
#     remove_pdml=False)

#print(packets_df)

#feature_vector = create_feature_vector(packets_df)
#plot_data = generate_scatterplots_for_wireshark_traces(packets_df)

#procedure_df, procedure_frames_df = calculate_procedure_length_eps(packets_df, logging_level=logging.DEBUG)

result_df = create_vectors_from_traces(file_directory)