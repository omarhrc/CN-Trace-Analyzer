# -*- coding: utf-8 -*-
"""
Created on Thu Jun  5 11:34:29 2025

@author: omar.rubio.camacho
"""

import pandas as pd
import subprocess
import os
import datetime
import glob

EPSILON_TIME = 0.5 # Time in seconds


def split_pcapng_by_excel_times(pcapng_directory, excel_file, output_directory):
    """
    Splits pcapng files based on time ranges specified in an Excel file.

    Args:
        pcapng_directory (str): Path to the directory containing input pcapng files.
        excel_file (str): Path to the Excel file with 'time_start' and 'time_stop' fields.
        output_directory (str): Path to the directory where split pcapng files will be saved.
    """
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)
        print(f"Created output directory: {output_directory}")

    try:
        df = pd.read_excel(excel_file)
        # Ensure 'time_start' and 'time_stop' columns exist
        if 'time_start' not in df.columns or 'time_stop' not in df.columns:
            raise ValueError("Excel file must contain 'time_start' and 'time_stop' columns.")
    except Exception as e:
        print(f"Error reading Excel file: {e}")
        return

    # Assuming time_start and time_stop are in a format tshark can understand,
    # e.g., "YYYY-MM-DD HH:MM:SS" or epoch time.
    # If not, you might need to convert them.

    for index, row in df.iterrows():
        test_name = f"test_{index + 1}"  # Or use another unique identifier from your Excel
        time_start = row['time_start']
        time_stop = row['time_stop']

        for filename in os.listdir(pcapng_directory):
            if ".pcap" in filename:
                input_pcapng_path = os.path.join(pcapng_directory, filename)
                output_pcapng_filename = f"{os.path.splitext(filename)[0]}_{test_name}.pcapng"
                output_pcapng_path = os.path.join(output_directory, output_pcapng_filename)

                # tshark command to filter by time
                # Using '-Y' for display filter (more flexible for time ranges)
                # The time format needs to be compatible with tshark's 'frame.time' field.
                # Example: "frame.time >= "2023-01-01 10:00:00" && frame.time <= "2023-01-01 10:05:00""
                # Or if using epoch time: "frame.time_epoch >= 1672531200 && frame.time_epoch <= 1672531500"

                # IMPORTANT: Adjust the time format and filter based on your Excel's time format.
                # If your times are in a standard datetime format, you can often directly use them.
                # If they are not, you might need to convert them to epoch time or a tshark-compatible string.

                # Let's assume your Excel times are directly usable as strings for display filters.
                # If they are datetime objects from pandas, convert them to string:
                
                def add_epsilon_time(time_field, epsilon=EPSILON_TIME, forward_time= True):
                    delta_time = datetime.timedelta(seconds=epsilon)
                    if not forward_time:
                        delta_time = -delta_time
                    new_date_object = time_field + delta_time
                    new_date_string = new_date_object.strftime("%Y-%m-%d %H:%M:%S.%f")
                    return new_date_string
                
                time_start_str = add_epsilon_time(time_start, forward_time=False)
                time_stop_str = add_epsilon_time(time_stop)
                    
                # The display filter for time:
                # 'frame.time >= "2025-06-05 10:00:00" && frame.time <= "2025-06-05 10:05:00"'
                time_filter = f'frame.time >= "{time_start_str}" && frame.time <= "{time_stop_str}"'

                command = [
                    'tshark',
                    '-r', input_pcapng_path,      # Read from input file
                    '-Y', time_filter,            # Apply display filter
                    '-w', output_pcapng_path      # Write to output file
                ]

                print(f"Executing command: {' '.join(command)}")
                try:
                    subprocess.run(command, check=True, capture_output=True, text=True)
                    print(f"Successfully split {filename} for {test_name} into {output_pcapng_filename}")
                except subprocess.CalledProcessError as e:
                    print(f"Error splitting {filename} for {test_name}:")
                    print(f"Command: {e.cmd}")
                    print(f"Return Code: {e.returncode}")
                    print(f"STDOUT: {e.stdout}")
                    print(f"STDERR: {e.stderr}")
                except FileNotFoundError:
                    print("Error: tshark command not found. Make sure Wireshark is installed and tshark is in your system's PATH.")
                    return


def merge_pcap_files(input_dir, output_dir, output_filename="merged.pcap"):
    """
    Merges all pcap* files from an input directory into a single PCAP file
    in the specified output directory using mergecap.

    Args:
        input_dir (str): The path to the directory containing the pcap* files.
        output_dir (str): The path to the directory where the merged PCAP file
                          will be written.
        output_filename (str): The name of the merged output PCAP file.
                               Defaults to "merged.pcap".

    Returns:
        bool: True if the merge was successful, False otherwise.
    """
    # Ensure input and output directories exist
    if not os.path.isdir(input_dir):
        print(f"Error: Input directory '{input_dir}' does not exist.")
        return False
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: '{output_dir}'")

    # Find all pcap* files in the input directory
    pcap_files = glob.glob(os.path.join(input_dir, "*pcap*"))

    if not pcap_files:
        print(f"No pcap* files found in '{input_dir}'. Nothing to merge.")
        return False

    # Construct the full path for the output file
    output_filepath = os.path.join(output_dir, output_filename)

    # Prepare the mergecap command
    # Basic command: mergecap -w output_file input_file1 input_file2 ...
    command = ["mergecap", "-w", output_filepath] + pcap_files

    print(f"Merging {len(pcap_files)} files to '{output_filepath}'...")
    try:
        # Execute the mergecap command
        # capture_output=True captures stdout and stderr
        # text=True decodes stdout/stderr as text
        # check=True raises a CalledProcessError if the command returns a non-zero exit code
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print("Merge successful!")
        if result.stdout:
            print("Mergecap Output:\n", result.stdout)
        if result.stderr:
            print("Mergecap Errors (if any):\n", result.stderr)
        return True
    except FileNotFoundError:
        print("Error: 'mergecap' command not found.")
        print("Please ensure Wireshark (which includes mergecap) is installed and in your system's PATH.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Error merging files: {e}")
        print("Command failed with exit code:", e.returncode)
        print("Stderr:\n", e.stderr)
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

