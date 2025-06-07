# Generic imports
import pandas as pd
import plotly
import plotly.graph_objects as go

# 5G visualization logic
import trace_plotting
from utils.wireshark import import_pcap_as_dataframe
from utils.pcaputils import split_pcapng_by_excel_times, merge_pcap_files
from trace_plotting import generate_scatterplots_for_wireshark_traces
from calculate_metrics import create_vectors_from_traces
import logging
import re
import platform
import os.path

########################################################################
#
# Parameters
#
########################################################################
number_test_db = r'C:\Telstra\CN_Traces\Input\Number_Test_database.xlsx'
pcapng_input_dir = r'C:\Telstra\CN_Traces\Input\Wireshark_traces'  # e.g., 'C:/Captures' or './captures'
cdr_excel_dir = r'C:\Telstra\CN_Traces\Input\Drive_CDRs'  # e.g., 'C:/Tests/test_plan.xlsx' or './test_times.xlsx'
output_split_dir = r'C:\Telstra\CN_Traces\Output' # e.g., 'C:/SplitCaptures' or './split_captures'
output_vector_file = r'vectors.xlsx'


def load_number_test_db(file_path):
    """
    Reads an Excel file and returns its content as a Pandas DataFrame.

    Args:
        file_path (str): The full path to the Excel file (.xls or .xlsx).

    Returns:
        pandas.DataFrame: A DataFrame containing the data from the Excel file,
                          or None if an error occurs.
    """
    if not os.path.exists(file_path):
        print(f"Error: The file '{file_path}' was not found.")
        return None
    
    if not file_path.lower().endswith(('.xls', '.xlsx')):
        print(f"Error: The file '{file_path}' is not an Excel file (.xls or .xlsx).")
        return None

    try:
        df = pd.read_excel(file_path, dtype=str)
        print(f"Successfully loaded database from '{file_path}'.")
        return df
    except FileNotFoundError:
        # This case is already handled by os.path.exists, but kept for robustness.
        print(f"Error: The file '{file_path}' was not found.")
        return None
    except pd.errors.EmptyDataError:
        print(f"Error: The Excel file '{file_path}' is empty.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred while reading '{file_path}': {e}")
        return None


def remove_files_non_recursively(directory_path, file_extension=None, ignore_errors=False):
    """
    Removes files directly within a specified directory (non-recursively),
    optionally filtered by file extension. It will not delete subdirectories
    or files within subdirectories.

    Args:
        directory_path (str): The path to the directory from which to remove files.
        file_extension (str, optional): The extension of files to remove (e.g., '.txt', 'log').
                                        Case-insensitive. If None or empty, all files
                                        will be removed. Defaults to None.
        ignore_errors (bool): If True, continue processing even if an error occurs
                              during file deletion (e.g., permission denied).
                              If False, the function will stop and raise the error.
                              Defaults to False.

    Returns:
        bool: True if the operation completed (even with ignored errors), False if
              the directory does not exist or a critical error occurred and
              ignore_errors is False.
    """
    if not os.path.isdir(directory_path):
        print(f"Error: Directory '{directory_path}' does not exist or is not a directory.")
        return False

    files_removed_count = 0
    errors_occurred = False

    # Normalize the file extension if provided
    normalized_extension = None
    if file_extension:
        normalized_extension = file_extension.lower()
        if not normalized_extension.startswith('.'):
            normalized_extension = '.' + normalized_extension
        print(f"Attempting to remove '{normalized_extension}' files from: '{directory_path}' (non-recursively)")
    else:
        print(f"Attempting to remove all files from: '{directory_path}' (non-recursively)")


    # Iterate over all entries in the directory
    for entry in os.listdir(directory_path):
        entry_path = os.path.join(directory_path, entry)

        # Check if the entry is a file
        if os.path.isfile(entry_path):
            # Check if an extension filter is applied and if the file matches
            if normalized_extension is None or entry_path.lower().endswith(normalized_extension):
                try:
                    os.remove(entry_path)
                    print(f"Removed: {entry_path}")
                    files_removed_count += 1
                except OSError as e:
                    errors_occurred = True
                    print(f"Error removing file '{entry_path}': {e}")
                    if not ignore_errors:
                        print("Stopping due to error (ignore_errors is False).")
                        return False
                except Exception as e:
                    errors_occurred = True
                    print(f"An unexpected error occurred with file '{entry_path}': {e}")
                    if not ignore_errors:
                        print("Stopping due to error (ignore_errors is False).")
                        return False
            else:
                print(f"Skipping (wrong extension): {entry_path}")
        else:
            # If it's a directory or other type of entry, we skip it
            print(f"Skipping (not a file): {entry_path}")

    if errors_occurred and ignore_errors:
        print(f"\nOperation completed with {files_removed_count} files removed, but some errors occurred (ignored).")
    else:
        print(f"\nOperation completed: {files_removed_count} files removed.")

    return not errors_occurred or ignore_errors

    
def process_all_pcap_files():
    database_df = load_number_test_db(number_test_db)
    for row in database_df.itertuples():
        print(f"Merging: {row.Relative_Dir_Path}")
        merge_input_path = os.path.join(pcapng_input_dir, row.Relative_Dir_Path)
        merge_output_path = os.path.join(merge_input_path, 'Merged')
        merge_pcap_files(merge_input_path,
                         merge_output_path, 
                         output_filename=f"{row.Relative_Dir_Path}_merged.pcapng")
        
        print(f"Splitting: {merge_output_path}")
        excel_filepath = os.path.join(cdr_excel_dir, row.Timestamp_File)   
        output_split_full_dir = os.path.join(output_split_dir, row.Path_Suffix, row.MSISDN)
        split_pcapng_by_excel_times(merge_output_path, excel_filepath, output_split_full_dir)
    
        print(f"Creating vectors for: {row.Relative_Dir_Path}")
        result_df = create_vectors_from_traces(output_split_full_dir)
        output_vector_file_path = os.path.join(output_split_full_dir, row.Vector_File)
        result_df.to_excel(output_vector_file_path, sheet_name="vectors", index=False)   


def cleanup_output():
    ''' Removes all the pcap files resulting from postprocessing '''
    database_df = load_number_test_db(number_test_db)
    for row in database_df.itertuples():
        print(f"Removing: {row.Relative_Dir_Path}")
        merge_input_path = os.path.join(pcapng_input_dir, row.Relative_Dir_Path)
        merge_output_path = os.path.join(merge_input_path, 'Merged')
        remove_files_non_recursively(merge_output_path, file_extension='.pcapng')
        
        print(f"Removing: {merge_output_path}")
        output_split_full_dir = os.path.join(output_split_dir, row.Path_Suffix, row.MSISDN)
        remove_files_non_recursively(output_split_full_dir, file_extension='.pcapng')
    
        print(f"Removing vectors for: {row.Relative_Dir_Path}")
        remove_files_non_recursively(output_split_full_dir, file_extension='.xlsx')   

#process_all_pcap_files()
cleanup_output()