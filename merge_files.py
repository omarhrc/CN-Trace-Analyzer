#!/usr/bin/env python3

import os
import re
import subprocess
from collections import defaultdict

# --- Configuration ---
# The directory containing your pcap files.
# Change '.' to a specific path like '/path/to/your/pcaps' if needed.
PCAP_DIRECTORY = '.'

def group_pcap_files(directory):
    """
    Scans a directory, finds pcap files with 'RowXXX' identifiers,
    and groups them by that identifier.

    Args:
        directory (str): The path to the directory to scan.

    Returns:
        defaultdict: A dictionary where keys are identifiers ('Row123')
                     and values are lists of full file paths.
    """
    # defaultdict(list) simplifies appending to lists for new keys.
    # It will store data like:
    # {'Row101': ['/path/to/fileA_Row101.pcap', '/path/to/fileB_Row101.pcap']}
    grouped_files = defaultdict(list)
    
    # Regex to find the 'Row' followed by one or more digits.
    # The parentheses create a capturing group for the identifier itself.
    identifier_pattern = re.compile(r'(Row\d+)')

    print(f"[*] Scanning for pcap files in: '{os.path.abspath(directory)}'")

    # Walk through all files in the specified directory
    for filename in os.listdir(directory):
        # Process files ending with .pcap or .pcapng
        if filename.lower().endswith(('.pcap', '.pcapng')):
            # Search for the pattern in the filename
            match = identifier_pattern.search(filename)
            if match:
                # The first matched group, e.g., 'Row101'
                identifier = match.group(1)
                # Construct the full, absolute path to the file
                full_path = os.path.join(directory, filename)
                grouped_files[identifier].append(full_path)
                
    return grouped_files

def merge_file_groups(grouped_files, output_directory):
    """
    Iterates through the grouped files and merges each group using the
    'mergecap' command-line tool.

    Args:
        grouped_files (defaultdict): The dictionary of files grouped by identifier.
        output_directory (str): The directory where merged files will be saved.
    """
    if not grouped_files:
        print("\n[!] No pcap files with 'RowXXX' identifiers were found to merge.")
        return

    print(f"\n[*] Found {len(grouped_files)} unique identifiers to process.")
    
    merged_count = 0
    skipped_count = 0

    # Process each group of files
    for identifier, files_to_merge in grouped_files.items():
        # We only need to merge if there is more than one file in a group.
        if len(files_to_merge) > 1:
            # Define the output filename, e.g., 'VoNR_Row101.pcapng'
            output_filename = f"VoNR_{identifier}.pcapng"
            output_path = os.path.join(output_directory, output_filename)

            # Construct the command for subprocess.run()
            # Format: ['mergecap', '-w', 'output.pcapng', 'input1.pcap', 'input2.pcap']
            command = ['mergecap', '-w', output_path] + files_to_merge

            print(f"\n--- Merging group '{identifier}' ---")
            print(f"    -> Output file: {output_filename}")
            print(f"    -> Source files ({len(files_to_merge)}): {', '.join(os.path.basename(f) for f in files_to_merge)}")
            
            try:
                # Execute the mergecap command
                # `check=True` will raise an error if mergecap fails
                # `capture_output=True` and `text=True` capture stdout/stderr
                result = subprocess.run(command, check=True, capture_output=True, text=True)
                print(f"[+] SUCCESS: Merged files into '{output_filename}'.")
                merged_count += 1
                
                # Optionally print mergecap's output if there is any
                if result.stderr:
                    print(f"    [mergecap output]: {result.stderr.strip()}")

            except FileNotFoundError:
                print("\n[!!!] CRITICAL ERROR: 'mergecap' command not found.")
                print("      Please ensure Wireshark (and its command-line tools) is installed and")
                print("      that its location is included in your system's PATH environment variable.")
                return # Stop the script if mergecap isn't available
            except subprocess.CalledProcessError as e:
                print(f"\n[!!!] ERROR: 'mergecap' failed for group '{identifier}'.")
                print(f"      Command failed with exit code {e.returncode}.")
                print(f"      Stderr: {e.stderr.strip()}")
        else:
            # Skip groups with only one file
            print(f"\n--- Skipping group '{identifier}' (only one file found, no merge needed) ---")
            skipped_count += 1
            
    print("\n[*] Script finished.")
    print(f"    -> Merged {merged_count} groups.")
    print(f"    -> Skipped {skipped_count} groups.")


if __name__ == "__main__":
    # 1. Find and group the pcap files
    file_groups = group_pcap_files(PCAP_DIRECTORY)
    
    # 2. Merge each group into a new file
    merge_file_groups(file_groups, PCAP_DIRECTORY)
