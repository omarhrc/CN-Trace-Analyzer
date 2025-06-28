#!/usr/bin/env python3

import os
import subprocess

# --- Configuration ---
# The directory containing your pcap files.
# Change '.' to a specific path like '/path/to/your/pcaps' if needed.
PCAP_DIRECTORY = '.'

def deduplicate_pcap_files(directory):
    """
    Scans a directory for .pcap or .pcapng files and uses the 'editcap'
    command-line tool to remove duplicate packets from each one.

    Args:
        directory (str): The path to the directory to scan.
    """
    print(f"[*] Scanning for pcap files in: '{os.path.abspath(directory)}'")
    
    processed_count = 0
    error_count = 0
    
    # Get a list of all pcap files in the directory
    try:
        pcap_files = [f for f in os.listdir(directory) if f.lower().endswith(('.pcap', '.pcapng'))]
    except FileNotFoundError:
        print(f"[!!!] ERROR: Directory not found at '{os.path.abspath(directory)}'")
        return

    if not pcap_files:
        print("\n[!] No pcap or pcapng files were found in the directory.")
        return

    print(f"\n[*] Found {len(pcap_files)} pcap file(s) to process.")

    # Process each file found
    for filename in pcap_files:
        input_path = os.path.join(directory, filename)
        
        # Create a new name for the output file to avoid overwriting the original.
        # Example: 'my_capture.pcap' -> 'my_capture_deduped.pcapng'
        base_name, _ = os.path.splitext(filename)
        output_filename = f"{base_name}_deduped.pcapng"
        output_path = os.path.join(directory, output_filename)

        # Construct the command for subprocess.run()
        # 'editcap -d <infile> <outfile>' removes duplicate packets
        command = ['editcap', '-d', input_path, output_path]

        print(f"\n--- Processing '{filename}' ---")
        print(f"    -> Output file: {output_filename}")
        
        try:
            # Execute the editcap command
            # `check=True` will raise an error if editcap fails.
            # `capture_output=True` and `text=True` capture stdout/stderr.
            result = subprocess.run(command, check=True, capture_output=True, text=True)
            
            # editcap often prints status information to stderr, so we check that.
            if result.stderr:
                # Example output: "100 packets seen, 10 packets duplicated..."
                # We can extract and print the duplicate info.
                for line in result.stderr.strip().split('\n'):
                    if "duplicated" in line:
                         print(f"    [editcap info]: {line.strip()}")

            print(f"[+] SUCCESS: Created deduplicated file '{output_filename}'.")
            processed_count += 1

        except FileNotFoundError:
            print("\n[!!!] CRITICAL ERROR: 'editcap' command not found.")
            print("      Please ensure Wireshark (and its command-line tools) is installed and")
            print("      that its location is included in your system's PATH environment variable.")
            return # Stop the script if editcap isn't available
            
        except subprocess.CalledProcessError as e:
            print(f"\n[!!!] ERROR: 'editcap' failed for file '{filename}'.")
            print(f"      Command failed with exit code {e.returncode}.")
            print(f"      Stderr: {e.stderr.strip()}")
            error_count += 1
            
    print("\n[*] Script finished.")
    print(f"    -> Successfully processed {processed_count} files.")
    if error_count > 0:
        print(f"    -> Failed to process {error_count} files.")


if __name__ == "__main__":
    deduplicate_pcap_files(PCAP_DIRECTORY)
