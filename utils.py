import csv
import json
import os

def save_api_keys(api_keys, filename="api_keys.txt"):
    with open(filename, "w") as f:
        json.dump(api_keys, f, indent=4)

def load_api_keys(filename="api_keys.txt"):
    api_keys = {}
    try:
        with open(filename, "r") as f:
            api_keys = json.load(f)
            if "VirusTotal" not in api_keys:
                api_keys["VirusTotal"] = ""
            if "AbuseIPDB" not in api_keys:
                api_keys["AbuseIPDB"] = ""
    except FileNotFoundError:
        print("No API keys found. Please set them using option 1 in the main menu.")
        api_keys["VirusTotal"] = ""
        api_keys["AbuseIPDB"] = ""

    return api_keys

def write_indicators_to_files(ips, domains, hashes): #changed order
    """
    Deletes and recreates the file indicated by file_choice.
    
    Args:
        file_choice (str): The choice made by the user ('1', '2', or '3').
    """

def delete_and_refresh(file_choice):
    """
    Deletes and recreates the file indicated by file_choice.
    """
    if file_choice == '1':
        open('ips.txt', 'w').close()  # Create an empty ips.txt
    elif file_choice == '2':
        open('hashes.txt', 'w').close()  # Create an empty hashes.txt
    elif file_choice == '3':
        open('hosts.txt', 'w').close() # Create an empty hosts.txt
    else:
        print("Invalid choice.")



def write_indicators_to_files(ips, domains, hashes):
    """
    Writes IPs to ips.txt, domains to hosts.txt, and hashes to hashes.txt.
    """
    with open("ips.txt", "w") as ip_file:
        for ip in ips:
            ip_file.write(ip + "\n")

    with open("hosts.txt", "w") as host_file:
        for domain in domains:
            host_file.write(domain + "\n")

    with open("hashes.txt", "w") as hash_file:
        for hash_val in hashes:
            hash_file.write(hash_val + "\n")


def create_csv_file_from_indicators(ips, domains, hashes, filename="indicators.csv"): #changed order
    """
    Creates a CSV file (indicators.csv) with columns 'IPs', 'Domains', and 'Hashes'.
    Each row represents an indicator.
    """
    
    
    # Convert sets to lists if they are sets.
    if isinstance(ips, set):
        ips = list(ips)
    if isinstance(domains, set):
        domains = list(domains)
    if isinstance(hashes, set):
        hashes = list(hashes)
    with open(filename, mode='w', newline='') as csv_file:
        fieldnames = ['IPs', 'Domains', 'Hashes']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        max_len = max(len(ips), len(domains), len(hashes))
        for i in range(max_len):            
            writer.writerow({'IPs': ips[i] if i < len(ips) else '', 'Domains': domains[i] if i < len(domains) else '', 'Hashes': hashes[i] if i < len(hashes) else ''})


def get_file_line_counts():
    """
    Gets the line count of ips.txt, hosts.txt, and hashes.txt.

    Returns:
        tuple: A tuple containing the line counts of ips.txt, hosts.txt, and hashes.txt.
    """
    ip_line_count = sum(1 for _ in open('ips.txt')) if os.path.exists('ips.txt') else 0
    host_line_count = sum(1 for _ in open('hosts.txt')) if os.path.exists('hosts.txt') else 0
    hash_line_count = sum(1 for _ in open('hashes.txt')) if os.path.exists('hashes.txt') else 0
    return ip_line_count, host_line_count, hash_line_count
