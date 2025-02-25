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
