import csv
import requests
import time 
from tqdm import tqdm
import os, sys
import utils, contextlib

# Function to query VirusTotal for SHA256 hashes
def query_virustotal_hash(hash_value, api_keys):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": api_keys['VirusTotal']}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(f"Successful API call for {hash_value} to VirusTotal. Gathering info..")
            data = response.json()
            if 'data' in data and 'attributes' in data['data']:
                analysis_results = data['data']['attributes'].get('last_analysis_results', {})
                reputation = {
                    engine: result.get('category', 'N/A')
                    for engine, result in analysis_results.items()
                }
                return {
                    'hash': hash_value,
                    'virustotal_reputation': reputation
                }
            else:
                print(f"No detailed analysis found for {hash_value} on VirusTotal.")
                return {'hash': hash_value, 'virustotal_reputation': 'No detailed analysis found'}
        else:
            print(f"Unsuccessful API call for {hash_value} to VirusTotal. Check your API Key or the hash.")
            return {'hash': hash_value, 'virustotal_reputation': 'Error: ' + str(response.status_code)}
    except Exception as e:
        return {'hash': hash_value, 'virustotal_reputation': 'Error: ' + str(e)}



# Function to query VirusTotal
def query_virustotal(ip, api_keys):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_keys['VirusTotal']}
    
    try:        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(f"Successful API call for {ip} to VirusTotal. Gathering info..")
            data = response.json()
            reputation = data['data']['attributes']['last_analysis_stats']
            return {
                'ip': ip,
                'virustotal_reputation': reputation
            }
        else:
            print(f"Unsuccessful API call for {ip} to VirusTotal. Check your API Key.")
            return {'ip': ip, 'virustotal_reputation': 'Error: ' + str(response.status_code)}
    except Exception as e:
        return {'ip': ip, 'virustotal_reputation': 'Error: ' + str(e)}

# Function to query AbuseIPDB
def query_abuseipdb(ip, api_keys):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_keys['AbuseIPDB'], "Accept": "application/json"}
    params = {'ipAddress': ip}

    try:
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            print(f"Successful API call for {ip} to AbuseIPDB. Gathering info..")
            data = response.json()
            reputation = data['data']['abuseConfidenceScore']  # Abuse confidence score (0-100)
            domain = data['data']['domain'] # Domain associated with the IP
            hostnames = data['data']['hostnames']  # Hostnames associated with the IP
            return {
                'ip': ip,
                'abuseipdb_reputation': {
                    'abuseIPDB_ConfidenceScore': "Confidence of abuse is " + str(reputation) + "%",  # The abuse confidence score.
                    'domain': domain,  # Domain from the abuseIPDB.
                    'hostnames': hostnames # Hostnames associated with the IP.
                }
            }
        else:
            print(f"Unsuccessful API call for {ip} to AbuseIPDB. Check your API Key or the IP Address.")
            return {'ip': ip, 'abuseipdb_reputation': 'Error: ' + str(response.status_code)}
    except Exception as e:
        return {'ip': ip, 'abuseipdb_reputation': 'Error: ' + str(e)}

# Function to get reputations for SHA256 hashes
def get_hash_reputations(hash_list, api_keys):
    with contextlib.redirect_stdout(None):
        with tqdm(total=len(hash_list), desc="Processing Hashes", position=0, leave=True) as progress_bar:
            results = []
            for hash_value in hash_list:
                virustotal_data = query_virustotal_hash(hash_value, api_keys)
                
                result = {
                    'Hash': hash_value,
                    'VirusTotal Reputation': '\n'.join(
                        f"{engine}: {result}"
                        for engine, result in virustotal_data['virustotal_reputation'].items()
                    )
                    if isinstance(virustotal_data['virustotal_reputation'], dict)
                    else virustotal_data['virustotal_reputation']
                }

                results.append(result)
                progress_bar.update(1)
                time.sleep(15)  # Adding delay to avoid hitting rate limits of APIs
    return results


# Main function to handle IP list and query APIs
def get_ip_reputations(ip_list, api_keys):
    progress_bar = tqdm(total=len(ip_list), desc="Processing IPs", position=0, leave=True)
    results = []
    with contextlib.redirect_stdout(None):
        for ip in ip_list:
            virustotal_data = query_virustotal(ip, api_keys)
            abuseipdb_data = query_abuseipdb(ip, api_keys)

            
            result = {
                'IP': ip,
                'VirusTotal Reputation': '\n'.join(
                    f"{key}: {value}"
                    for key, value in virustotal_data['virustotal_reputation'].items()
                )
                if isinstance(virustotal_data['virustotal_reputation'], dict)
                else virustotal_data['virustotal_reputation'],
                'AbuseIPDB Reputation': '\n'.join(
                    f"{key}: {value}"
                    for key, value in abuseipdb_data['abuseipdb_reputation'].items()
                )
                if isinstance(abuseipdb_data['abuseipdb_reputation'], dict)
                else abuseipdb_data['abuseipdb_reputation']
            }
            
            progress_bar.update(1)
            results.append(result)

            time.sleep(15)  # Adding delay to avoid hitting rate limits of APIs
    

    return results

# Function to save results to CSV
def save_to_csv(data, filename='output.csv'):
    keys = data[0].keys()
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)

# Read IP addresses from a text file
def read_ip_list(file_path='ips.txt'):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines()]

# Read SHA256 hashes from a text file
def read_hash_list(file_path='hashes.txt'):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines()]
    return []
# Main script execution
if __name__ == "__main__":
    print(f"""
 ::::::::  :::    :::  ::::::::   :::::::: ::::::::::: :::     ::: ::::::::::: ::::::::  :::::::::: 
:+:    :+: :+:    :+: :+:    :+: :+:    :+:    :+:     :+:     :+:     :+:    :+:    :+: :+:        
+:+        +:+    +:+ +:+    +:+ +:+           +:+     +:+     +:+     +:+    +:+        +:+        
:#:        +#++:++#++ +#+    +:+ +#++:++#++    +#+     +#+     +:+     +#+    +#+        +#++:++#   
+#+   +#+# +#+    +#+ +#+    +#+        +#+    +#+      +#+   +#+      +#+    +#+        +#+        
#+#    #+# #+#    #+# #+#    #+# #+#    #+#    #+#       #+#+#+#       #+#    #+#    #+# #+#        
 ########  ###    ###  ########   ########     ###         ###     ########### ########  ########## 

                                          Initializing...
    """)

    time.sleep(2)

def main_menu():
    api_keys = utils.load_api_keys()  # Load API keys here
    if not api_keys:
      print("No API keys found. Please set them first (Option 1).")
    
    while True:
        def option_1():
            current_keys = utils.load_api_keys()
            if not current_keys:
                print("No API keys found. You need to enter API keys for VirusTotal and AbuseIPDB")
            else:
                print("\nCurrent API keys:")
                print(f"  VirusTotal: {current_keys.get('VirusTotal', 'Not set')}")
                print(f"  AbuseIPDB: {current_keys.get('AbuseIPDB', 'Not set')}")

            print("\nEnter new API keys (or press Enter to skip):")
            new_virustotal_key = input("Enter new VirusTotal API Key: ")
            new_abuseipdb_key = input("Enter new AbuseIPDB API Key: ")

            updated_keys = {'VirusTotal': new_virustotal_key, 'AbuseIPDB': new_abuseipdb_key}
            
            utils.save_api_keys(updated_keys)  # Save the updated keys, even if they're empty
            print("\nUpdated API keys, checking now.")
            print(f"  VirusTotal: {utils.load_api_keys().get('VirusTotal','Not set')}")
            print(f"  AbuseIPDB: {utils.load_api_keys().get('AbuseIPDB','Not set')}")
            print("\nAPI keys saved.")
        print("Main Menu:")
        print("\n")
        print("1. Set API Keys for VirusTotal & AbuseIPDB")
        print("2. Run Reputation Analysis for IPv4 Addresses")
        print("3. Run Repuation Analysis for SHA256 Hashes")
        print("5. Run Repuation Analysis for Remote Hosts")
        print("6. Extract Above Indicators from a text file.")
        print("E. Exit")

        choice = input("Enter your choice (1-7), or 'e' to exit: ")
        api_keys = utils.load_api_keys()  # Load API keys here again for option 2

        if choice == '1':
            option_1()
        elif choice == '2':
            ip_list = read_ip_list()
            if ip_list:
                print(f"Using the following VirusTotal API Key for IP Reputation Report: {api_keys['VirusTotal']}")
                print(f"Using the following AbuseIPDB API Key for IP Reputation Report: {api_keys['AbuseIPDB']}")
                results = get_ip_reputations(ip_list, api_keys)
                save_to_csv(results)
                print("Reputation report has been saved to output.csv")
            else:
                print("No valid IP addresses found in ips.txt")
        elif choice == '3':
            hash_list = read_hash_list()
            if hash_list:
                results = get_hash_reputations(hash_list, api_keys)
                save_to_csv(results, filename='hash_output.csv')
                print("Reputation report for hashes has been saved to hash_output.csv")
            else:
                print("No valid SHA256 hashes found in hashes.txt")
            
        elif choice == 'e':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

main_menu()
