import csv
import re
import requests
import time
from tqdm import tqdm
import os, sys
import utils, contextlib

# Clean terminal output
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

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

# Function to query VirusTotal for remote hosts
def query_virustotal_host(host, api_keys):
    url = f"https://www.virustotal.com/api/v3/domains/{host}"
    headers = {"x-apikey": api_keys['VirusTotal']}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(f"Successful API call for {host} to VirusTotal. Gathering info..")
            data = response.json()
            if 'data' in data and 'attributes' in data['data']:
                analysis_results = data['data']['attributes'].get('last_analysis_stats', {})

                return {
                    'host': host,
                    'virustotal_reputation': analysis_results
                }
            else:
                print(f"No detailed analysis found for {host} on VirusTotal.")
                return {'host': host, 'virustotal_reputation': 'No detailed analysis found'}
        else:
            print(f"Unsuccessful API call for {host} to VirusTotal. Check your API Key or the host.")
            return {'host': host, 'virustotal_reputation': 'Error: ' + str(response.status_code)}
    except Exception as e:
        return {'host': host, 'virustotal_reputation': 'Error: ' + str(e)}
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
def get_host_reputations(host_list, api_keys):
    progress_bar = tqdm(total=len(host_list), desc="Processing Hosts", position=0, leave=True)
    results = []
    with contextlib.redirect_stdout(None):
        for host in host_list:
            virustotal_data = query_virustotal_host(host, api_keys)


            result = {
                'Host': host,
                'VirusTotal Reputation': '\n'.join(
                    f"{key}: {value}"
                    for key, value in virustotal_data['virustotal_reputation'].items()
                )
                if isinstance(virustotal_data['virustotal_reputation'], dict)
                else virustotal_data['virustotal_reputation'],
                'AbuseIPDB Reputation': "Host Reputation cannot be queried via AbuseIPDB API."
            }

            progress_bar.update(1)
            results.append(result)
            time.sleep(15)

    return results

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
def save_to_csv(data, filename='ip_output.csv'):
    if data:
        keys = data[0].keys()
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.DictWriter(file, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)

# Function to save host results to CSV
def save_host_to_csv(data, filename='host_output.csv'):
    if data:
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

def read_remote_host_list(file_path = 'hosts.txt'):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f.readlines()]

def extract_indicators(file_path):
    """Extracts IP addresses, domains, and hashes from a file."""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    hash_pattern = r'\b[0-9a-fA-F]{64}\b'
    domain_pattern = re.compile(
        r'^(https?://)?'  # Optional http:// or https://
        r'([a-zA-Z0-9.-]+)'  # Domain name (letters, numbers, dots, and dashes)
        r'(\.[a-zA-Z]{2,})+'  # Top-level domain(s) (e.g., .com, .org, .net)
        r'([/?].*)?$'  # Optional path, query string, and/or fragment
    )

    ips = set()
    domains = set()
    hashes = set()

    try:
        with open(file_path, 'r') as file:
            for line in file:
                #Domains
                ips.update(re.findall(ip_pattern, line))
                domain_matches = re.findall(domain_pattern, line)
                for match in domain_matches:
                    domains.add(match[1] + match[2])  # Combine domain name and TLD
                hashes.update(re.findall(hash_pattern, line))
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return [], [], []
    return list(ips), list(domains), list(hashes)
def extract_from_csv(file_path="indicators.csv"):    
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            ips = set()
            domains = set()
            hashes = set()

            reader = csv.DictReader(csvfile)
            
            for row in reader:
                if row.get('IPs', '').strip(): ips.add(row.get('IPs').strip())
                if row.get('Domains', '').strip(): domains.add(row.get('Domains').strip())
                if row.get('Hashes', '').strip(): hashes.add(row.get('Hashes').strip())
    except FileNotFoundError:
        print(f"Error: Indicators CSV file not found at {file_path}")        

    utils.write_indicators_to_files(list(ips), list(domains), list(hashes))
    print("Indicators extracted from indicators.csv and saved to ips.txt, hosts.txt, and hashes.txt")   

    return list(ips), list(domains), list(hashes)

def option_5_enhanced(api_keys):
    """Enhanced version of option 5 that handles file creation."""
    file_name = 'search.txt'    
    
    
    if not os.path.exists(file_name):
        clear_terminal()
        print(f"File '{file_name}' not found.\n")
        create_file = input(f"Would you like to create '{file_name}' and continue? (yes/no): ").lower()
        if create_file == "yes":
            create_method = input("Would you like to copy and paste the contents or create it manually? (copy/manual): ").lower()
            if create_method == "copy":
                print(f"Paste the content for '{file_name}' here (press Ctrl+D when done):")
                try:
                    lines = sys.stdin.read().splitlines()
                except EOFError:
                        lines.append(lines)
                except EOFError:
                    pass
                content = '\n'.join(lines)
                with open(file_name, 'w') as f:
                    f.write(content)
                print(f"Content saved to '{file_name}'.")
            elif create_method == "manual":
                print(f"Please manually create '{file_name}' and put the content in there.")
            else:
                print("Invalid choice. File not created.")
                return
        else:
            print("File not created, returning to main menu.")
            return
    clear_terminal()
            

def file_check():
    files_to_check = ["ips.txt", "hashes.txt", "hosts.txt"]
    for file_name in files_to_check:
        if not os.path.exists(file_name):
            clear_terminal()
            print(f"File '{file_name}' not found.")
            create_file = input(f"Would you like to create '{file_name}'? (yes/no): ").lower()
            if create_file == "yes":
                create_method = input("Would you like to copy and paste the contents or create it manually? (copy/manual): ").lower()
                if create_method == "copy":
                    # Copy and paste content
                    print(f"Paste the content for '{file_name}' here (press Ctrl+D when done):")
                    lines = []
                    try:                        
                        for line in sys.stdin:
                            lines.append(line)

                    except EOFError:
                        pass
                    content = '\n'.join(lines)                    
                    with open(file_name, 'w') as f:
                        try:
                            f.write(content)
                            print(f"File '{file_name}' created and content pasted.")
                        except Exception as e:
                            print(f"Error pasting content into '{file_name}': {e}")
                elif create_method == "manual":
                    # Create manually
                    try:
                        with open(file_name, 'w') as f:
                            print(f"File '{file_name}' created, please populate it.")
                    except Exception as e:
                        print(f"Error creating '{file_name}': {e}")

                else:
                    print("Invalid choice. File not created.")
            else:
                print(f"'{file_name}' not created.")
            clear_terminal()
            main_menu()

# Main script execution
if __name__ == "__main__":

    time.sleep(2)
    file_check()
    clear_terminal()

def main_menu():

    print("""
 ::::::::  :::    :::  ::::::::   :::::::: ::::::::::: :::     ::: ::::::::::: ::::::::  :::::::::: 
:+:    :+: :+:    :+: :+:    :+: :+:    :+:    :+:     :+:     :+:     :+:    :+:    :+: :+:        
+:+        +:+    +:+ +:+    +:+ +:+           +:+     +:+     +:+     +:+    +:+        +:+        
:#:        +#++:++#++ +#+    +:+ +#++:++#++    +#+     +#+     +:+     +#+    +#+        +#++:++#   
+#+   +#+# +#+    +#+ +#+    +#+        +#+    +#+      +#+   +#+      +#+    +#+        +#+        
#+#    #+# #+#    #+# #+#    #+# #+#    #+#    #+#       #+#+#+#       #+#    #+#    #+# #+#        
 ########  ###    ###  ########   ########     ###         ###     ########### ########  ########## 
    """)

    time.sleep(1)
    print("Files Checked.")
    print("ips.txt, hashes.txt, and hosts.txt have been checked for creation.")
    print("Please ensure they are populated with the correct values you wish to query.")
    time.sleep(2)
    print("Loading Main Menu...")
    time.sleep(1)

    api_keys = utils.load_api_keys()  # Load API keys here
    if not api_keys:
        print("No API keys found. Please set them first (Option 1).")
    
    
    def option_1():        
        clear_terminal()
        print("Setting API Keys\n")
        api_keys = utils.load_api_keys()

        print("Current API Keys (press Enter to skip/leave unchanged):")
        print(f"  VirusTotal: {api_keys.get('VirusTotal', 'Not set')}")
        print(f"  AbuseIPDB: {api_keys.get('AbuseIPDB', 'Not set')}\n")

        # Prompt for VirusTotal API key
        virustotal_key = input("Enter VirusTotal API Key: ").strip()
        if virustotal_key == "":
            virustotal_key = api_keys.get('VirusTotal', '')

        # Prompt for AbuseIPDB API key
        abuseipdb_key = input("Enter AbuseIPDB API Key: ").strip()
        if abuseipdb_key == "":
            abuseipdb_key = api_keys.get('AbuseIPDB', '')
        # Save API keys
        utils.save_api_keys({'VirusTotal': virustotal_key, 'AbuseIPDB': abuseipdb_key})

        print("\nAPI Keys saved:")
        print(f"  VirusTotal: {virustotal_key if virustotal_key else 'Not set'}")
        print(f"  AbuseIPDB: {abuseipdb_key if abuseipdb_key else 'Not set'}\n")
        print("Returning to Main Menu.")



    while True:
        clear_terminal()
        # Function to copy and paste IPs/Hashes/Hosts
        def option_6():
            print("\nChoose which file to paste into:")
            print("1. ips.txt")
            print("2. hashes.txt")
            print("3. hosts.txt")
            file_choice = input("Enter your choice (1-3): ")

            if file_choice in ['1', '2', '3']:
                if file_choice == '1':
                    file_name = 'ips.txt'
                elif file_choice == '2':
                    file_name = 'hashes.txt'
                else:
                    file_name = 'hosts.txt'

                print(f"Paste the content for '{file_name}' here (press Ctrl+D when done):")
                lines = []
                try:
                    lines = sys.stdin.read().splitlines()
                except EOFError:
                    pass  # End of input reached
                content = '\n'.join(lines)
                with open(file_name, 'w') as f:
                    try:
                        content = '\n'.join(line.strip() for line in content.splitlines() if line.strip())
                        # Removing empty lines and extra characters from the string
                        

                        f.write(content)
                        print(f"Content pasted into '{file_name}'.")
                    except Exception as e:
                        print(f"Error pasting content into '{file_name}': {e}")
            else:
                print("Invalid choice. Please select 1, 2, or 3.")
        #Function to delete and refresh files.
        def option_7():
            print("\nChoose which file to delete and refresh:")
            print("1. ips.txt")
            print("2. hashes.txt")
            print("3. hosts.txt")
            file_choice = input("Enter your choice (1-3): ")

            if file_choice in ['1', '2', '3']:
                if file_choice == '1':
                    file_name = 'ips.txt'
                elif file_choice == '2':
                    file_name = 'hashes.txt'
                else:
                    file_name = 'hosts.txt'
                if os.path.exists(file_name):
                    os.remove(file_name)
                    print(f"'{file_name}' has been deleted.")
                    file_check()
                else:
                    print(f"'{file_name}' does not exist.")
            else:
                print("Invalid choice. Please select 1, 2, or 3.")
        print("\nMain Menu:")
        print("1. Set API Keys for VirusTotal & AbuseIPDB")
        print("2. Run Reputation Analysis for IPv4 Addresses")
        print("3. Run Repuation Analysis for SHA256 Hashes")
        print("4. Run Repuation Analysis for Remote Hosts")
        print("5. Extract Above Indicators from a text file.")
        print("6. Copy & Paste IPs/Hashes/Hosts into respective files.")
        print("7. Delete and Refresh Ips.txt, Hashes.txt, Hosts.txt")
        print("8. Read from indicators.csv and write to ips.txt, hosts.txt, hashes.txt")
        print("E. Exit")

        choice = input("Enter your choice (1-7), or 'e' to exit: ").lower()
        api_keys = utils.load_api_keys()  # Load API keys here again for option 2

        if choice == '1':
            option_1()
        elif choice == '2':
            ip_list = read_ip_list()
            if ip_list:
                print("Gathering reputation report for IP addresses....")
                print(f"Using the following VirusTotal API Key for IP Reputation Report: {api_keys['VirusTotal']}")
                print(f"Using the following AbuseIPDB API Key for IP Reputation Report: {api_keys['AbuseIPDB']}")
                results = get_ip_reputations(ip_list, api_keys)
                save_to_csv(results)   
                print("Reputation report has been saved to ip_output.csv")
            else:
                print("\nNo valid IP addresses found in ips.txt")
        elif choice == '3':
            hash_list = read_hash_list()
            if hash_list:
                results = get_hash_reputations(hash_list, api_keys)
                save_to_csv(results, filename='hash_output.csv')
                print("Reputation report for hashes has been saved to hash_output.csv")
            else:
                print("\nNo valid SHA256 hashes found in hashes.txt")
        elif choice == '4':
            host_list = read_remote_host_list()
            if host_list:
                print("Gathering reputation report for remote hosts...")
                results = get_host_reputations(host_list, api_keys)
                save_host_to_csv(results)  
                print("Reputation report for hosts has been saved to host_output.csv")
            else:
                

                print("\nNo valid hosts found in hosts.txt")
        elif choice == '5':
            print("Extracting indicators from text file")
            file_name = 'search.txt'           
            option_5_enhanced(api_keys)
            if os.path.exists(file_name):
                ips, domains, hashes = extract_indicators(file_name)
                if ips or domains or hashes:
                    utils.create_csv_file_from_indicators(ips, domains, hashes)
            
                else:
                    print("No indicators were extracted. indicators.csv was not created.")

        elif choice == '6':
            option_6()
        elif choice == '7':
            option_7()
        elif choice == '8':
            print("Reading indicators from indicators.csv...")
            extract_from_csv()
        elif choice == 'e':
            print("Exiting...")
            clear_terminal()
            break
        else:
            print("Invalid choice. Please try again.")


main_menu()
