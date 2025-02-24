import csv
import requests
import time

# Replace with your actual API keys
VIRUSTOTAL_API_KEY = '75b56f6fd05e8f13665ab13b32374e00be5845862bbee48ed36445adc738647a'
ABUSEIPDB_API_KEY = '222f5a57ecc1b893b32d7b77e0e43c6373ceedc918b302550a6cbde5af617834c233a6e426439159'

# Function to query VirusTotal
def query_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    
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
def query_abuseipdb(ip):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
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
            print(f"Unsuccessful API call for {ip} to AbuseIPDB. Check your API Key.")
            return {'ip': ip, 'abuseipdb_reputation': 'Error: ' + str(response.status_code)}
    except Exception as e:
        return {'ip': ip, 'abuseipdb_reputation': 'Error: ' + str(e)}

# Main function to handle IP list and query APIs
def get_ip_reputations(ip_list):
    results = []
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
    for ip in ip_list:
        print(f"Processing IP: {ip}")
        virustotal_data = query_virustotal(ip)
        abuseipdb_data = query_abuseipdb(ip)
        
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

# Main script execution
if __name__ == "__main__":
    ip_list = read_ip_list('input.txt')  # Read list of IPs from txt file
    results = get_ip_reputations(ip_list)  # Query the APIs for each IP
    save_to_csv(results)  # Save the results to a CSV
    print("Reputation report has been saved to output.csv")
