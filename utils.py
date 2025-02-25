import json

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
