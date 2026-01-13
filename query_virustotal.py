import os
import json
import time
import requests

# Configuration
RESOLVED_IPS_FILE = "resolved_ips.txt"
VT_DOMAINS_FILE  = "domains.txt"
NEW_DATASET_FILE = "new_dataset.txt"
VT_API_KEY       = "GET YOUR OWN CODE AT https://www.virustotal.com/gui/join-us"

if not VT_API_KEY:
    raise RuntimeError("Please set VT_API_KEY")

headers = {
    "x-apikey": VT_API_KEY
}

vt_domains = set()

with open(RESOLVED_IPS_FILE) as f:
    ips = [line.strip() for line in f if line.strip()]

try:
    for idx, ip in enumerate(ips, 1):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}/resolutions"
        print(f"[{idx}/{len(ips)}] Querying {ip}...", end=" ")

        try:
            resp = requests.get(url, headers=headers, timeout=15)

            if resp.status_code == 200:
                data = resp.json().get("data", [])
                names = {
                    entry["attributes"]["host_name"]
                    for entry in data
                    if entry.get("attributes", {}).get("host_name")
                }

                if names:
                    print(f"found {len(names)} domains")
                    vt_domains.update(names)
                else:
                    print("no domains")

            elif resp.status_code == 429:
                print("rate limited — sleeping longer")
                time.sleep(60)

            else:
                print(f"HTTP error {resp.status_code}")

        except requests.exceptions.ConnectTimeout:
            print("timeout — skipped")

        except requests.exceptions.RequestException as e:
            print(f"request failed — skipped ({e})")

        # VirusTotal free API safety
        time.sleep(16)

except KeyboardInterrupt:
    print("\n🛑 Stopped by user (Ctrl+C)")

# Save results
with open(VT_DOMAINS_FILE, "w") as f:
    for d in sorted(vt_domains):
        f.write(d + "\n")

with open(NEW_DATASET_FILE, "w") as f:
    for d in sorted(vt_domains):
        f.write(d + "\n")

print(f"\n✅ Completed: {len(vt_domains)} unique domains written to {NEW_DATASET_FILE}")
