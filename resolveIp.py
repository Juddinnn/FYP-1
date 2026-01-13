import socket

DOMAINS_FILE = "domains.txt"
RESOLVED_IPS_FILE = "resolved_ips.txt"

# Read all domains
with open(DOMAINS_FILE, 'r') as f:
    domains = [line.strip() for line in f if line.strip()]

resolved_ips = set()

with open(RESOLVED_IPS_FILE, 'w') as out:
    for domain in domains:
        try:
            # Get all IPv4 addresses
            infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
            ips = {info[4][0] for info in infos}
            if ips:
                print(f"{domain} → {', '.join(ips)}")
                for ip in ips:
                    if ip not in resolved_ips:
                        resolved_ips.add(ip)
                        out.write(ip + "\n")
            else:
                print(f"{domain} → no A records")
        except socket.gaierror:
            print(f"{domain} → lookup failed")

# YOU WILL GET RESOLVED IPS IN resolved_ips.txt
# Can now use query_virustotal.py to check these IPs against VirusTotal!