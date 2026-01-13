import os
import re

# 1. Configuration: point to your logs folder
DATASET_DIR = r"C:\Users\kyrai\Desktop\fast-flux_dataset\FFWeb_168.95.1.1_Attack\fluxor"  # ← folder that contains all the dig .text files!

# 2. Regex for domains
DOMAIN_REGEX = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.IGNORECASE)

# 3. Collect domains
domains = set()
for fname in os.listdir(DATASET_DIR):
    if not fname.endswith(".txt"):
        continue
    path = os.path.join(DATASET_DIR, fname)
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            for match in DOMAIN_REGEX.findall(line):
                domains.add(match.lower())

# 4. Show a quick preview
print(f"Found {len(domains)} unique domains. Sample:")
for d in list(domains)[:10]:
    print(" ", d)

# 5. Save to domains.txt
with open("domains.txt", "w") as out:
    for d in sorted(domains):
        out.write(d + "\n")
print("Saved all domains to domains.txt")

# 6. Now you can run resolveIp.py to resolve the domains to IPs!