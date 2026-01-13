# FYP 1 – Fast Flux Detection System using Machine Learning

## Description
This project implements a **Fast Flux Detection System** using **Machine Learning** to identify and analyze fast flux domains. Fast flux is a technique used by cybercriminals to hide phishing and malware sites by frequently changing the IP addresses associated with a domain.

The system works in three main steps:
1. **Dataset Preparation:** Raw datasets of domains (text files) are cleaned using `build_new_dataset.py` to generate `domains.txt`.
2. **Domain Resolution:** `resolveIP.py` resolves each domain in `domains.txt` to its IP addresses, creating `resolved_ips.txt`.
3. **VirusTotal Verification:** Both `domains.txt` and `resolved_ips.txt` are processed using `query_virustotal.py` with the VirusTotal API to identify and extract **unique live domains** for analysis.

This workflow allows efficient detection of fast flux domains and helps analyze potentially malicious domains using a combination of data cleaning, domain resolution, and threat verification.

---

## How to Run
1. Place your raw dataset text files in the `raw_dataset` folder.
2. Run the dataset cleaning script:
```bash
python build_new_dataset.py
```
3. Resolve domains to IP addresses:
```bash
python resolveIP.py
```
4. Query VirusTotal to identify unique live domains:
```bash
python query_virustotal.py
```
After completing these steps, you will have a list of verified, unique, live domains ready for analysis.

## Requirements

- Python 3.x
- requests library (for API calls)
- VirusTotal API key (set in query_virustotal.py)


