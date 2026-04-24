# Log Matcher & Threat Parser
A script that identifies matches between local system logs and a user-provided list of malicious IP addresses.

### Features
- **IP Matching**: Scans log files for entries that exist within a provided blacklist.
- **Traffic Analysis**: Calculates the hit count and the percentage of total log traffic for each identified IP.
- **Offline Operation**: Operates entirely on local files without external network requests.

### Data Requirements
Users must provide two files in the same directory as the script:
1. `access.log`: The log file to be analyzed (standard space-separated format).
2. `blacklist.txt`: A list of known malicious IPs, one per line.

### How It Works
The script loads the `blacklist.txt` into a set for efficient comparison. It iterates through every line of the `access.log`, extracting the source IP. If a match is found, it is recorded. The final output provides a breakdown of how many times each flagged IP appeared and its impact as a percentage of the total log volume.

### Usage
`python sentinel.py`
