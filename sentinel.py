import os
from collections import Counter

def run_sentinel():
    log_file = "access.log"
    blacklist_file = "blacklist.txt"
    
    if not os.path.exists(log_file) or not os.path.exists(blacklist_file):
        print(f"[-] Missing files: Ensure '{log_file}' and '{blacklist_file}' are in this folder.")
        return

    # 1. Load the provided threat data
    try:
        with open(blacklist_file, "r") as f:
            blacklist = {line.strip() for line in f if line.strip() and not line.startswith("#")}
    except Exception as e:
        print(f"[-] Error loading blacklist: {e}")
        return

    threat_hits = []
    total_lines = 0

    # 2. Analyze the log file
    try:
        print(f"[*] Analyzing {log_file}...")
        with open(log_file, "r") as f:
            for line in f:
                total_lines += 1
                parts = line.split()
                if not parts:
                    continue
                
                # IP is usually the first element in server logs
                ip = parts[0]
                if ip in blacklist:
                    threat_hits.append(ip)

        # 3. Process Data for Insights
        counts = Counter(threat_hits)
        unique_malicious = len(counts)
        
        print("\n" + "="*50)
        print(f"LOG ANALYSIS SUMMARY")
        print("="*50)
        print(f"Total Log Entries: {total_lines}")
        print(f"Total Malicious Matches: {len(threat_hits)}")
        print(f"Unique Malicious IPs: {unique_malicious}")
        print("="*50)

        if threat_hits:
            print(f"{'IP Address':<20} | {'Hits':<10} | {'% of Traffic'}")
            print("-" * 50)
            for ip, count in counts.most_common():
                percentage = (count / total_lines) * 100
                print(f"{ip:<20} | {count:<10} | {percentage:.2f}%")
        else:
            print("[+] No malicious IPs from the blacklist were found in the logs.")

    except Exception as e:
        print(f"[-] Error parsing logs: {e}")

if __name__ == "__main__":
    run_sentinel()