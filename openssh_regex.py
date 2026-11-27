"""Detect SSH brute-force attempts in structured OpenSSH logs.

Reads the structured OpenSSH log CSV, extracts the source IP from every
"Failed password" event, and reports each IP alongside its total failed
logins and whether its peak number of failures inside a rolling time
window crosses the brute-force threshold.

Author: Rahul Venkat Ravishankar
Date: 2026-09-18
"""

import csv
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# Detection settings: flag an IP when this many failures occur in the time window.
IP_PATTERN = r"(?:\d{1,3}\.){3}\d{1,3}"
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10

# Store each IP's total failures and the timestamps needed for rolling-window checks.
failed_logins_by_ip = Counter()
failed_login_times_by_ip = defaultdict(list)

with open("data/OpenSSH_2k.log_structured.csv", newline="", encoding="utf-8") as file:
    reader = csv.reader(file)
    next(reader)  # Skip the header row.

    for columns in reader:
        # CSV columns 1-3 are Date, Day, and Time; column 6 contains the log message.
        content = columns[6]
        timestamp = f"{columns[1]} {columns[2]} {columns[3]}"

        ip_address = re.search(IP_PATTERN, content)

        # Count only explicit SSH password failures and associate them with their source IP.
        if "Failed password" in content:
            if ip_address:
                failed_logins_by_ip[ip_address.group()] += 1
                event_time = datetime.strptime(timestamp, "%b %d %H:%M:%S")
                failed_login_times_by_ip[ip_address.group()].append(event_time)

# Convert the configured number of minutes into a duration for timestamp comparisons.
time_window = timedelta(minutes=TIME_WINDOW_MINUTES)
print(
    f"{'IP Address':<16} {'Failed Login Attempts':<23} "
    f"{'Brute Force?':<14} Reason"
)

for ip_address, count in failed_logins_by_ip.most_common():
    # Sort timestamps before evaluating all possible rolling window start times.
    timestamps = sorted(failed_login_times_by_ip[ip_address])
    maximum_failures = 0

    for start_index, start_time in enumerate(timestamps):
        failures_in_window = 0
        for event_time in timestamps[start_index:]:
            # Later events are outside this window, so no further events can qualify.
            if event_time - start_time <= time_window:
                failures_in_window += 1
            else:
                break

        if failures_in_window > maximum_failures:
            maximum_failures = failures_in_window

    # Flag the IP only when the peak failures in one window reaches the threshold.
    brute_force = "Yes" if maximum_failures >= BRUTE_FORCE_THRESHOLD else "No"
    if brute_force == "Yes":
        reason = (
            f"{maximum_failures} failures within {TIME_WINDOW_MINUTES} minutes "
            f"(threshold: {BRUTE_FORCE_THRESHOLD})"
        )
    else:
        reason = (
            f"Maximum {maximum_failures} failures within {TIME_WINDOW_MINUTES} minutes "
            f"(threshold: {BRUTE_FORCE_THRESHOLD})"
        )

    print(f"{ip_address:<16} {count:<23} {brute_force:<14} {reason}")
