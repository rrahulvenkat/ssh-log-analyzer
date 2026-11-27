"""Detect SSH brute-force attempts in structured OpenSSH logs.

Reads a structured OpenSSH log CSV (the Loghub format), finds every
failed and successful SSH login, and reports each source IP with its
total failed logins, the peak number of failures inside a rolling time
window, the usernames it tried, and whether it went on to log in
successfully after crossing the brute-force threshold.

Usage:
    python openssh_regex.py [LOG_CSV] [--threshold 5] [--window 10] [--year 2026]

Exit codes: 0 no brute force found, 1 brute force found, 2 error.

Author: Rahul Venkat Ravishankar
Date: 2026-09-18 (revised 2026-11-27)

Each change from the first version is marked "FIX n" in the comments.
"""

import argparse
import csv
import ipaddress
import re
import sys
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

# FIX 4: the default log path is worked out from THIS FILE's location, not
# from whatever folder the script happens to be run in. Any other path can
# be passed on the command line.
DEFAULT_LOG = Path(__file__).resolve().parent / "data" / "OpenSSH_2k.log_structured.csv"

# Detection settings: flag an IP when this many failures occur in the time window.
BRUTE_FORCE_THRESHOLD = 5
TIME_WINDOW_MINUTES = 10

# FIX 6: columns are found by NAME, so an extra or reordered column can't
# silently shift every field. These are the ones the script needs.
REQUIRED_COLUMNS = {"Date", "Day", "Time", "Content"}

# FIX 3 and FIX 8: instead of grabbing the first IPv4-looking text anywhere in
# the line, match sshd's own sentence structure and take whatever follows
# "from". That covers IPv6 as well as IPv4, and any authentication method
# ("Failed password", "Failed publickey", "Failed keyboard-interactive/pam").
FAILED = re.compile(
    r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+")
ACCEPTED = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")
# syslog collapses identical lines into one: "message repeated 3 times: [ ... ]".
REPEATED = re.compile(r"message repeated (?P<times>\d+) times: \[ ?(?P<message>.*?) ?\]$")

# English month names, written out so parsing doesn't depend on the computer's
# language setting (which %b in strptime does).
MONTHS = {name: number for number, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
    start=1)}


@dataclass
class LoginEvent:
    time: datetime
    ip: str
    user: str
    success: bool


@dataclass
class IPReport:
    ip: str
    failures: int = 0
    peak: int = 0                       # most failures inside any one window
    users: set = field(default_factory=set)
    flagged_at: datetime | None = None  # when the threshold was first reached
    success_after: LoginEvent | None = None   # FIX 9: a login AFTER being flagged

    @property
    def brute_force(self):
        return self.flagged_at is not None


# ---------------------------------------------------------------------------
# FIX 1 and FIX 2: timestamps with a real year
# ---------------------------------------------------------------------------
# Syslog lines have no year. Parsing "Dec 31 23:59" without one gives the year
# 1900, which (1) puts Dec 31 364 days AFTER Jan 1, so bursts across New Year
# are split, and (2) makes "Feb 29" raise ValueError, because 1900 wasn't a
# leap year. Python 3.13 already warns about this, and 3.15 will change it.
#
# The fix: start from a known year (--year, the year of the FIRST line) and,
# since log lines are in time order, move to the next year whenever the month
# goes backwards (Dec -> Jan). Times are treated as UTC.

class SyslogClock:
    def __init__(self, year):
        self.year = year
        self.previous_month = None

    def parse(self, month_name, day, clock_time):
        month = MONTHS.get(month_name)
        if month is None:
            raise ValueError(f"unknown month {month_name!r}")
        year = self.year
        if self.previous_month is not None and month < self.previous_month:
            year += 1                                    # e.g. Dec -> Jan: a new year
        hour, minute, second = (int(part) for part in clock_time.split(":"))
        when = datetime(year, month, int(day), hour, minute, second, tzinfo=timezone.utc)
        # Only remember the year and month once the date is known to be valid.
        self.year, self.previous_month = year, month
        return when


def parse_ip(text):
    """Return the address in standard form, or None if it isn't an IP address."""
    try:
        return str(ipaddress.ip_address(text))           # FIX 3: IPv4 and IPv6
    except ValueError:
        return None


def warn(message):
    print(f"warning: {message}", file=sys.stderr)


def read_events(lines, year, on_warning=warn):
    """Yield a LoginEvent for every failed or successful SSH login in the CSV."""
    reader = csv.DictReader(lines)                       # FIX 6
    missing = REQUIRED_COLUMNS - set(reader.fieldnames or [])
    if missing:
        raise ValueError(f"the CSV is missing columns: {', '.join(sorted(missing))}")

    clock = SyslogClock(year)
    for row in reader:
        try:
            when = clock.parse(row["Date"], row["Day"], row["Time"])
        except (ValueError, TypeError) as err:
            # FIX 2: one bad date is reported and skipped; it doesn't stop the run.
            on_warning(f"line {reader.line_num}: skipped, bad timestamp ({err})")
            continue

        content = row["Content"] or ""
        times = 1
        repeated = REPEATED.search(content)
        if repeated:                                     # FIX 8
            times = int(repeated["times"])
            content = repeated["message"]

        match = FAILED.search(content)
        success = False
        if match is None:
            match = ACCEPTED.search(content)
            success = True
        if match is None:
            continue                                     # not a login line

        ip = parse_ip(match["ip"])
        if ip is None:
            # FIX 3: an address we can't read is reported, never silently dropped.
            on_warning(f"line {reader.line_num}: skipped, unrecognised address {match['ip']!r}")
            continue
        for _ in range(times):
            yield LoginEvent(when, ip, match["user"], success)


# ---------------------------------------------------------------------------
# FIX 7: the rolling window in one pass
# ---------------------------------------------------------------------------
# The first version restarted a count from EVERY failure, which is O(n^2) per
# IP. Here a deque holds just the failures inside the current window: add the
# new one on the right, drop old ones from the left, and the deque's length IS
# the count. Each failure is added and removed once, so it's O(n).

def analyse(events, threshold=BRUTE_FORCE_THRESHOLD,
            window=timedelta(minutes=TIME_WINDOW_MINUTES)):
    events_by_ip = defaultdict(list)
    for event in events:
        events_by_ip[event.ip].append(event)

    reports = []
    for ip, ip_events in events_by_ip.items():
        ip_events.sort(key=lambda e: e.time)             # sort is stable: file order on ties
        report = IPReport(ip)
        recent = deque()
        for event in ip_events:
            if event.success:
                if report.flagged_at is not None and report.success_after is None:
                    report.success_after = event         # FIX 9
                continue
            report.failures += 1
            report.users.add(event.user)
            recent.append(event.time)
            while event.time - recent[0] > window:       # same "within the window"
                recent.popleft()                         # rule as before (<= window)
            report.peak = max(report.peak, len(recent))
            if report.flagged_at is None and len(recent) >= threshold:
                report.flagged_at = event.time
        if report.failures:
            reports.append(report)

    return sorted(reports, key=lambda r: (-r.failures, r.ip))


def print_report(reports, threshold, window_minutes, out=sys.stdout):
    print(f"{'IP Address':<26} {'Failed':>6} {'Peak':>5}  {'Brute Force?':<13} Users tried",
          file=out)
    for r in reports:
        # FIX 9: one wording for both cases, instead of two near-identical strings.
        users = ", ".join(sorted(r.users))
        print(f"{r.ip:<26} {r.failures:>6} {r.peak:>5}  {'Yes' if r.brute_force else 'No':<13} "
              f"{users}", file=out)
        if r.success_after:
            s = r.success_after
            print(f"{'':<26} !!! then logged in as {s.user!r} at "
                  f"{s.time:%Y-%m-%d %H:%M:%S} UTC", file=out)
    print(f"\nPeak = most failures within {window_minutes} minutes; "
          f"brute force = a peak of {threshold} or more.", file=out)


# ---------------------------------------------------------------------------
# FIX 5: a main() that takes its arguments, so it can be tested and reused
# ---------------------------------------------------------------------------

def positive_int(text):
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {value}")
    return value


def build_parser():
    parser = argparse.ArgumentParser(description="Find SSH brute-force attempts in a "
                                                 "structured OpenSSH log CSV.")
    parser.add_argument("log", nargs="?", type=Path, default=DEFAULT_LOG,
                        help="the CSV to read (default: data/OpenSSH_2k.log_structured.csv "
                             "next to this script)")
    parser.add_argument("--threshold", type=positive_int, default=BRUTE_FORCE_THRESHOLD,
                        help="failures in one window to count as brute force (default: %(default)s)")
    parser.add_argument("--window", type=positive_int, default=TIME_WINDOW_MINUTES,
                        help="window length in minutes (default: %(default)s)")
    parser.add_argument("--year", type=int, default=datetime.now(timezone.utc).year,
                        help="year of the FIRST line; syslog lines don't include one "
                             "(default: this year)")
    return parser


def main(argv=None, out=sys.stdout):
    args = build_parser().parse_args(argv)
    try:
        with open(args.log, newline="", encoding="utf-8") as file:
            events = list(read_events(file, args.year))
    except FileNotFoundError:
        print(f"error: {args.log} not found", file=sys.stderr)
        return 2
    except ValueError as err:
        print(f"error: {args.log}: {err}", file=sys.stderr)
        return 2

    reports = analyse(events, args.threshold, timedelta(minutes=args.window))
    print_report(reports, args.threshold, args.window, out)
    return 1 if any(r.brute_force for r in reports) else 0


if __name__ == "__main__":
    sys.exit(main())
