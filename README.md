# ssh-log-analyzer

Detects SSH brute-force attempts in OpenSSH logs using regular expressions.

> **Part of a four-step series on SSH brute-force detection:**
> 1. **ssh-log-analyzer** (this repo): regex rules
> 2. [log-analyzer-agent](https://github.com/rrahulvenkat/log-analyzer-agent): Claude reads each line
> 3. [ssh-detection-eval](https://github.com/rrahulvenkat/ssh-detection-eval): the two compared
> 4. [ssh-hybrid-detector](https://github.com/rrahulvenkat/ssh-hybrid-detector): rules first, Claude for the rest

[log-analyzer-agent](https://github.com/rrahulvenkat/log-analyzer-agent) solves
the same problem with an LLM. This version is free, instant and predictable;
that one can read log lines nobody wrote a pattern for.

For every source IP it reports the total failed logins, the peak number of
failures inside a rolling time window, the usernames tried, and whether the
IP went on to **log in successfully** after crossing the brute-force threshold.

## Input

A structured OpenSSH log CSV in the [Loghub](https://github.com/logpai/loghub)
format, with at least these columns: `Date` (month), `Day`, `Time`, `Content`.
By default it reads `data/OpenSSH_2k.log_structured.csv` next to the script.

The data isn't in this repository (`data/` is in `.gitignore`, so logs are
never committed by accident). Download `OpenSSH_2k.log_structured.csv` from the
`OpenSSH` folder of the Loghub repository into `data/`, or pass the path to
your own file.

**On a real server:** this tool reads only Loghub's CSV, not a raw
`/var/log/auth.log`. To scan a real server's logs, use
[ssh-hybrid-detector](https://github.com/rrahulvenkat/ssh-hybrid-detector):
`python hybrid.py /var/log/auth.log --no-llm` runs the same kind of
regex rules on raw syslog lines, free and offline.

## Usage

```
python main.py                                   # default data file
python main.py path/to/log.csv
python main.py log.csv --threshold 3 --window 5  # 3 failures within 5 minutes
python main.py log.csv --year 2015               # year of the FIRST line
```

Syslog timestamps have no year, so pass `--year` for the year the log starts
in. The year moves on automatically when the log crosses from December to
January. Times are treated as UTC.

Exit codes: `0` no brute force found, `1` brute force found, `2` error, so
it can be used in scripts: `python main.py log.csv || echo "brute force"`.

Example output:

```
IP Address                 Failed  Peak  Brute Force?  Users tried
198.51.100.7                    9     6  Yes           admin, root
                           !!! then logged in as 'root' at 2026-11-27 10:15:31 UTC
2001:db8::7                     6     6  Yes           root
192.0.2.50                      2     1  No            bob

Peak = most failures within 10 minutes; brute force = a peak of 5 or more.
```

## What counts as a failed login

Any `Failed <method> for <user> from <ip> port <n>` line (password, publickey,
keyboard-interactive and so on), including ones syslog has collapsed into
`message repeated N times: [ ... ]`, which count N times. `Invalid user ...`
and PAM `authentication failure` lines are **not** counted separately, because
sshd also writes a `Failed ...` line for the same attempt, so counting them too
would count each attempt twice. IPv4 and IPv6 addresses are both supported.

## Tests

```
python test_openssh_regex.py      # or: pytest
```
