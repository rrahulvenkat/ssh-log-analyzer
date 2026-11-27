"""Tests for openssh_regex.py.

Run with:  python test_openssh_regex.py     (or: pytest)

Each test that guards a fix says which one.
"""

import io
import random
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from openssh_regex import analyse, main, print_report, read_events

HEADER = "LineId,Date,Day,Time,Component,Pid,Content,EventId,EventTemplate"


def csv_text(rows):
    """rows: (month, day, time, content) -> a Loghub-style CSV string."""
    lines = [HEADER]
    for i, (month, day, clock, content) in enumerate(rows, start=1):
        lines.append(f'{i},{month},{day},{clock},LabSZ,{1000 + i},"{content}",E1,template')
    return "\n".join(lines) + "\n"


def fail(ip, user="root", method="password"):
    return f"Failed {method} for {user} from {ip} port 51122 ssh2"


def run(rows, year=2026, warnings=None, **kwargs):
    on_warning = warnings.append if warnings is not None else (lambda message: None)
    events = list(read_events(io.StringIO(csv_text(rows)), year, on_warning))
    return analyse(events, **kwargs)


def test_burst_across_new_year():                                       # FIX 1
    rows = [("Dec", 31, t, fail("10.0.0.1")) for t in ("23:58:00", "23:59:00")]
    rows += [("Jan", 1, t, fail("10.0.0.1")) for t in ("00:00:30", "00:01:00", "00:02:00")]
    [report] = run(rows, year=2026)
    assert report.peak == 5 and report.brute_force
    assert report.flagged_at == datetime(2027, 1, 1, 0, 2, tzinfo=timezone.utc)


def test_leap_day_parses_in_a_leap_year():                              # FIX 2
    [report] = run([("Feb", 29, "10:00:00", fail("10.0.0.9"))], year=2028)
    assert report.failures == 1


def test_impossible_date_is_skipped_not_fatal():                        # FIX 2
    warnings = []
    rows = [("Feb", 29, "10:00:00", fail("10.0.0.9")),      # 2027 isn't a leap year
            ("Mar", 1, "10:00:00", fail("10.0.0.9"))]
    [report] = run(rows, year=2027, warnings=warnings)
    assert report.failures == 1
    assert len(warnings) == 1 and "bad timestamp" in warnings[0]


def test_ipv6_is_counted_and_normalised():                              # FIX 3
    rows = [("Jan", 1, f"00:10:0{s}", fail("2001:0db8:0000::7")) for s in range(6)]
    [report] = run(rows)
    assert report.ip == "2001:db8::7" and report.failures == 6 and report.brute_force


def test_bad_address_is_reported_not_dropped_silently():                # FIX 3
    warnings = []
    assert run([("Jan", 1, "00:00:00", fail("999.1.1.1"))], warnings=warnings) == []
    assert "999.1.1.1" in warnings[0]


def test_any_auth_method_and_repeated_messages_count():                 # FIX 8
    rows = [("Jan", 1, "00:00:00", fail("10.0.0.2", method="publickey")),
            ("Jan", 1, "00:00:05", "message repeated 4 times: [ " + fail("10.0.0.2") + "]")]
    [report] = run(rows)
    assert report.failures == 5 and report.brute_force


def test_invalid_user_lines_are_not_double_counted():                   # FIX 8
    # sshd logs BOTH lines for one attempt on a non-existent account
    rows = [("Jan", 1, "00:00:00", "Invalid user admin from 10.0.0.3 port 40000"),
            ("Jan", 1, "00:00:01", fail("10.0.0.3", user="invalid user admin"))]
    [report] = run(rows)
    assert report.failures == 1 and report.users == {"admin"}


def test_usernames_with_spaces_are_still_counted():                    # FIX 10
    # a real evasion from the Loghub sample: a leading space in the username
    rows = [("Jan", 1, "00:00:00", fail("10.0.0.4", user="invalid user  0101")),
            ("Jan", 1, "00:00:01", fail("10.0.0.4", user="john smith"))]
    [report] = run(rows)
    assert report.failures == 2 and report.users == {" 0101", "john smith"}


def test_fake_from_inside_the_username_cannot_frame_another_ip():       # FIX 10
    rows = [("Jan", 1, f"00:00:0{s}",
             fail("10.0.0.5", user="invalid user x from 6.6.6.6 port 1")) for s in range(5)]
    [report] = run(rows)
    assert str(report.ip) == "10.0.0.5" and report.brute_force
    assert report.users == {"x from 6.6.6.6 port 1"}


def test_report_quotes_usernames_with_hidden_spaces():                  # FIX 10
    out = io.StringIO()
    events = read_events(io.StringIO(csv_text(
        [("Jan", 1, "00:00:00", fail("10.0.0.6", user="invalid user  0101"))])), 2026)
    print_report(analyse(events), 5, 10, out=out)
    assert "' 0101'" in out.getvalue()


def test_success_after_brute_force_is_reported():                       # FIX 9
    rows = [("Jan", 1, f"00:00:0{s}", fail("10.0.0.4")) for s in range(5)]
    rows.append(("Jan", 1, "00:00:30", "Accepted password for root from 10.0.0.4 port 1 ssh2"))
    [report] = run(rows)
    assert report.success_after is not None and report.success_after.user == "root"


def test_success_before_brute_force_is_not():                           # FIX 9
    rows = [("Jan", 1, "00:00:00", "Accepted password for root from 10.0.0.5 port 1 ssh2")]
    rows += [("Jan", 1, f"00:01:0{s}", fail("10.0.0.5")) for s in range(5)]
    [report] = run(rows)
    assert report.brute_force and report.success_after is None


def test_window_edge_is_inclusive():                                    # same rule as before
    rows = [("Jan", 1, "00:00:00", fail("10.0.0.6")), ("Jan", 1, "00:10:00", fail("10.0.0.6")),
            ("Jan", 1, "00:10:01", fail("10.0.0.6"))]
    [report] = run(rows, threshold=2, window=timedelta(minutes=10))
    assert report.peak == 2


def test_fast_window_matches_the_original_method():                     # FIX 7
    def original_peak(times, window):
        best = 0
        for i, start in enumerate(times):
            best = max(best, sum(1 for t in times[i:] if t - start <= window))
        return best

    rng = random.Random(1)
    for _ in range(50):
        seconds = sorted(rng.randint(0, 3600) for _ in range(rng.randint(1, 40)))
        rows = [("Jan", 1, f"{s // 3600:02d}:{s % 3600 // 60:02d}:{s % 60:02d}", fail("10.0.0.7"))
                for s in seconds]
        [report] = run(rows, window=timedelta(minutes=5))
        times = [datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=s) for s in seconds]
        assert report.peak == original_peak(times, timedelta(minutes=5))


def test_columns_are_read_by_name():                                    # FIX 6
    text = csv_text([("Jan", 1, "00:00:00", fail("10.0.0.8"))])
    header, row = text.strip().split("\n")
    reordered = "Extra," + header + "\n" + "x," + row + "\n"
    events = list(read_events(io.StringIO(reordered), 2026))
    assert events[0].ip == "10.0.0.8"
    try:
        list(read_events(io.StringIO("Date,Time\nJan,00:00:00\n"), 2026))
        assert False, "expected ValueError"
    except ValueError as err:
        assert "Content" in str(err)


def test_main_runs_from_any_folder_and_sets_exit_codes():               # FIX 4 and FIX 5
    with tempfile.TemporaryDirectory() as folder:
        log = Path(folder) / "auth.csv"
        log.write_text(csv_text([("Jan", 1, f"00:00:0{s}", fail("10.0.0.9")) for s in range(5)]))
        out = io.StringIO()
        assert main([str(log), "--year", "2026"], out=out) == 1          # found brute force
        assert "10.0.0.9" in out.getvalue()
        assert main([str(log), "--threshold", "50"], out=io.StringIO()) == 0
        assert main([str(Path(folder) / "missing.csv")], out=io.StringIO()) == 2


if __name__ == "__main__":
    tests = [value for name, value in sorted(globals().items()) if name.startswith("test_")]
    for test in tests:
        test()
        print(f"ok  {test.__name__}")
    print(f"\nAll {len(tests)} tests passed!")
