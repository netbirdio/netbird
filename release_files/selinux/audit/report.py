#!/usr/bin/env python3
"""Maps the audit records of netbird_t to the feature that was running.

usage: cat <marks-file>... | report.py <start-epoch> > report.tsv

The marks are read from standard input, one line per boundary: "<epoch> S <name>" when a
feature starts and "<epoch> E <name>" when it ends. Every start needs its own end: a
repeated start, an end without a start, an end before its start, a window left open, a line
that is not exactly three fields and any other kind are errors. A record inside
a window is reported under that feature, a record within a short padding around a window
under the closest one, and any other under "(outside-tests)". Reads /var/log/audit/audit.log
and its rotations. The "granted" records come from the netbirdaudit module next to this file.
"""
import glob
import math
import re
import sys
from collections import defaultdict

RECORD = re.compile(
    r"audit\((\d+\.\d+):\d+\): avc:\s+(granted|denied)\s+\{ ([^}]*) \} for\s+(.*?)\s*"
    r"scontext=\S+?:\S+?:(\S+?):\S+ tcontext=\S+?:\S+?:(\S+?):\S+ tclass=(\S+)"
)
COMM = re.compile(r'comm="([^"]*)"')


def parse_mark(line):
    """Returns (stamp, kind, name) for a mark line, or None for a blank line."""
    parts = line.split()
    if not parts:
        return None
    if len(parts) != 3:
        sys.exit(f"report.py: malformed mark {line.strip()!r}, expected '<epoch> S|E <name>'")
    try:
        stamp = float(parts[0])
    except ValueError:
        stamp = math.nan
    if not math.isfinite(stamp):
        sys.exit(f"report.py: invalid mark timestamp {parts[0]!r}")
    return stamp, parts[1], parts[2]


def start_window(started, stamp, name):
    if name in started:
        sys.exit(f"report.py: window {name} started twice without an end")
    started[name] = stamp


def end_window(started, windows, stamp, name):
    if name not in started:
        sys.exit(f"report.py: window {name} ended without a start")
    begin = started.pop(name)
    if stamp < begin:
        sys.exit(f"report.py: window {name} ends at {stamp} before it starts at {begin}")
    windows.append((begin, stamp, name))


def read_windows(marks):
    windows = []
    started = {}
    for line in marks:
        mark = parse_mark(line)
        if mark is None:
            continue
        stamp, kind, name = mark
        if kind == "S":
            start_window(started, stamp, name)
        elif kind == "E":
            end_window(started, windows, stamp, name)
        else:
            sys.exit(f"report.py: unknown mark kind {kind!r} for window {name}, expected S or E")
    if started:
        sys.exit(f"report.py: window {min(started)} has no end")
    return windows


def window_of(windows, stamp):
    # A record inside a window belongs to it, whatever the padding of a neighbour says.
    for start, end, name in windows:
        if start <= stamp <= end:
            return name
    candidates = [
        (start - stamp if stamp < start else stamp - end, name)
        for start, end, name in windows
        if start - 0.05 <= stamp <= end + 0.5
    ]
    if not candidates:
        return "(outside-tests)"
    return min(candidates, key=lambda candidate: candidate[0])[1]


def parse_record(line, since):
    """Returns (stamp, verdict, perms, target, tclass, comm) for a netbird_t record, or None."""
    if "avc:" not in line or "netbird_t" not in line:
        return None
    match = RECORD.search(line)
    if not match:
        return None
    stamp, verdict, perms, _, source, target, tclass = match.groups()
    if float(stamp) < since or source != "netbird_t":
        return None
    comm = COMM.search(line)
    return float(stamp), verdict, perms, target, tclass, comm.group(1) if comm else "?"


def count_records(since, windows):
    counts = defaultdict(lambda: defaultdict(int))
    commands = defaultdict(set)
    for path in sorted(glob.glob("/var/log/audit/audit.log*")):
        with open(path, errors="replace") as log:
            for line in log:
                record = parse_record(line, since)
                if record is None:
                    continue
                stamp, verdict, perms, target, tclass, name = record
                for perm in perms.split():
                    key = (verdict, tclass, perm, target)
                    counts[key][window_of(windows, stamp)] += 1
                    commands[key].add(name)
    return counts, commands


def print_report(counts, commands):
    print("verdict\tclass\tperm\ttarget\tcommands\ttotal\tscenarios")
    for key in sorted(counts):
        per_window = counts[key]
        top = ",".join(f"{w}:{n}" for w, n in sorted(per_window.items(), key=lambda x: -x[1]))
        print("\t".join([*key, ",".join(sorted(commands[key])), str(sum(per_window.values())), top]))


def read_since(args):
    try:
        since = float(args[1])
    except (IndexError, ValueError):
        sys.exit("usage: cat <marks-file>... | report.py <start-epoch>")
    if not math.isfinite(since):
        sys.exit(f"report.py: invalid start epoch {args[1]!r}")
    return since


def main():
    since = read_since(sys.argv)
    windows = read_windows(sys.stdin)
    counts, commands = count_records(since, windows)
    print_report(counts, commands)


if __name__ == "__main__":
    main()
