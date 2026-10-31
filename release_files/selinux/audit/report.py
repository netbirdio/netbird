#!/usr/bin/env python3
"""Maps the audit records of netbird_t to the feature that was running.

usage: report.py <start-epoch> <marks-file>... > report.tsv

A marks file holds one line per boundary, "<epoch> S <name>" when a feature starts and
"<epoch> E <name>" when it ends. Records that fall in no window are reported under
"(outside-tests)". Reads /var/log/audit/audit.log and its rotations. Needs the
netbirdaudit module for the "granted" records, see ../README.md.
"""
import glob
import re
import sys
from collections import defaultdict

RECORD = re.compile(
    r"audit\((\d+\.\d+):\d+\): avc:\s+(granted|denied)\s+\{ ([^}]*) \} for\s+(.*?)\s*"
    r"scontext=\S+?:\S+?:(\S+?):\S+ tcontext=\S+?:\S+?:(\S+?):\S+ tclass=(\S+)"
)
COMM = re.compile(r'comm="([^"]*)"')


def read_windows(paths):
    windows = []
    for path in paths:
        started = {}
        with open(path) as marks:
            for line in marks:
                parts = line.split()
                if len(parts) < 3:
                    continue
                stamp, kind, name = float(parts[0]), parts[1], parts[2]
                if kind == "S":
                    started[name] = stamp
                elif kind == "E" and name in started:
                    windows.append((started.pop(name), stamp, name))
    return windows


def window_of(windows, stamp):
    for start, end, name in windows:
        if start - 0.05 <= stamp <= end + 0.5:
            return name
    return "(outside-tests)"


def main():
    since = float(sys.argv[1])
    windows = read_windows(sys.argv[2:])

    counts = defaultdict(lambda: defaultdict(int))
    commands = defaultdict(set)
    for path in sorted(glob.glob("/var/log/audit/audit.log*")):
        with open(path, errors="replace") as log:
            for line in log:
                if "avc:" not in line or "netbird_t" not in line:
                    continue
                match = RECORD.search(line)
                if not match:
                    continue
                stamp, verdict, perms, _, source, target, tclass = match.groups()
                if float(stamp) < since or source != "netbird_t":
                    continue
                comm = COMM.search(line)
                name = comm.group(1) if comm else "?"
                for perm in perms.split():
                    key = (verdict, tclass, perm, target)
                    counts[key][window_of(windows, float(stamp))] += 1
                    commands[key].add(name)

    print("verdict\tclass\tperm\ttarget\tcommands\ttotal\tscenarios")
    for key in sorted(counts):
        per_window = counts[key]
        top = ",".join(f"{w}:{n}" for w, n in sorted(per_window.items(), key=lambda x: -x[1])[:12])
        print("\t".join([*key, ",".join(sorted(commands[key]))[:60], str(sum(per_window.values())), top]))


if __name__ == "__main__":
    main()
