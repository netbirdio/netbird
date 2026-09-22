#!/bin/sh
#
# Generate the changelog nfpm embeds into the RPM.
#
# chglog records the whole commit message for each entry. Pull requests are
# squashed on merge, so that body is usually the pull request description:
# template headings, review checklists, HTML comments and Co-authored-by
# trailers. None of that belongs in a package on Red Hat's catalog, and it is
# most of the changelog's size. Keep the subject line and drop the rest.

set -eu

go tool chglog init

python3 - changelog.yml <<'PYEOF'
import re
import sys

path = sys.argv[1]
lines = open(path, encoding="utf-8").read().split("\n")

NOTE = re.compile(r"^      note: (.*)$")
BLOCK = {"|", "|-", "|+", ">", ">-", ">+"}


def quote(text):
    """Render text as a YAML single-quoted scalar."""
    return "      note: '{}'".format(text.replace("'", "''"))


def first_line_of_double_quoted(value):
    """Text of a double-quoted scalar up to its first \\n escape."""
    out = []
    i = 1
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value):
            if value[i + 1] == "n":
                break
            out.append(value[i:i + 2])
            i += 2
            continue
        if c == '"':
            break
        out.append(c)
        i += 1
    return "".join(out).replace('\\"', '"').replace("\\\\", "\\")


out = []
seen = 0
i = 0
while i < len(lines):
    line = lines[i]
    m = NOTE.match(line)
    if not m:
        out.append(line)
        i += 1
        continue

    seen += 1
    value = m.group(1)

    if value in BLOCK:
        # Subject is the first non-empty body line; skip the rest of the block.
        i += 1
        subject = None
        while i < len(lines) and (lines[i] == "" or lines[i].startswith("        ")):
            if subject is None and lines[i].strip():
                subject = lines[i][8:]
            i += 1
        if subject is None:
            sys.exit("empty block scalar note near line {}".format(i))
        out.append(quote(subject))
        continue

    if value.startswith('"') and value.endswith('"') and len(value) > 1:
        out.append(quote(first_line_of_double_quoted(value)))
        i += 1
        continue

    if value.startswith("'") and value.endswith("'") and len(value) > 1:
        out.append(line)
        i += 1
        continue

    if not value.startswith(("'", '"')) and value not in BLOCK:
        out.append(line)
        i += 1
        continue

    sys.exit("unhandled note form at line {}: {!r}".format(i + 1, value))

open(path, "w", encoding="utf-8").write("\n".join(out))
print("changelog entries: {}".format(seen))
PYEOF

# Every note must now be a single line. A multi-line one means the rewrite
# missed a form chglog emitted, and the package would ship the pull request
# body again.
if grep -nE "^      note: [|>]" changelog.yml; then
	echo "block-scalar notes survived the rewrite" >&2
	exit 1
fi
if grep -nE '^      note: ".*\\n' changelog.yml; then
	echo "multi-line notes survived the rewrite" >&2
	exit 1
fi

test -s changelog.yml
