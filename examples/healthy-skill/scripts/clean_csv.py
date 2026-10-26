#!/usr/bin/env python3
"""Clean a CSV or TSV file: tidy headers, trim spaces, drop duplicate rows, normalise dates."""
import argparse
import csv
import re
import sys
from datetime import datetime

DAY_FIRST = ["%d/%m/%Y", "%d.%m.%Y", "%d-%m-%Y"]
MONTH_FIRST = ["%m/%d/%Y", "%m-%d-%Y"]
UNAMBIGUOUS = ["%Y-%m-%d", "%b %d, %Y", "%d %b %Y", "%B %d, %Y", "%d %B %Y"]


def snake(name):
    name = re.sub(r"[^0-9A-Za-z]+", "_", name.strip()).strip("_").lower()
    return name or "column"


def parse_date(value, order):
    for fmt in UNAMBIGUOUS + (DAY_FIRST if order == "day" else MONTH_FIRST if order == "month" else []):
        try:
            return datetime.strptime(value, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("input")
    ap.add_argument("--out", required=True)
    ap.add_argument("--day-first", action="store_true")
    ap.add_argument("--month-first", action="store_true")
    args = ap.parse_args()
    order = "day" if args.day_first else "month" if args.month_first else None
    delim = "\t" if args.input.lower().endswith(".tsv") else ","
    with open(args.input, newline="", encoding="utf-8-sig") as fh:
        rows = list(csv.reader(fh, delimiter=delim))
    if not rows:
        sys.exit("empty file")
    old_header = rows[0]
    header = [snake(h) for h in old_header]
    body = [[c.strip() for c in r] for r in rows[1:] if any(c.strip() for c in r)]
    seen, unique = set(), []
    for r in body:
        key = tuple(r)
        if key not in seen:
            seen.add(key)
            unique.append(r)
    skipped = []
    for i, h in enumerate(header):
        if "date" not in h:
            continue
        converted = [parse_date(r[i], order) if i < len(r) and r[i] else "" for r in unique]
        if all(c is not None for c in converted):
            for r, c in zip(unique, converted):
                if i < len(r):
                    r[i] = c
        else:
            skipped.append(h)
    with open(args.out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh, delimiter=delim)
        w.writerow(header)
        w.writerows(unique)
    renamed = sum(1 for a, b in zip(old_header, header) if a != b)
    print("rows in: %d, rows out: %d, duplicates removed: %d, headers renamed: %d"
          % (len(body), len(unique), len(body) - len(unique), renamed))
    if skipped:
        print("date columns left unchanged (ambiguous or unreadable): " + ", ".join(skipped))


if __name__ == "__main__":
    main()
