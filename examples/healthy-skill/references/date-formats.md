# Date formats the cleaner understands

## Recognised inputs

- `2026-10-25` (ISO, already clean)
- `25/10/2026` and `25.10.2026` (day first)
- `10/25/2026` (month first, only when the day is greater than 12)
- `Oct 25, 2026` and `25 Oct 2026`

## Ambiguous dates

A value such as `03/04/2026` can be 3 April or 4 March. The script leaves the column unchanged and lists it in the summary. Ask the user which order the file uses, then rerun with `--day-first` or `--month-first`.
