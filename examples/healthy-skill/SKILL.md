---
name: healthy-skill
description: "Cleans messy CSV and TSV files: fixes headers, trims spaces, removes duplicates, normalises dates. Use when the user shares a .csv or .tsv and asks to clean, dedupe or tidy it, or says an export looks broken."
license: MIT
---

# CSV cleaner

Cleans one CSV or TSV file and writes a new file next to it. The original is never changed.

## Steps

1. Confirm the input path with the user. If they pasted the data instead of attaching a file, save it to a file first.
2. Run the cleaner:

```
python3 scripts/clean_csv.py INPUT.csv --out cleaned.csv
```

3. Read the summary the script prints (rows in, rows out, duplicates removed, columns renamed) and repeat it to the user in one or two sentences.
4. If a date column was left untouched, check [date formats](references/date-formats.md) and ask the user which format the column uses.

## Rules

- Never overwrite the input file.
- Do not guess a date format when the day and month are ambiguous; ask.
- Keep the original column order.

## Example

User: "This export from our shop is a mess, can you tidy it?"

Reply after running the script: "Cleaned 1,204 rows down to 1,187. I removed 17 exact duplicates, renamed 6 headers to snake_case and standardised the `order_date` column to YYYY-MM-DD. The result is in cleaned.csv."
