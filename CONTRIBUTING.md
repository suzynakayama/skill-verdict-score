# Contributing

Thanks for helping. The short version:

1. Run the tests: `python3 -m unittest discover -s tests -v`
2. Run the tool on itself: `python3 skills/skill-verdict-score/scripts/skill_verdict_score.py skills/skill-verdict-score`. It must stay at 100.
3. Added or changed a rule? Regenerate the rules page:
   `python3 skills/skill-verdict-score/scripts/skill_verdict_score.py --list-rules --format markdown > skills/skill-verdict-score/references/rules.md`
   A test fails if the page is out of date.

## Rules for new checks

- Every rule needs a code, a severity, a one-line reason and a fix.
- Cite a source for any number taken from a specification. Mark your own thresholds as heuristics in `references/scoring.md`.
- Add a test with a case that fires and a case that must stay quiet.
- Do not commit anything shaped like a real secret or any hidden Unicode. Build such fixtures inside the test, at run time.
- Keep the tool read-only and standard-library only.
