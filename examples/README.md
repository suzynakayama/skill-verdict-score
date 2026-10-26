# Example skills

Three small skills used to demo and test Skill Verdict Score.

| Folder | What it shows | Expected result |
| --- | --- | --- |
| `healthy-skill` | A well-formed skill with a real script | 100, grade A |
| `sick-skill` | Broken frontmatter, vague trigger, missing files, weak script | low score, no critical issue |
| `suspicious-skill` | Patterns that look like a hostile skill | low score, security findings |

The last two are intentionally bad. They contain only inert text, point at hosts that cannot resolve, and are not meant to be installed or run. Do not copy them into a real skills folder.

Try it from the repository root:

```
python3 skills/skill-verdict-score/scripts/skill_verdict_score.py examples
```
