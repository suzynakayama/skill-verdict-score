# How scoring works

## Categories

| Category | Points | What it covers |
| --- | ---: | --- |
| Validity | 25 | Frontmatter, name and description limits, broken links, syntax of bundled scripts and JSON |
| Triggering | 25 | Whether the description tells the agent what the skill does and when to use it |
| Weight | 20 | Context cost: file length, token estimate, large files, inline code |
| Security | 20 | Secrets, hidden characters, remote or hidden code execution, credential access and exfiltration, reverse shells, persistence, self-tampering, injection and impersonation language |
| Hygiene | 10 | Stray files, placeholders, orphan files, license, examples |

## Penalties

Every category starts at its full points. Each finding removes points:

| Severity | Penalty | Meaning |
| --- | ---: | --- |
| critical | 20 | Leaked secret or hidden-text trick. Also caps the total at 49 (see Caps) |
| error | 8 | The skill is broken or clearly unsafe |
| warn | 3 | Worth fixing |
| info | 0 | Good to know, never changes the score |

Identical findings (same rule and same message) are merged into one finding that shows how many times it occurred and the first five places. A merged finding counts once, plus a small extra weight of 0.05 for each repeat, never more than half a finding in total. Different findings of the same rule and severity add half the base amount each, up to double the base amount, so one noisy rule cannot zero a category by itself. A category never drops below 0.

## Context

Text-based security findings (S003, S004, S005, S006, S007, S008, S009, S010, S011, S012, S014, S017, S021, S022 to S029) are classified by what the matched text is. The context changes the severity and is shown in brackets in the report and as `context` in JSON.

| Context | Meaning | Severity |
| --- | --- | --- |
| executed | code that runs | unchanged |
| agent-instr | an instruction the agent is told to follow, including override text (S011, S012) in references and a command in hooks.json or .mcp.json | unchanged |
| documented | documentation the agent only reads | one level lower |
| hint | a message or help text a script prints | one level lower |
| comment | a comment or docstring | info |
| defensive | a blocklist, deny rule or warning against it | info |
| fixture | under tests/, test/, fixtures/, __tests__/ | info |

Executed and agent-instr both keep the rule's severity, so the same command can score the same in a script and in an instruction, and lower in a hint or a comment. Secrets (S001) are never lowered. Hidden characters (S002) are lowered only inside a test folder.

Two things override the context. A detection pattern (a regex, a blocklist, a string that only describes a threat) in the tool-like code is read as data, not as a command. And anything dangerous inside the `description` is raised to critical, because the description is loaded into every conversation before the skill is even chosen. The wording rules (S011 override text, S021 "never ask", S022 and S024 to S026 instructions) count wherever the agent reads them, including a `references/` file.

## Caps

Some problems should never be hidden by good scores elsewhere, so the total is capped:

| Condition | Cap | Verdict |
| --- | ---: | --- |
| Any critical finding | 49 | Quarantine: review before installing |
| Any security finding of severity error (and no critical) | 64 | Security review needed |
| Security category below half of its points (and none of the above) | 74 | Security review needed |

A cap is shown in the report only when it actually lowered the score.

## Plugin score

`--plugin` adds a separate score from 0 to 100 for what the plugin installs besides its skills. It never changes a skill's score unless you add `--plugin-affects-skills`.

| Block | Points | Rules |
| --- | ---: | --- |
| Code security | 30 | S rules on scripts, installers, hooks and extension files, and P009 |
| Permissions and hooks | 25 | P002, P003 |
| Supply chain | 30 | P004, P005, P006, P007, P012 |
| Consistency and privacy | 15 | P001, P008, P010 |

Penalties use the same table and the same merging as skills. Strengths (P011) add one point each, up to 5, after the blocks are added. The caps apply after the bonus, so a bonus never lifts a plugin above the cap that a critical finding sets: critical caps at 49, a security error in plugin code caps at 64, and a Code security block under half caps at 74. P004 at error severity costs points but does not cap on its own.

The plugin checks read files only. They cannot see what happens at run time, so a clean plugin block is not a guarantee. Scripts inside skill folders are scored in each skill's own report, not in the plugin block.

## Grades

A from 90, B from 80, C from 70, D from 60, F below 60. Verdicts: "Picture of health" from 95, "Healthy, minor notes" from 85, "Needs a checkup" from 70, "Sick, treat soon" from 55, "Needs the ER" below that, and the two security verdicts from the Caps table, which replace the score-based verdict.

## Where the numbers come from

Verified in October 2026 against the sources below. Specification limits can change, so check the current documents before treating them as fixed.

| Limit | Value | Source |
| --- | --- | --- |
| name | 1 to 64 characters; lowercase letters, numbers, hyphens; no leading, trailing or doubled hyphen; must match the folder name | Agent Skills specification |
| description | 1 to 1024 characters | Agent Skills specification |
| compatibility | up to 500 characters | Agent Skills specification |
| Body size | under 500 lines and about 5000 tokens recommended | Agent Skills specification |
| Description voice | third person, say what and when | Anthropic skill authoring best practices |
| Reserved name prefixes | avoid anthropic- and claude- | Anthropic skill authoring best practices |
| Reference depth | keep references one level deep from SKILL.md | Anthropic skill authoring best practices |
| Forward slashes in paths | required for portability | Anthropic skill authoring best practices |
| Menu cut at 250 characters | some Claude Code versions (reported for 2.1.86; later versions raised the cap) | an unofficial write-up of the Claude Code listing budget, not Anthropic documentation |
| Listing budget about 1 percent of the context window | about 2000 tokens on a 200K window | the same unofficial write-up; treat as an estimate |

Everything else is a heuristic chosen by this tool: the 50-character minimum description, the 900-character "close to the limit" mark, the 1000-line and 12000-token error marks, the 1 MB and 10 MB file marks, the 0.45 description-overlap threshold and the 4-characters-per-token estimate.

## Limits of this tool

- It reads files. It does not run the skill, so it cannot tell whether a skill actually triggers or whether its instructions work. Treat the triggering score as a checklist of known causes, not a measurement.
- Security checks are pattern matching. They catch common, high-signal problems and they can raise false alarms, especially in skills that teach security. A clean result is not a guarantee of safety.
- When a line sits next to words like "never" or "avoid" in the same sentence, or under a heading such as "Red flags", most security findings are lowered because the text is likely a warning rather than an instruction. The check looks only at the words around the match, so a warning word elsewhere on the line cannot excuse a real command. The most dangerous findings in SKILL.md and agent files are lowered by one level, not all the way to a note. Secrets and hidden characters are never lowered.
- Use `--ignore CODE` for a rule that does not fit your skill, and say so in the review.
