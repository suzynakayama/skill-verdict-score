# Changelog

## 1.3.0

**Renamed from Skill Doctor to Skill Verdict Score.** The tool itself is unchanged: same rules, same score, same messages and caveats. What changed is the name.

- The command is `skill_verdict_score.py` (was `skill_doctor.py`), the skill folder and plugin are `skill-verdict-score`, and the JSON report says `"tool": "skill-verdict-score"`.
- The scorecard and the plugin card now read SKILL VERDICT SCORE.
- If you used the old name in CI or in scripts, replace `skill_doctor.py` with `skill_verdict_score.py` and `skills/skill-doctor` with `skills/skill-verdict-score`.
- The README and the skill now say plainly that a verdict is a reading of the files, not a guarantee.

## 1.2.0

A much deeper security pass. Tested against about 1,080 public skills (anthropics/skills, obra/superpowers, wshobson/agents, the ComposioHQ list): no skill was wrongly marked dangerous. Tested against a corpus of planted attacks: every one is caught.

**New threats caught (rules S022 to S029)**

- **S022 Exfiltration.** A secret (an SSH key, a credential file, the whole environment) that reaches a network call is followed through variables, not just matched on one line. Reaching the network with a secret is critical; so is a line or an instruction that sends `.env`, keys or the environment out.
- **S023 Reverse shell.** A shell wired to a network socket: `/dev/tcp`, `nc -e`, `socat exec:`, a `socket`+`dup2`+`sh` chain in Python.
- **S024 Remote instructions.** Text that tells the agent to fetch a URL at run time and follow what it says. The reviewed skill is not the one that runs, so this is flagged (error when the source is a raw Gist or changes every run).
- **S025 Chat-data image URLs.** An image whose URL is filled in from the conversation leaks that conversation the moment it renders.
- **S026 Self-tampering.** Code or instructions that change the agent's own settings, memory (`CLAUDE.md`), skills or allowed tools, or grant `Bash(*)`.
- **S027 TLS off.** `verify=False`, `curl -k`, `NODE_TLS_REJECT_UNAUTHORIZED=0` and the like.
- **S028 Miners.** Mining tools and `stratum+tcp://` pools.
- **S029 Unsafe installs.** An extra or plain-HTTP package index, or `--trusted-host`, which can serve a look-alike package.

**Hidden payloads (S004) are decoded**

The tool now decodes base64, hex, `\xNN` escapes, `chr()`/`fromCharCode` lists, PowerShell `-EncodedCommand`, strings built with `+`, and commands assembled from shell variables, then checks what they decode to. An encoded reverse shell or `curl | sh` is caught.

**Severity reflects reach**

- Instruction-override, impersonation and concealment text (S011) is an error, and critical when it sits in the `description`, which loads into every conversation before the skill is even chosen. Persistence (S017) is an error. Anything dangerous in the description is critical.
- A fake `<system>` or "message from Anthropic" tag is flagged (S011).
- The verdict says "Healthy, read the security notes" when a clean-scoring skill still has a security warning, so a note is never lost in an A grade.

**Fewer false alarms**

- A missing file in SKILL.md (V017) is now graded: an error when the skill clearly ships it, a warning for a bare path, and only a note when it reads as an example or a file the skill creates, or exists in a sibling skill.
- Unreferenced files (H005) understand imports, `require`, folders a script opens by name, and whole directories named in prose, and group a noisy folder into one line.
- Near-identical descriptions (T011) are grouped, so a large collection gives one finding, not thousands.
- A detection pattern, a help message, a blocklist, a comment or a `never ...` warning is read as what it is, not as a command. A command's severity now follows whether the surrounding sentence tells the agent to run it.
- Credential files a tool legitimately uses to log in (`.netrc`, `.pypirc`) are separated from private keys and secret stores.

**Faster**

Each file's syntax tree is parsed once. About 1,080 skills audit in well under a minute.

## 1.1.0

Fewer false alarms, and a plugin mode. With no new flag, a skill's score only changes through the first group below.

**Fewer false alarms**

- V017 no longer reports link placeholders (`url`, `path`, `<url>`, `{file}` ...) or links shown inside code.
- Identical findings are merged into one that shows how many times it occurred and the first five places (`count` and `locations` in JSON). Repeats add only a small, capped extra penalty.
- Text-based findings (S003, S005, S006, S010, S011, S012, S014, S017, S021) carry a context: executed, agent-instr, documented, hint, comment, defensive or fixture. The context sets the severity, so a command that runs outranks the same text in a help message, a comment or a blocklist. Shown in brackets in the report and as `context` in JSON.
- S015 decodes long encoded blobs: an embedded PNG, JPEG, GIF, WEBP or font in a `data:` URI is no longer flagged; text with execution patterns or an executable is flagged as an error.
- Override or hidden-instruction text (S011, S012) in a `references/` file keeps its severity, because the agent reads those files. A `command` or `args` value in hooks.json or .mcp.json counts as executed, so `curl | sh` in a hook is an error.
- S002 hidden characters inside `tests/`, `test/`, `fixtures/` or `__tests__/` drop to info.
- S014 also sees package installs written as argument lists, such as `[python, "-m", "pip", "install", ...]`.

**Plugin mode (`--plugin [ROOT]`)**

- Audits what a plugin would install: agents, hooks, scripts, installers, extensions, CI workflows, dependencies, lockfiles, manifests and the privacy notes. Read-only, offline, standard library only.
- New rules P001 to P012 (see rules.md), scored in a separate Plugin block with its own 0 to 100 score. The block lists strengths (pinned actions, threat model, code owners and more) and gives a bonus of up to 5 points that never cancels a critical finding.
- Findings carry `scope` (`skill` or `plugin`); scripts a skill calls are attributed to it in `used_by`. `--plugin-affects-skills` adds them to the skill's own score (off by default).
- Without `--plugin`, a detected plugin only adds one info line.
- `--only plugin`, `--explain P002` and `--list-rules` know the new rules. `--online` is reserved and does nothing yet.
- The scorecard image shows the plugin score in its footer, and `--svg` / `--badge` also write a plugin card and badge.

## 1.0.0

First release.

- 75 rules in five categories: validity, triggering, weight, security, hygiene, plus collection checks.
- Score from 0 to 100, letter grade, verdict, and score caps for serious security findings.
- Text, JSON and Markdown reports; SVG scorecard and README badge.
- `--fail-under` and `--fail-on` for CI, `--ignore`, `--only`, `--min-severity`, `--explain`, `--list-rules`.
- Read-only, standard library only, Python 3.8 or newer.
