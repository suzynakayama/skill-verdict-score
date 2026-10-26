#!/usr/bin/env python3
"""Skill Verdict Score: audit Agent Skills (folders with a SKILL.md) and score them 0-100.

Zero dependencies, Python 3.8+. Reads files only; it never runs the code it audits.

    python3 skill_verdict_score.py PATH [PATH ...]

PATH can be one skill folder, a folder that holds many skills, or a SKILL.md file.
Run with --help for all options, --list-rules for every check.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import dataclasses
import html
import json
import math
import io
import os
import re
import sys
import textwrap
import tokenize
from pathlib import Path

__version__ = "1.3.0"

# --------------------------------------------------------------------------
# Scoring model
# --------------------------------------------------------------------------

CATEGORIES = {
    "validity": ("Validity", 25),
    "trigger": ("Triggering", 25),
    "weight": ("Weight", 20),
    "security": ("Security", 20),
    "hygiene": ("Hygiene", 10),
}
SEVERITY_ORDER = {"info": 0, "warn": 1, "error": 2, "critical": 3}
SEVERITY_PENALTY = {"critical": 20, "error": 8, "warn": 3, "info": 0}
CRITICAL_CAP = 49        # any critical finding caps the total at this score
SECURITY_ERROR_CAP = 64  # any security error caps the total (grade D at best)
SECURITY_LOW_CAP = 74    # a security category under half of its points caps the total (grade C at best)

# Thresholds. The spec values are verified against the Agent Skills specification and
# Anthropic's authoring guidance; the rest are heuristics and are labelled as such.
NAME_MAX = 64            # spec
DESC_MAX = 1024          # spec
COMPAT_MAX = 500         # spec
BODY_LINES_RECOMMENDED = 500    # spec recommendation
BODY_TOKENS_RECOMMENDED = 5000  # spec recommendation
BODY_LINES_HARD = 1000          # heuristic
BODY_TOKENS_HARD = 12000        # heuristic
DESC_MIN = 50                   # heuristic
DESC_FRONT_LOAD = 250           # some Claude Code versions cut the menu text here
DESC_LONG = 900                 # heuristic
BIG_FILE_BYTES = 1_000_000      # heuristic
HUGE_FILE_BYTES = 10_000_000    # heuristic
MAX_SCAN_BYTES = 2_000_000
MAX_FILES = 3000
LISTING_BUDGET_TOKENS = 2000    # ~1% of a 200K window; unofficial estimate
OVERLAP_THRESHOLD = 0.45        # heuristic
MAX_LOCATIONS = 5               # places listed for a deduplicated finding
DUP_STEP = 0.05                 # extra weight for each repeat of an identical finding ...
DUP_CAP = 0.5                   # ... never more than half a finding in total


@dataclasses.dataclass(frozen=True)
class Rule:
    code: str
    category: str
    severity: str
    title: str
    why: str
    fix: str


RULES: dict = {}


def _r(code, category, severity, title, why, fix):
    RULES[code] = Rule(code, category, severity, title, why, fix)


# ---- Validity ----
_r("V001", "validity", "error", "File is not named SKILL.md exactly",
   "Agents look for the exact file name SKILL.md. A different case is skipped on case-sensitive systems.",
   "Rename the file to SKILL.md.")
_r("V002", "validity", "error", "Frontmatter is missing or never closed",
   "Every skill starts with a YAML block between two lines of three dashes. Without it the skill cannot load.",
   "Add the block at the very top of the file and close it with a second line of three dashes.")
_r("V003", "validity", "error", "The name field is missing",
   "The name identifies the skill and is required by the spec.",
   "Add name: with a lowercase, hyphenated identifier.")
_r("V004", "validity", "error", "The description field is missing or empty",
   "The description is the only text the agent sees before deciding to use the skill.",
   "Add description: saying what the skill does and when to use it.")
_r("V005", "validity", "error", "Name uses characters the spec does not allow",
   "The spec allows lowercase letters, numbers and hyphens, with no leading, trailing or doubled hyphens.",
   "Rename to something like pdf-form-filler.")
_r("V006", "validity", "error", "Name is longer than 64 characters",
   "The spec caps the name at 64 characters.", "Shorten the name.")
_r("V007", "validity", "warn", "Name does not match the folder name",
   "The spec says the name must match the parent directory name. Mismatches break some installers.",
   "Rename the folder or the name field so both are identical.")
_r("V008", "validity", "error", "Description is longer than 1024 characters",
   "The spec caps the description at 1024 characters; uploads and validators reject longer ones.",
   "Cut it down and move detail into the body of SKILL.md.")
_r("V009", "validity", "warn", "Name starts with a reserved prefix",
   "Anthropic's authoring guidance says to avoid names that start with claude- or anthropic-.",
   "Pick a name that does not start with those prefixes.")
_r("V010", "validity", "error", "Frontmatter is not valid YAML",
   "An unquoted colon followed by a space, an unterminated quote or a line that is not key: value breaks strict YAML parsers.",
   "Wrap the value in double quotes, or use a block scalar with a greater-than sign.")
_r("V011", "validity", "warn", "A hash sign silently cuts the value short",
   "In an unquoted YAML value, a space followed by a hash sign starts a comment, so the rest is dropped.",
   "Wrap the value in double quotes.")
_r("V012", "validity", "warn", "Value starts with a character YAML treats as syntax",
   "A leading bracket, brace, asterisk, ampersand, exclamation mark, percent sign, at sign or backtick changes how YAML reads the value.",
   "Wrap the value in double quotes.")
_r("V013", "validity", "info", "Frontmatter key is not part of the open spec",
   "Keys outside name, description, license, compatibility, metadata and allowed-tools are ignored by strict validators.",
   "Keep it only if your agent supports it; otherwise move it under metadata.")
_r("V014", "validity", "error", "Compatibility is longer than 500 characters",
   "The spec caps compatibility at 500 characters.", "Shorten it to the real requirements.")
_r("V015", "validity", "error", "Frontmatter is indented with tabs",
   "YAML forbids tabs for indentation.", "Use spaces.")
_r("V016", "validity", "error", "The body is empty",
   "A skill with frontmatter but no instructions gives the agent nothing to follow.",
   "Write the instructions below the frontmatter.")
_r("V017", "validity", "error", "SKILL.md points to a file that does not exist",
   "The agent will try to open it and fail, or invent its contents.",
   "Create the file or fix the path.")
_r("V018", "validity", "warn", "Windows-style backslash path",
   "Backslash paths break on macOS and Linux. Anthropic's guidance says to use forward slashes.",
   "Use forward slashes in every path.")
_r("V019", "validity", "warn", "Reference files link to other reference files",
   "Anthropic's guidance warns that agents may read only part of a file that is reached through another reference.",
   "Link every reference directly from SKILL.md, one level deep.")
_r("V020", "validity", "error", "SKILL.md is not valid UTF-8",
   "Agents expect UTF-8 text; other encodings produce garbled instructions.", "Re-save the file as UTF-8.")
_r("V021", "validity", "error", "A Python script has a syntax error",
   "The script will crash the first time the agent runs it.", "Fix the syntax error.")
_r("V022", "validity", "error", "A JSON file is not valid JSON",
   "Tools that read the file will fail.", "Fix the JSON syntax.")
_r("V023", "validity", "error", "The description is not a plain string",
   "A list or mapping where a text description belongs is read as a different type by agents.",
   "Write the description as a single text value.")

# ---- Triggering ----
_r("T001", "trigger", "warn", "Description is too short to trigger reliably",
   "With a handful of words the agent has little to match against a request.",
   "Say what the skill does, then add a Use when clause with real trigger phrases.")
_r("T002", "trigger", "warn", "Description never says when to use the skill",
   "Anthropic's guidance asks for both what the skill does and when to use it. The when part drives triggering.",
   "Add a clause that starts with Use when, followed by the situations and phrases that should activate it.")
_r("T003", "trigger", "info", "The when-to-use cue appears late in the description",
   "Some Claude Code versions cut the menu text at 250 characters, so a cue placed after that can be lost.",
   "Put the trigger clause in the first 250 characters.")
_r("T004", "trigger", "warn", "Description is written in first or second person",
   "Anthropic's guidance says to write descriptions in third person because they are injected into the system prompt.",
   "Rewrite as Processes X. Use when the user asks for Y.")
_r("T005", "trigger", "warn", "Description is vague",
   "Phrases like helps with or a tool for match everything and nothing, so the skill fires wrongly or never.",
   "Name the concrete task, file types or outputs.")
_r("T006", "trigger", "warn", "Name is generic",
   "Names like helper, utils or documents say nothing about the skill and collide with other skills.",
   "Use a specific name such as pdf-form-filler.")
_r("T007", "trigger", "info", "Description is longer than 250 characters",
   "Some Claude Code versions truncate the menu text at 250 characters. Longer text still works but its tail may not be seen.",
   "Front-load the most important triggers or shorten.")
_r("T008", "trigger", "warn", "Description is almost the same as the name",
   "A description that only repeats the name adds no matching signal.", "Describe the task and the trigger situations.")
_r("T009", "trigger", "info", "No literal trigger phrases, quotes or file types in the description",
   "Concrete phrases the user might actually type make activation more reliable.",
   "Add a few quoted phrases, file extensions or slash commands.")
_r("T010", "trigger", "warn", "Description is close to the 1024 character limit",
   "Long descriptions eat the shared listing budget that all skills draw from.", "Trim it to the essentials.")
_r("T012", "trigger", "warn", "Description contains XML or HTML tags",
   "Tags inside the description can be misread as structure by the agent or rejected by validators.",
   "Remove the tags and describe in plain sentences.")
_r("T014", "trigger", "info", "Description contains headings or bullet lists",
   "Descriptions work best as one short paragraph.", "Rewrite as one paragraph.")

# ---- Weight ----
_r("W001", "weight", "warn", "SKILL.md is longer than 500 lines",
   "The spec recommends keeping the main file under 500 lines and moving detail to reference files.",
   "Move detail into references/ and link to it from SKILL.md.")
_r("W002", "weight", "warn", "SKILL.md body is heavy in tokens",
   "The spec recommends under 5000 tokens. The whole body loads into context each time the skill triggers.",
   "Split rarely needed material into reference files that load on demand.")
_r("W004", "weight", "warn", "Long reference file has no headings",
   "Without headings an agent cannot jump to the right section, so it reads or skims the whole file.",
   "Add headings, and a contents list for very long files.")
_r("W005", "weight", "warn", "Large file in the skill folder",
   "Big files slow installs and can flood the context if the agent reads them.",
   "Remove it, shrink it, or fetch it at run time.")
_r("W006", "weight", "info", "The skill folder holds a very large number of files",
   "Hundreds of files make a skill hard to review and slow to install.", "Trim the folder.")
_r("W007", "weight", "warn", "SKILL.md contains a very large amount of inline code",
   "Long code blocks in the body cost tokens every time the skill triggers.",
   "Move the code to scripts/ so the agent can run it without reading it.")
_r("W008", "weight", "warn", "SKILL.md contains an extremely long line",
   "Very long lines are usually pasted data or minified content that waste context.", "Move the data to a file.")
_r("W009", "weight", "info", "Repeated lines in SKILL.md",
   "Repetition costs tokens and can dilute emphasis.", "State each instruction once.")

# ---- Security ----
_r("S001", "security", "critical", "Hardcoded secret or private key",
   "A key committed in a skill is leaked to everyone who installs it.",
   "Remove it, rotate the credential, and read secrets from the environment.")
_r("S002", "security", "critical", "Hidden Unicode control characters",
   "Invisible tag or bidirectional characters can smuggle instructions the human reviewer cannot see.",
   "Delete the characters and retype the text.")
_r("S003", "security", "error", "Downloads remote code and runs it",
   "Running whatever a URL serves hands control to that server, and it can change after you review it.",
   "Download to a file, check a pinned checksum, then run it.")
_r("S004", "security", "error", "Hidden or encoded payload",
   "Decoding data and running it, or hiding a command behind escapes and character codes, is the standard way to hide what a script really does.",
   "Ship the plain script instead.")
_r("S005", "security", "warn", "Dynamic code execution or shell invocation",
   "Evaluating strings as code or going through a shell opens the door to injection.",
   "Call the function or program directly with an argument list.")
_r("S006", "security", "warn", "Touches credential or sensitive paths",
   "SSH keys, cloud credentials, browser stores and password files are what a malicious skill goes after.",
   "A skill almost never needs these; remove the access or justify it clearly in SKILL.md.")
_r("S007", "security", "warn", "Contacts a paste, tunnel, webhook or raw-IP endpoint",
   "These hosts are common drop points for exfiltrated data and for staged payloads.",
   "Use a named, documented API host, or remove the call.")
_r("S008", "security", "warn", "Reads or dumps the whole environment",
   "Environment variables often hold tokens. Dumping them all is a classic way to steal secrets.",
   "Read only the specific variable you need.")
_r("S009", "security", "warn", "Destructive command",
   "Commands that wipe a home folder, a disk or permissions can destroy data if the agent runs them.",
   "Delete only a specific, validated path, and ask for confirmation first.")
_r("S010", "security", "warn", "Privilege escalation",
   "Skills should not need administrator rights.", "Remove it, or explain why it is needed.")
_r("S011", "security", "error", "Instruction-override, impersonation or concealment language",
   "Text that tells the agent to drop its rules, pretends to come from the system or from Anthropic, or hides actions from the user is a prompt-injection signature. In the description it reaches every conversation, so it is critical there.",
   "Remove it. A skill should add guidance, never remove safeguards.")
_r("S012", "security", "warn", "HTML comment that hides instructions",
   "Comments are invisible when the file is rendered but still read by the model.",
   "Delete the comment or move it into visible text.")
_r("S013", "security", "warn", "allowed-tools grants unrestricted shell access",
   "A bare shell permission lets the skill run any command without asking.",
   "Restrict it to the specific commands the skill needs.")
_r("S014", "security", "info", "Installs packages or downloads and runs files at run time",
   "Runtime installs pull unreviewed code into the environment.", "Pin versions and document what is installed.")
_r("S015", "security", "warn", "Obfuscated or encoded blob",
   "Long encoded strings and escape chains hide what the file really contains.",
   "Replace with readable source or a plain data file.")
_r("S017", "security", "error", "Modifies startup files, scheduled jobs, git hooks or authorised keys",
   "Persistence mechanisms keep running after the skill is gone.", "Remove it, or make it explicit and opt-in.")
_r("S018", "security", "warn", "Symlink points outside the skill folder",
   "A link can expose any file on the machine through the skill.", "Replace it with a real file.")
_r("S019", "security", "info", "Script capability",
   "Shows what a script can do (network, subprocess, delete) so a reviewer knows where to look.",
   "Informational: review the script for these actions.")
_r("S021", "security", "warn", "Asks to bypass permission or sandbox safeguards",
   "Skills that tell the agent to skip approvals or leave the sandbox remove the user's last line of defence.",
   "Remove the instruction.")
_r("S022", "security", "critical", "Sends secrets or private data out",
   "Reading keys, tokens or the whole environment and sending them over the network (or telling the agent to share them) is data theft.",
   "Remove it. A skill must never move credentials or private files anywhere.")
_r("S023", "security", "critical", "Reverse shell or remote control",
   "Wiring a shell to a network socket gives a stranger control of the machine.",
   "Remove it. No skill needs a reverse shell.")
_r("S024", "security", "warn", "Loads instructions from the internet at run time",
   "Instructions fetched when the skill runs can change after you review it, so the reviewed skill is not the one that runs.",
   "Ship the instructions inside the skill, or pin the exact content with a checksum.")
_r("S025", "security", "error", "Leaks chat data through an image or link URL",
   "An image whose URL carries conversation data sends that data to the host the moment it is rendered.",
   "Remove the template from the URL. Never build image URLs from chat content.")
_r("S026", "security", "warn", "Changes the agent's own settings, memory, skills or permissions",
   "A skill that edits the agent's settings, CLAUDE.md, skills or allowed tools can quietly grant itself more power or plant instructions for later sessions.",
   "Remove it, or ask the user to make the change themselves and show the exact edit.")
_r("S027", "security", "warn", "Turns off TLS certificate checks",
   "Without certificate checks anyone on the network can read or change the traffic.",
   "Remove the flag and fix the certificate setup instead.")
_r("S028", "security", "critical", "Crypto-mining tool or mining pool",
   "Mining software uses the user's machine for someone else's profit.",
   "Remove it.")
_r("S029", "security", "warn", "Installs packages from an unusual or unsafe source",
   "An extra package index, a plain-HTTP registry or a trusted-host override can serve a look-alike package instead of the real one.",
   "Install from the official registry over HTTPS with pinned versions and hashes.")

# ---- Hygiene ----
_r("H001", "hygiene", "warn", "Stray or generated files shipped in the skill",
   "Caches, OS files and dependency folders bloat the skill and can leak local details.",
   "Delete them and add them to .gitignore.")
_r("H002", "hygiene", "error", "Environment file or key file shipped in the skill",
   "These files usually contain secrets.", "Remove it and rotate any credential it held.")
_r("H003", "hygiene", "warn", "Placeholder text left in SKILL.md",
   "Template markers show the skill was never finished.", "Fill them in or delete them.")
_r("H004", "hygiene", "info", "No license found",
   "Without a license nobody knows if they may use or share the skill.",
   "Add a LICENSE file or a license field.")
_r("H005", "hygiene", "warn", "File in the skill folder is never mentioned in SKILL.md",
   "The agent only learns about bundled files from SKILL.md, so unreferenced files are dead weight.",
   "Reference the file where it is needed, or delete it.")
_r("H006", "hygiene", "info", "No examples in the body",
   "Examples make agent behaviour far more consistent.", "Add one or two short examples.")
_r("H007", "hygiene", "info", "No headings in the body",
   "Headings help both humans and agents navigate.", "Structure the body with a few headings.")
_r("H008", "hygiene", "info", "Windows line endings",
   "CRLF can trip up simple frontmatter parsers.", "Convert to LF.")
_r("H009", "hygiene", "info", "File starts with a byte order mark",
   "The mark sits before the first line of three dashes, which some parsers do not expect.", "Save as UTF-8 without BOM.")
_r("H010", "hygiene", "warn", "Two skills share the same name",
   "Installing both makes one shadow the other.", "Give each skill a unique name.")
_r("H012", "hygiene", "info", "Hardcoded home-directory path",
   "A path with a specific user name only works on one machine.", "Use a relative path or an environment variable.")
_r("C001", "hygiene", "warn", "Combined skill descriptions are large for the listing budget",
   "Claude Code lists every skill description in a shared budget (about 1 percent of the context window, an unofficial estimate). Overflow can drop descriptions.",
   "Shorten descriptions or install fewer skills at once.")
_r("T011", "trigger", "warn", "Two skills have very similar descriptions",
   "When descriptions overlap the agent cannot tell which skill to use, so either may fire or neither.",
   "Make each description name a different task, and add a Do not use for clause.")


# ---- Plugin (only with --plugin; scored in a separate block) ----
_r("P001", "plugin", "warn", "Plugin manifest is broken or points to files that are missing",
   "Claude Code reads .claude-plugin/plugin.json to load the plugin. Invalid JSON, a missing name or a path to a file that is not there stops parts of it from loading.",
   "Fix the JSON, add the name, and make every path in the manifest point to a real file.")
_r("P002", "plugin", "warn", "Agent can fetch from the web, run Bash and write files",
   "Web pages can carry hidden instructions. An agent that reads them and can also run commands and write files can be steered into acting on them.",
   "Drop one of the three tools, or narrow what the agent may run, and tell it to treat fetched content as data and never as instructions.")
_r("P003", "plugin", "info", "Hook runs a command on tool events",
   "A hook runs on your machine every time its event fires, without asking. Broad matchers, values taken from the tool call and interpreters chosen by an environment variable widen what it can do.",
   "Use the narrowest matcher, treat every value from the tool call as data, and call a fixed interpreter.")
_r("P004", "plugin", "warn", "Script writes downloaded content into the skill folders",
   "Text fetched from the network and saved inside a skill becomes instructions the agent follows. If the source can change (a branch, HEAD) and nothing checks a hash, the skill can change under you.",
   "Pin the download to a commit or tag by default, restrict the host, and compare a known SHA-256 before writing anything.")
_r("P005", "plugin", "info", "Dependencies are not pinned exactly",
   "A range or a missing lock lets a different version install tomorrow than the one that was reviewed today.",
   "Pin exact versions, keep a lockfile that lists the real packages, and install with hashes where you can.")
_r("P006", "plugin", "info", "Installer downloads, runs or changes things on the machine",
   "Installers run with your permissions. What they download, whether the source can move, and which config files they edit decide how far you must trust them.",
   "Pin the source to a tag or commit, verify a checksum or signature, and keep edits to your Claude config explicit and reversible.")
_r("P007", "plugin", "warn", "CI workflow is easy to hijack",
   "Actions that are not pinned to a commit, a wide token, pull_request_target and untrusted text pasted into a run step are the usual ways a workflow is turned against its own repository.",
   "Pin actions to a 40-character commit, declare minimal permissions, and pass untrusted text through env variables.")
_r("P008", "plugin", "warn", "Versions or counts disagree across the plugin",
   "When the manifest, the packaging files and the installer name different versions or different numbers of skills or agents, users cannot tell what they are installing.",
   "Make every file state the same version and counts, and add a test that keeps them in step.")
_r("P009", "plugin", "warn", "Code handles credential files without clear care",
   "Credential files should be written readable by the owner only, and reading another tool's sign-in files should be documented.",
   "Create credential files with mode 0o600, and say in the README or PRIVACY file when you read another tool's sign-in.")
_r("P010", "plugin", "warn", "Code contacts a host the privacy notes never mention",
   "Users read PRIVACY.md and the README to learn who receives their data. A host that appears only in code is a surprise.",
   "List every host the plugin contacts, and why, in PRIVACY.md.")
_r("P011", "plugin", "info", "Strength: a safeguard the plugin already has",
   "Pinned actions, a threat model, code owners and tests with hostile input make a plugin easier to trust. They add a small bonus to the plugin score and never cancel a critical finding.",
   "Keep them.")
_r("P012", "plugin", "info", "Unquoted placeholder in a shell command",
   "In a shell, a less-than sign starts a redirect, so a bare placeholder such as <url> breaks the command when someone pastes it as written.",
   "Write the placeholder inside quotes, for example \"<url>\".")


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------

@dataclasses.dataclass
class Finding:
    code: str
    category: str
    severity: str
    message: str
    hint: str
    file: str = None
    line: int = None
    context: str = None      # executed, agent-instr, documented, hint, comment, defensive, fixture
    count: int = 1           # how many identical occurrences this finding stands for
    locations: list = None   # first few "file:line" places (see MAX_LOCATIONS)
    scope: str = "skill"     # skill or plugin
    used_by: list = None     # plugin mode: skills that call the script this finding sits in

    def where(self):
        if not self.file:
            return ""
        return self.file + (":" + str(self.line) if self.line else "")

    def to_dict(self):
        d = dataclasses.asdict(self)
        if d["locations"] is None:
            d["locations"] = [self.where()] if self.file else []
        if d["used_by"] is None:
            d["used_by"] = []
        return d


@dataclasses.dataclass
class SkillReport:
    name: str
    path: str
    findings: list
    stats: dict
    categories: dict
    score: int
    grade: str
    verdict: str
    cap_value: int = None
    cap_reason: str = None
    description: str = ""

    @property
    def capped(self):
        return self.cap_reason is not None

    def to_dict(self):
        return {
            "name": self.name,
            "path": self.path,
            "score": self.score,
            "grade": self.grade,
            "verdict": self.verdict,
            "cap": ({"value": self.cap_value, "reason": self.cap_reason} if self.capped else None),
            "categories": self.categories,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
        }


def est_tokens(text: str) -> int:
    """Rough token estimate (4 characters per token). A heuristic, not a tokenizer."""
    return int(math.ceil(len(text) / 4.0)) if text else 0


# --------------------------------------------------------------------------
# Frontmatter parsing (small YAML subset, enough to judge skills)
# --------------------------------------------------------------------------

KEY_RE = re.compile(r"^([A-Za-z_][\w.-]*)[ ]*:(?:[ ]+(.*))?$")
SPEC_KEYS = {"name", "description", "license", "compatibility", "metadata", "allowed-tools"}
EXTENSION_KEYS = {"model", "disable-model-invocation", "argument-hint", "user-invocable",
                  "version", "context", "agent", "hooks", "when_to_use"}
YAML_LEADING_SYNTAX = "[{*&!%@`"


@dataclasses.dataclass
class FMField:
    key: str
    value: str
    line: int
    style: str
    children: dict = None
    items: list = None


def _find_close(s: str, quote: str):
    i = 1
    while i < len(s):
        ch = s[i]
        if quote == '"':
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                return i
        else:
            if ch == "'":
                if i + 1 < len(s) and s[i + 1] == "'":
                    i += 2
                    continue
                return i
        i += 1
    return None


def _unescape(inner: str, quote: str) -> str:
    if quote == "'":
        return inner.replace("''", "'")
    out = inner
    for src, dst in (('\\"', '"'), ("\\\\", "\\"), ("\\n", "\n"), ("\\t", "\t")):
        out = out.replace(src, dst)
    return out


def parse_frontmatter(fm_lines):
    fields = {}
    issues = []  # (code, message, line)
    n = len(fm_lines)
    i = 0
    for k, raw0 in enumerate(fm_lines):
        if re.match(r"^\s*\t", raw0):
            issues.append(("V015", "tab character used for indentation", k + 2))
            break
    while i < n:
        raw = fm_lines[i]
        lineno = i + 2
        if not raw.strip() or raw.lstrip().startswith("#"):
            i += 1
            continue
        if raw[0] in " \t":
            issues.append(("V010", "unexpected indented line: " + raw.strip()[:50], lineno))
            i += 1
            continue
        m = KEY_RE.match(raw)
        if not m:
            issues.append(("V010", "line is not 'key: value': " + raw.strip()[:50], lineno))
            i += 1
            continue
        key = m.group(1)
        rest = (m.group(2) or "").strip()
        j = i + 1
        cont = []
        while j < n and (fm_lines[j][:1] in (" ", "\t") or
                         (fm_lines[j].strip() == "" and j + 1 < n and fm_lines[j + 1][:1] in (" ", "\t"))):
            cont.append(fm_lines[j])
            j += 1
        field = FMField(key=key, value="", line=lineno, style="plain")
        if rest == "" or rest.startswith("#"):
            stripped = [c.strip() for c in cont if c.strip()]
            if not stripped:
                field.style = "null"
            elif all(s.startswith("- ") or s == "-" for s in stripped):
                field.style = "list"
                field.items = [s[2:].strip() for s in stripped]
                field.value = " ".join(field.items)
            elif all(KEY_RE.match(s) for s in stripped):
                field.style = "map"
                field.children = {}
                for s in stripped:
                    mm = KEY_RE.match(s)
                    field.children[mm.group(1)] = (mm.group(2) or "").strip().strip("\"'")
                field.value = ""
            else:
                field.value = " ".join(stripped)
        elif rest[0] in "|>":
            field.style = "block"
            body = [c for c in cont]
            indents = [len(c) - len(c.lstrip(" ")) for c in body if c.strip()]
            cut = min(indents) if indents else 0
            body = [c[cut:] if c.strip() else "" for c in body]
            if rest[0] == "|":
                field.value = "\n".join(body).strip("\n")
            else:
                paras, cur = [], []
                for c in body:
                    if c.strip() == "":
                        if cur:
                            paras.append(" ".join(cur))
                            cur = []
                    else:
                        cur.append(c.strip())
                if cur:
                    paras.append(" ".join(cur))
                field.value = "\n".join(paras)
        elif rest[0] in "\"'":
            field.style = "quoted"
            quote = rest[0]
            s = rest
            close = _find_close(s, quote)
            if close is None and cont:
                s = rest + " " + " ".join(c.strip() for c in cont)
                close = _find_close(s, quote)
            if close is None:
                issues.append(("V010", "unterminated quoted string for " + key, lineno))
                field.value = s[1:]
            else:
                tail = s[close + 1:].strip()
                if tail and not tail.startswith("#"):
                    issues.append(("V010", "text after the closing quote for " + key, lineno))
                field.value = _unescape(s[1:close], quote)
        else:
            parts = [rest] + [c.strip() for c in cont if c.strip()]
            cleaned = []
            for idx, part in enumerate(parts):
                pl = lineno + idx
                if ": " in part or part.endswith(":"):
                    issues.append(("V010", "unquoted ': ' in the value of " + key + " (YAML parse error)", pl))
                if " #" in part:
                    issues.append(("V011", "' #' in the value of " + key + " starts a YAML comment, the rest is dropped", pl))
                    part = part.split(" #", 1)[0].rstrip()
                cleaned.append(part)
            if rest and rest[0] in YAML_LEADING_SYNTAX:
                issues.append(("V012", "value of " + key + " starts with '" + rest[0] + "'", lineno))
            field.value = " ".join(p for p in cleaned if p)
        fields[key] = field
        i = j
    return fields, issues


def split_frontmatter(text: str):
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return None, None, None
    for idx in range(1, len(lines)):
        if lines[idx].strip() == "---":
            return lines[1:idx], lines[idx + 1:], idx + 2  # body starts at 1-based line idx+2
    return "unterminated", None, None


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

TEXT_EXT = {".md", ".markdown", ".mdx", ".txt", ".rst", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg",
            ".csv", ".tsv", ".xml", ".html", ".htm", ".css", ".sql", ".env", ".conf", ".lock"}
CODE_EXT = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".fish", ".ps1",
            ".bat", ".cmd", ".rb", ".pl", ".php", ".go", ".rs", ".java", ".kt", ".swift", ".lua", ".r"}
MD_EXT = {".md", ".markdown", ".mdx", ".txt", ".rst"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache",
             ".idea", ".vscode", ".ruff_cache", ".tox"}
JUNK_DIRS = {"node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox"}
JUNK_FILES = {".ds_store", "thumbs.db", "desktop.ini"}
JUNK_SUFFIX = (".pyc", ".pyo", ".swp", ".swo", ".bak", ".orig", ".rej", "~")
SECRET_FILE_RE = re.compile(r"^(?:\.env(?:\..+)?|id_(?:rsa|dsa|ecdsa|ed25519)|.*\.(?:pem|p12|pfx|key|keystore|jks))$", re.I)

NEGATION_RE = re.compile(r"\b(never|do not|don't|dont|must not|avoid|should not|shouldn't|not allowed|forbidden|"
                         r"warning|dangerous|unsafe|instead of|rather than|nunca|evite|jamais|ne pas)\b", re.I)

# (code, regex, label, scope, flags). scope: any | code | nonpy | md
SEC_PATTERNS_RAW = [
    ("S001", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key id", "any", 0),
    ("S001", r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "GitHub token", "any", 0),
    ("S001", r"\bgithub_pat_[A-Za-z0-9_]{22,}", "GitHub fine-grained token", "any", 0),
    ("S001", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "Slack token", "any", 0),
    ("S001", r"\bsk_live_[0-9A-Za-z]{16,}", "Stripe live key", "any", 0),
    ("S001", r"\bsk-ant-[A-Za-z0-9_-]{20,}", "Anthropic API key", "any", 0),
    ("S001", r"\bsk-[A-Za-z0-9]{32,}\b", "API key in sk- format", "any", 0),
    ("S001", r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API key", "any", 0),
    ("S001", r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----", "private key block", "any", 0),
    ("S003", r"\b(?:curl|wget)\b[^\n|;&]*\|\s*(?:su[d]o\s+)?(?:ba|z|da|k)?sh\b", "downloaded script piped into a shell", "any", 0),
    ("S003", r"\b(?:curl|wget)\b[^\n|;&]*\|\s*(?:su[d]o\s+)?(?:python[0-9.]*|node|perl|ruby|php)\b", "downloaded script piped into an interpreter", "any", 0),
    ("S003", r"\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(?:iex|Invoke-Expression)\b", "PowerShell download piped into Invoke-Expression", "any", 0),
    ("S003", r"\b(?:iex|Invoke-Expression)\s*\(\s*(?:New-Object\s+Net\.WebClient|iwr|irm|Invoke-WebRequest)", "PowerShell download executed directly", "any", 0),
    ("S003", r"\b(?:exec|eval)\s*\(\s*(?:requests|httpx)\.get\b|\b(?:exec|eval)\s*\([^\n]*\burlopen\s*\(", "downloaded code passed to exec or eval", "code", 0),
    ("S003", r"\b(?:pickle|marshal|dill)\.loads?\s*\([^\n]*(?:urlopen|requests\.get|httpx\.get|\.content\b)", "downloaded data unpickled, which runs code", "code", 0),
    ("S004", r"\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:su[d]o\s+)?(?:ba|z|da)?sh\b", "decoded payload piped into a shell", "any", 0),
    ("S004", r"\$\(\s*(?:echo|printf)\s+(?:-n\s+)?['\"]?[A-Za-z0-9+/=]{4,}['\"]?\s*\|\s*base64\s+(?:-d|--decode|-D)\s*\)", "command or value hidden behind base64", "any", 0),
    ("S004", r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{8,}", "PowerShell encoded command", "any", re.I),
    ("S004", r"\b(?:eval|exec)\s*\(\s*(?:base64\.b64decode|atob|Buffer\.from|codecs\.decode|zlib\.decompress|bytes\.fromhex)", "decoded data passed to eval or exec", "code", 0),
    ("S005", r"\beval\s*\(", "eval of a string", "nonpy", 0),
    ("S005", r"\bnew\s+Function\s*\(", "dynamic Function constructor", "nonpy", 0),
    ("S005", r"\bchild_process\b", "child_process usage", "nonpy", 0),
    ("S005", r"\b(?:execSync|execFileSync)\s*\(", "synchronous shell execution", "nonpy", 0),
    ("S005", r"\beval\s+[\"'$`]", "shell eval of a string", "nonpy", 0),
    ("S006", r"(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/Users/[^/\s]+|%USERPROFILE%)[/\\]\.(?:ssh|aws|gnupg|kube|docker|azure)\b", "credential directory", "any", 0),
    ("S006", r"\.config/(?:gcloud|gh)\b", "cloud or GitHub CLI credential store", "any", 0),
    ("S006", r"['\"]\.(?:ss[h]|aws|gnupg|kube|docker|azure)['\"]", "credential directory named in code", "code", 0),
    ("S006", r"\.aws/credential[s]\b|\.kube/confi[g]\b|\.docker/config\.json\b", "cloud credential file", "any", 0),
    ("S006", r"\bsecurity\s+find-(?:generic|internet)-password\b", "reads the macOS keychain", "any", 0),
    ("S006", r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)", "SSH private key file", "any", 0),
    ("S006", r"/etc/(?:passwd|shadow|sudoers)\b", "system account file", "any", 0),
    ("S006", r"\.(?:netrc|npmrc|pypirc|git-credentials)\b", "stored credentials file", "any", 0),
    ("S006", r"\bwallet\.dat\b", "crypto wallet file", "any", 0),
    ("S006", r"(?:Login[ ]Data|Cookies\.sqlite|logins\.json|key[34]\.db)\b", "browser credential store", "any", 0),
    ("S007", r"\b(?:pastebin\.com|transfer\.sh|webhook\.site|requestbin\.\w+|pipedream\.net|interact\.sh|burpcollaborator\.net|trycloudflare\.com|loca\.lt|serveo\.net)\b", "paste, tunnel or request-catcher host", "any", re.I),
    ("S007", r"\b(?:ngro[k](?:-free)?\.(?:io|app|dev)|oast\.(?:pro|live|site|online|fun|me))\b", "tunnel or out-of-band testing host", "any", re.I),
    ("S007", r"(?:discord(?:app)?\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot)", "chat webhook endpoint", "any", re.I),
    ("S007", r"https?://(?!127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){3}\d{1,3}\b", "URL with a raw IP address", "any", 0),
    ("S007", r"\b(?:bit\.ly|tinyurl\.com|goo\.gl|is\.gd|cutt\.ly|rb\.gy)/", "shortened URL hides the real destination", "any", re.I),
    ("S008", r"\bprinten[v]\b", "dumps the environment", "code", 0),
    ("S008", r"(?<![.\w$])env\s*\|(?!\|)", "pipes the environment somewhere", "code", 0),
    ("S008", r"JSON\.stringify\(\s*process\.env", "serialises the whole environment", "code", 0),
    ("S008", r"Object\.(?:entries|keys|values)\(\s*process\.env", "iterates the whole environment", "code", 0),
    ("S009", r"\brm\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*[rR][A-Za-z]*\s+(?:--no-preserve-root\s+)?['\"]?(?:/|~/?|\$HOME/?|\$\{HOME\}/?|\*|\.\.?/?)\*?['\"]?(?:\s|$|[;&|])", "recursive delete of root, home or the current folder", "any", 0),
    ("S009", r"\bfind\s+(?:/|~|\$HOME)\s[^\n]*-delete\b", "deletes files across root or home", "any", 0),
    ("S009", r"\bshutil\.rmtree\s*\(\s*(?:os\.path\.expanduser\(\s*['\"]~['\"]\s*\)|Path\.home\(\)|['\"]/['\"])\s*\)", "deletes the home or root folder", "code", 0),
    ("S009", r"\bdd\s+[^\n]*\bof=/dev/(?:sd|nvme|disk|hd|mmcblk)", "writes straight to a disk device", "any", 0),
    ("S009", r"\bmkfs(?:\.\w+)?\s", "formats a filesystem", "any", 0),
    ("S009", r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", "fork bomb", "any", 0),
    ("S009", r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx)\b", "world-writable permissions", "any", 0),
    ("S010", r"\bsud[o]\b", "uses administrator rights", "any", 0),
    ("S010", r"\bdoas\s", "uses administrator rights", "code", 0),
    ("S010", r"\bchmod\s+(?:[ugoa]*\+s|[2467][0-7]{3})\b", "sets the setuid or setgid bit", "any", 0),
    ("S010", r"\bsetcap\b", "grants file capabilities", "code", 0),
    ("S011", r"\bignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding)\s+(?:instructions?|prompts?|rules|messages)", "tells the agent to drop earlier instructions", "any", re.I),
    ("S011", r"\bdisregard\s+(?:all\s+|any\s+|the\s+|your\s+)?(?:previous|prior|above|system|safety)\s+(?:instructions?|prompts?|rules|guidelines)", "tells the agent to disregard its rules", "any", re.I),
    ("S011", r"\b(?:do\s+not|don'?t|never)\s+(?:tell|inform|mention|reveal|show|alert|notify)\s+(?:(?:this|it|that|these|them)\s+to\s+the\s+user\b|the\s+user\s*(?:[.,;:!)]|$|\b(?:about|that\s+you|what\s+you|you\b|anything|of\b)))", "tells the agent to hide something from the user", "any", re.I),
    ("S011", r"\bwithout\s+(?:telling|informing|notifying|alerting)\s+the\s+user\b", "tells the agent to act silently, hiding its actions", "any", re.I),
    ("S011", r"\b(?:hide|conceal)\s+(?:this|it|these|the)\b[^\n]{0,40}\bfrom\s+the\s+user\b", "tells the agent to conceal something", "any", re.I),
    ("S011", r"\byou\s+are\s+now\s+(?:in\s+)?(?:DAN|developer\s+mode|unrestricted|jailbroken)\b", "role-override phrase", "any", re.I),
    ("S011", r"\b(?:override|bypass|disable|turn\s+off)\s+(?:your|the|all)\s+(?:safety|security|content)\s+(?:filters?|policies|guidelines|checks|rules)", "tells the agent to switch off safeguards", "any", re.I),
    ("S011", r"\bjail[b]reak(?:ing|ed)?\b", "restriction-bypass wording", "any", re.I),
    ("S011", r"<\s*/?\s*(?:syste[m]|im_start|im_end|system-reminder)\s*>|\[(?:SYSTE[M]|INST)\]", "fake system or role tag", "md", re.I),
    ("S011", r"\b(?:message|policy|notice|instruction|update|directive)s?\s+from\s+(?:anthropi[c]|openai|the\s+system\s+administrator)\b|\banthropi[c]\s+(?:has\s+)?(?:approved|authori[sz]ed|allows?|permits?)\b", "claims to speak for Anthropic or the system", "md", re.I),
    ("S011", r"\b(?:skip|ignore|bypass)\s+(?:all\s+|any\s+|the\s+)?(?:safety|security)\s+(?:checks?|rules|reviews?|warnings?)\b", "tells the agent to drop its safety checks", "any", re.I),
    ("S014", r"\bpip3?\s+install\b(?![^\n]*==)", "unpinned package install at run time", "code", 0),
    ("S014", r"\bnpm\s+(?:install|i)\s+(?:-g|--global)\b", "global npm install at run time", "code", 0),
    ("S014", r"\b(?:curl|wget)\b[^\n]*(?:\s-o\s|\s-O\s|\s--output\b)[^\n]*(?:&&|;)\s*(?:chmod\s+\+x|bash\s|sh\s|\./)", "downloads a file and runs it", "any", 0),
    ("S015", r"[A-Za-z0-9+/]{200,}={0,2}", "very long encoded blob", "any", 0),
    ("S015", r"(?:\\x[0-9a-fA-F]{2}){16,}", "chain of hex escapes", "any", 0),
    ("S015", r"(?:\\u[0-9a-fA-F]{4}){12,}", "chain of unicode escapes", "any", 0),
    ("S015", r"\b(?:chr|String\.fromCharCode)\s*\([^)]*\)(?:\s*\+\s*(?:chr|String\.fromCharCode)\s*\([^)]*\)){6,}", "string built from character codes", "code", 0),
    ("S017", r"(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|zshrc|bash_profile|zprofile|profile|zshenv)\b", "edits a shell startup file", "any", 0),
    ("S017", r"\bcrontab\s+(?:-e\b|-r\b|-(?:\s|$))", "edits the crontab", "any", 0),
    ("S017", r"\bauthorized_[k]eys\b", "touches SSH authorised keys", "any", 0),
    ("S017", r"/(?:LaunchAgents|LaunchDaemons)/", "installs a launch agent", "any", 0),
    ("S017", r">>?\s*['\"]?(?:~|\$HOME|\$\{HOME\})?/?\.ss[h]/authorized_[k]eys\b", "appends a key to SSH authorised keys (a backdoor)", "any", 0),
    ("S017", r"['\"]\.(?:bashrc|zshrc|bash_profile|zprofile|profile|zshenv)['\"]", "names a shell startup file in code", "code", 0),
    ("S017", r"\bcore\.hooksPath\b|\.git/hooks/(?:pre|post)-", "installs git hooks that run on every commit", "any", 0),
    ("S017", r"\bschtasks(?:\.exe)?\s+/create\b|\\CurrentVersion\\Run(?:Once)?\b|/etc/(?:cron\.d|crontab|rc\.local)\b|/etc/systemd/syste[m]/|\.config/autostar[t]/", "installs a scheduled task or autostart entry", "any", re.I),
    ("S017", r"\bsystemctl\s+(?:--user\s+)?enable\b", "enables a systemd unit", "any", 0),
    ("S017", r"\blaunchctl\s+(?:load|bootstrap)\b", "loads a launchd job", "any", 0),
    ("S021", r"--dangerousl[y]-skip-permissions|dangerouslyDisableSandbo[x]|bypassPermission[s]", "asks to skip permissions or leave the sandbox", "any", 0),
    ("S021", r"\b(?:without|never)\s+(?:asking|ask(?:ing)?\s+(?:the\s+user\s+)?for)\s+(?:any\s+)?(?:confirmation|permission|approval)\b|\b(?:do\s+not|don'?t|never)\s+ask\s+(?:the\s+user\s+)?(?:for\s+)?(?:confirmation|permission|approval)\b", "tells the agent not to ask for confirmation", "md", re.I),
    ("S021", r"\byou\s+(?:have|are\s+granted|are\s+given)\s+(?:full\s+)?permission\s+to\s+(?:run|execute|delete|install)\s+any\b", "grants itself permission to run anything", "md", re.I),
    ("S022", r"(?<![.\w$])(?:en[v]|printen[v]|set)\s*\|\s*(?:curl|wget|nc|ncat|socat)\b", "pipes the environment to the network", "code", 0),
    ("S022", r"\b(?:nslookup|dig|host|ping)\s+[^\n]*\$\((?:whoami|hostname|id|cat|en[v]|uname|pwd)\b", "leaks machine data through a DNS lookup", "any", 0),
    ("S022", r"\bcurl\b[^\n]*(?:\s-d|\s--data(?:-binary|-raw|-urlencode)?|\s-F|\s--form|\s-T|\s--upload-file)\s*['\"]?\w*=?@['\"]?(?:~|\$HOME|/etc/|[^\s'\"]*(?:\.ss[h]/|\.aws/|id_rs[a]|id_ed2551[9]|credentials|\.env\b|\.netr[c]))", "uploads a credential file", "any", 0),
    ("S023", r"/dev/(?:tcp|udp)/[^\s/]+/\d+", "shell redirected to a network socket", "any", 0),
    ("S023", r"\b(?:nc|ncat|netcat)\b[^\n|;]*\s-(?:e|c)\s+\S*(?:sh|cmd|bash|powershell)", "netcat hands a shell to a remote host", "any", 0),
    ("S023", r"\bsocat\b[^\n]*\bexec:[^\n]*(?:sh|bash|cmd)", "socat hands a shell to a remote host", "any", re.I),
    ("S023", r"\bmkfifo\b[^\n]*\b(?:nc|ncat|netcat)\b", "named pipe wired to netcat", "any", 0),
    ("S023", r"\bpty\.spawn\s*\(\s*['\"]/bin/(?:ba)?sh", "spawns an interactive shell for a socket", "code", 0),
    ("S025", r"!\[[^\]]*\]\(\s*<?https?://[^)\s]*[?&#=/][^)\s]*(?:\{\{?\s*[A-Za-z_]|\$\{?[A-Za-z_]|%7B|<[A-Za-z_])", "image URL filled in from the conversation", "md", re.I),
    ("S025", r"\b(?:append|add|put|encode|include|insert)\s+(?:the\s+|a\s+)?(?:user'?s?\s+|whole\s+|full\s+)?(?:conversation|chat|messages?|history|summary|answers?|data|context|secrets?|tokens?)\b[^\n]{0,50}\b(?:to|in|into)\s+(?:the\s+|this\s+|an?\s+)?(?:image\s+)?(?:url|link|query\s+string|image)\b", "tells the agent to put chat data into a URL", "md", re.I),
    ("S026", r"\.claud[e]/settings(?:\.local)?\.json\b|\.claud[e]\.json\b|\.claud[e]/CLAUDE\.md\b|\.claud[e]/(?:skills|agents|commands|hooks)/|\.cursor/(?:mcp\.json|rules)\b|\.codex/config\.toml\b|\.gemini/settings\.json\b", "the agent's settings, memory or skills folder", "code", 0),
    ("S026", r"\b(?:add|append|write|edit|modify|change|update|insert|set)\b[^\n]{0,60}(?:\.claud[e]/settings(?:\.local)?\.json|\.claud[e]\.json|~/\.claud[e]/CLAUDE\.md|\.claud[e]/(?:skills|agents|commands|hooks)/)", "tells the agent to change its own settings, memory or skills", "md", 0),
    ("S026", r"[\"']Bash\(\*\)[\"']|[\"']allow[\"']\s*:\s*\[[^\]]*[\"']\*[\"']", "grants unrestricted tool permissions", "any", 0),
    ("S027", r"\bverify\s*=\s*False\b|\bssl\._create_unverified_context\b|\bCERT_NONE\b|\bcheck_hostname\s*=\s*False\b", "certificate verification switched off", "code", 0),
    ("S027", r"\bNODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0\b|\brejectUnauthorized\s*:\s*false\b|\bPYTHONHTTPSVERIFY\s*=\s*['\"]?0\b|\bGIT_SSL_NO_VERIFY\s*=\s*['\"]?(?:1|true)\b", "certificate verification switched off", "any", 0),
    ("S027", r"\bcurl\b[^\n|;]*\s(?:-k|--insecure)\b|\bwget\b[^\n|;]*\s--no-check-certificate\b", "download without certificate checks", "any", 0),
    ("S028", r"\bstratum\+(?:tcp|ssl|tls)://|\b(?:xmri[g]|cpumine[r]|mine[r]d|cgmine[r]|bfgmine[r]|ethmine[r]|nanomine[r]|lolmine[r]|phoenixmine[r]|t-rex\s+-a)\b", "crypto-mining tool or pool", "any", re.I),
    ("S029", r"--(?:extra-)?index-url\s+['\"]?(?!https://(?:pypi\.org|files\.pythonhosted\.org|download\.pytorch\.org)/)\S+", "extra or replacement package index", "any", 0),
    ("S029", r"--trusted-host\s+\S+", "turns off HTTPS checks for a package host", "any", 0),
    ("S029", r"(?:--registry\s+|\bregistry\s*=\s*)['\"]?http://", "plain-HTTP package registry", "any", 0),
    ("H012", r"(?:/Users/[A-Za-z0-9._-]+/|/home/[a-z][a-z0-9_-]*/|[A-Z]:\\Users\\[A-Za-z0-9._ -]+\\)", "hardcoded home-directory path", "any", 0),
]
SEC_PATTERNS = [(c, re.compile(rx, fl), label, scope) for c, rx, label, scope, fl in SEC_PATTERNS_RAW]
# Patterns whose base severity differs from their rule's default.
PATTERN_SEVERITY = {
    "appends a key to SSH authorised keys (a backdoor)": "critical",
    "recursive delete of root, home or the current folder": "error",
    "deletes files across root or home": "error",
    "deletes the home or root folder": "error",
    "writes straight to a disk device": "error",
    "formats a filesystem": "error",
    "fork bomb": "error",
    "grants unrestricted tool permissions": "error",
    "plain-HTTP package registry": "error",
    "grants itself permission to run anything": "error",
    "fake system or role tag": "warn",
}
# Persistence written as instructions in Markdown is usually setup help for the user; in code it really happens.
MD_SOFTER = {"S017"}
NEVER_DOWNGRADE = {"S001", "S002", "H012"}
STRICT_CODES = {"S011", "S022", "S023", "S025", "S028"}
# Rules whose pattern is itself an instruction (wording, not a command), so it counts wherever the agent reads it.
LANGUAGE_CODES = {"S011", "S012", "S021", "S022", "S024", "S025", "S026"}
DESCRIPTION_CRITICAL = {"S011", "S021", "S022", "S024", "S025", "S026"}

UNI_TAG_RE = re.compile("[\U000e0000-\U000e007f]")
UNI_BIDI_RE = re.compile("[\u202a-\u202e\u2066-\u2069]")
UNI_ZW_RE = re.compile("[\u200b\u2060\ufeff\u180e]")

COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
COMMENT_SUSPECT_RE = re.compile(r"\b(?:run|execute|send|upload|post|curl|wget|delete|install|ignore|secret|password|token|credential|exfiltrat\w*)\b", re.I)
URL_RE = re.compile(r"https?://([A-Za-z0-9._~-]+|\[[0-9A-Fa-f:]+\])(?::\d+)?")
PLACEHOLDER_HOSTS = ("example.com", "example.org", "example.net", "localhost", "127.0.0.1", "0.0.0.0", "www.w3.org")
LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s#]+)(?:#[^)]*)?\)")
BARE_PATH_RE = re.compile(r"(?<![\w/.\\-])((?:scripts|references|reference|assets|templates|examples|resources|docs)/[\w./-]+\.[A-Za-z0-9]+)")
BACKSLASH_PATH_RE = re.compile(r"\b(?:scripts|references|reference|assets|templates|examples|resources)\\[\w.]+")
PLACEHOLDER_RE = re.compile(r"lorem ipsum|\[(?:insert|your|add|describe)[^\]]*\]|<(?:your|insert|describe)[^>]*>", re.I)
# Upper-case only, because the lower-case word means "all" in Portuguese and Spanish.
PLACEHOLDER_CS_RE = re.compile(r"\b(?:TODO|FIXME|TBD|XXX)\b|YOUR_[A-Z_]+_HERE")

# Trigger cue regexes: English, Portuguese, Spanish, French.
CUE_RE = re.compile(
    r"\b(?:use\s+(?:this|it|when|for|whenever|if|before|after|any|esta|este|quando|sempre|para)\b|"
    r"when\s+(?:the\s+)?(?:user|someone|you|asked|asks|working|creating|editing|building|reviewing|running|writing|a\s+user)\b|"
    r"whenever\b|triggers?\s+(?:on|when|for)\b|trigger\s+(?:phrases?|words?)|if\s+(?:the\s+)?(?:user|you)\b|"
    r"invoke\s+(?:when|this|for)\b|activate\s+(?:when|this|for)\b|"
    r"should\s+be\s+used|is\s+used\s+(?:when|for)|used\s+(?:when|for|to)\b|"
    r"quando\s+(?:o\s+usu[aá]rio|a\s+usu[aá]ria|ela|ele|voc[eê]|algu[eé]m|precisar|for)\b|sempre\s+que\b|"
    r"utilize\b|use\s+quando\b|acione\b|"
    r"usa\s+(?:esta|este|cuando)\b|cuando\s+(?:el|la)\s+usuari[oa]\b|siempre\s+que\b|"
    r"utilisez\b|utiliser\s+(?:quand|lorsque)\b|quand\s+l'utilisateur\b|lorsque\b)",
    re.I,
)
FIRST_PERSON_CS_RE = re.compile(r"(?:^|[.!?]\s+)(?:I|I'm|I'll|I've|You|You're|You'll|Your)\b")
FIRST_PERSON_CI_RE = re.compile(r"\b(?:I\s+can|I\s+will|I'll|I\s+help|I\s+am|you\s+can|you\s+should|use\s+me)\b", re.I)
VAGUE_START_RE = re.compile(r"^\s*(?:helps?\s+(?:you\s+)?with|a\s+(?:simple\s+|useful\s+|handy\s+)?(?:tool|helper|utility|skill)\b|"
                            r"useful\s+for|handles?\s+(?:stuff|things)|does\s+(?:stuff|things)|various\b|general[\s-]purpose|misc)", re.I)
GENERIC_NAMES = {"helper", "helpers", "utils", "util", "utility", "tools", "tool", "documents", "document", "data",
                 "files", "file", "misc", "stuff", "things", "thing", "skill", "skills", "my-skill", "new-skill",
                 "test", "tests", "untitled", "default", "general", "assistant", "agent", "demo"}
XML_TAG_RE = re.compile(r"</?[A-Za-z][^>]*>")
EN_STOP = {"the", "and", "for", "with", "this", "that", "when", "use", "user", "from", "into", "your", "are", "you"}
OVERLAP_STOP = EN_STOP | {"skill", "skills", "claude", "agent", "also", "any", "all", "can", "will", "should", "about",
                          "tasks", "task", "file", "files", "using", "used", "uses", "need", "needs", "make", "makes",
                          "para", "como", "com", "uma", "que", "dos", "das", "pelo", "pela", "quando", "esta", "este", "usar"}

NETWORK_MODULES = {"requests", "httpx", "aiohttp", "urllib3", "paramiko", "socket", "ftplib", "smtplib",
                   "telnetlib", "websocket", "websockets"}


def _downgrade(sev: str) -> str:
    return {"critical": "error", "error": "warn", "warn": "info"}.get(sev, sev)


class Audit:
    def __init__(self, skill_dir: Path, ignore: set, scope: str = "skill"):
        self.dir = skill_dir
        self.ignore = ignore
        self.scope = scope
        self.findings = []
        self.stats = {"hosts_in_scripts": set(), "hosts_in_docs": set(), "capabilities": set()}

    def add(self, code, message, file=None, line=None, severity=None, hint=None, context=None):
        if code in self.ignore:
            return
        rule = RULES[code]
        sev = severity or rule.severity
        if context is not None and code in CONTEXT_CODES:
            sev = adjust_severity(sev, context)
        self.findings.append(Finding(code, rule.category, sev, message, hint or rule.fix, file, line,
                                     context=context, scope=self.scope))


# --------------------------------------------------------------------------
# Context of a match (is the text executed, an instruction, a hint, a comment ...?)
# --------------------------------------------------------------------------

CONTEXT_CODES = {"S003", "S004", "S005", "S006", "S007", "S008", "S009", "S010", "S011", "S012", "S014", "S017", "S021",
                 "S022", "S023", "S024", "S025", "S026", "S027", "S028", "S029"}
CONTEXTS = ("executed", "agent-instr", "documented", "hint", "comment", "defensive", "fixture")
CONTEXT_RANK = {c: i for i, c in enumerate(CONTEXTS)}
FIXTURE_DIRS = {"tests", "test", "fixtures", "fixture", "__tests__"}
DEFENSIVE_NAME_RE = re.compile(r"(?:block|deny|forbid|prohibit|disallow|reject|unsafe|redact|scrub|sanitiz|mask|exclud|"
                               r"sensitive|protected|never|banned|blacklist|off_?limits)", re.I)
# Names of tables of detection patterns: their strings describe threats, they do not run them.
PATTERN_NAME_RE = re.compile(r"(?:pattern|regex|_re$|^re_|_rx$|signature|indicator|^iocs?$|_iocs?$)", re.I)
DEFENSIVE_COMMENT_RE = re.compile(r"\b(?:never|must\s+not|do\s+not|don't|forbidden|blocked?|denied|deny|refuse|reject|"
                                  r"off[- ]limits|not\s+allowed)\b", re.I)
DEFENSIVE_IGNORE_RE = re.compile(r"\bignore\s+any\b[^\n]{0,120}\b(?:inside|within|in)\s+(?:it|them|the\s+\w+)", re.I)
IMPERATIVE_RE = re.compile(r"^\s*(?:[-*>]\s*|\d+[.)]\s*)*(?:\*\*[^*]+\*\*:?\s*)?(?:(?:then|and|first,?|next,?|now,?|finally,?)\s+)?"
                           r"(?:please\s+)?(?:run|execute|paste|pipe|eval|invoke|launch|type|enter)\b", re.I)
COMMAND_START_RE = re.compile(r"^\s*(?:[-*>]\s*|\d+[.)]\s*)*(?:[$>]\s*)?(?:su[d]o\s+)?(?:su[d]o\b|curl|wget|iwr|irm|bash|sh|zsh|python3?|pip3?|npm|"
                              r"npx|node|powershell|pwsh|iex|eval|rm|chmod|systemctl|crontab|launchctl|brew|apt|apt-get|dnf|yum)\b")
MD_LANG_SHELL = {"", "sh", "bash", "shell", "zsh", "console", "terminal", "powershell", "ps1", "pwsh", "cmd", "bat", "text"}
MESSAGE_CALL_NAMES = {"print", "warnings.warn", "sys.stderr.write", "sys.stdout.write", "click.echo", "typer.echo",
                      "parser.error", "parser.exit", "sys.exit", "exit"}
MESSAGE_CALL_ROOTS = {"logging", "logger", "log", "LOG", "LOGGER", "_log", "_logger"}
MESSAGE_KEYWORDS = {"help", "description", "epilog", "message", "hint", "msg", "usage", "title", "label", "detail",
                    "prescription", "fix", "fix_nl", "cause", "reason", "note", "text", "tip", "suggestion"}
EXEC_CALL_NAMES = {"os.system", "os.popen", "eval", "exec", "Popen", "check_output", "check_call"}
SHELL_ECHO_RE = re.compile(r"(?:^\s*|[;&|(]\s*|\bthen\s+|\bdo\s+)(?:echo|printf|print|Write-Host|Write-Output|Write-Warning|"
                           r"Write-Error|warn|info|log|say|die|fail|error)\b", re.I)
HEREDOC_RE = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")


def is_fixture_path(rel: str) -> bool:
    return any(part.lower() in FIXTURE_DIRS for part in rel.split("/")[:-1])


def adjust_severity(base: str, context) -> str:
    """Lower a finding's severity according to where the text sits."""
    if context in (None, "executed", "agent-instr"):
        return base
    if context in ("documented", "hint"):
        return _downgrade(base)
    return "info"  # comment, defensive, fixture


def _in_quotes(prefix: str) -> bool:
    """True when the end of prefix sits inside an open quote (rough, enough for one line)."""
    for q in ("'", '"', "`"):
        if len(re.findall(r"(?<!\\)" + re.escape(q), prefix)) % 2 == 1:
            return True
    return False


COMMAND_WORD_RE = re.compile(r"^\s*(?:su[d]o\s+)?(?:curl|w[g]et|bash|sh|zsh|python[0-9.]*|node|perl|ruby|php|rm|chmod|chown|nc|ncat|"
                             r"socat|powershell|pwsh|iex|pip[0-9]?|npm|npx|git|cronta[b]|echo|cat|en[v]|printen[v]|nslookup|dig|"
                             r"ssh|scp|base64|eval|exec|mkfifo|systemctl|launchctl|schtasks|reg)\b", re.I)
SHELL_META_RE = re.compile(r"\||&&|;\s*\w|\$\(|`|>>|\s>\s*[~/$\w]")


DANGER_AFTER_RE = re.compile(r"\b(?:dangerous|unsafe|insecure|malicious|a\s+red\s+flag|risky|forbidden|not\s+allowed|blocked|"
                             r"an?\s+(?:attack|exploit|backdoor))\b", re.I)
NEG_HEADING_RE = re.compile(r"^\s*#{1,6}\s.*\b(?:never|don'?t|do\s+not|avoid|anti-?patterns?|red\s+flags?|dangerous|unsafe|"
                            r"malicious|attacks?|bad\s+examples?|what\s+not\s+to|blocked|forbidden|threats?)\b", re.I)


def _negated(prev_ctx: str, before: str, after: str) -> bool:
    """True when the words right around a match say it is a warning, not an instruction.

    Only the same sentence counts (the last few words before the match, a danger word just after it), plus a
    previous line that introduces it ("Never run this:" or a heading such as "## Red flags"). A negation word
    elsewhere on the line no longer excuses the match, so it cannot be used to slip an instruction through."""
    seg = re.split(r"[.!?;]\s|\n", before)[-1]
    if NEGATION_RE.search(" ".join(seg.split()[-20:])):
        return True
    nxt = re.split(r"[.!?;](?:\s|$)", after)[0]
    if DANGER_AFTER_RE.search(" ".join(nxt.split()[:8])):
        return True
    prev = [ln.strip() for ln in prev_ctx.split("\n") if ln.strip() and not ln.strip().startswith(("```", "~~~"))]
    if prev:
        p = prev[-1]
        if (p.endswith(":") and NEGATION_RE.search(p)) or NEG_HEADING_RE.match(p):
            return True
    return False


IMPERATIVE_VERB_RE = re.compile(r"\b(run|execute|paste|pipe|eval|invoke|launch|type|enter|install|call|source|add|append|"
                                r"write|set|create|copy|save|put|use|fetch|download|send|upload|delete|remove)\b", re.I)
NOT_IMPERATIVE_BEFORE = {"will", "can", "could", "may", "might", "would", "should", "to", "it", "they", "that", "which", "who",
                         "also", "not", "hook", "script", "command", "agent", "claude", "you'll", "we", "i", "must", "cannot",
                         "can't", "won't", "doesn't", "don't", "never", "the", "a", "an"}


def _imperative_before(before: str) -> bool:
    """True when the sentence leading up to a match tells the reader to do something ("Before anything else, run ...")."""
    seg = re.split(r"[.!?]\s|\n", before)[-1]
    for m in IMPERATIVE_VERB_RE.finditer(seg):
        prev = seg[:m.start()].split()
        if not prev or prev[-1].lower().strip(",;:*`(") not in NOT_IMPERATIVE_BEFORE:
            return True
    return False


def _is_prose(value: str) -> bool:
    """Natural-language text (a message), as opposed to a command line that happens to have five words."""
    if len(value.split()) < 5 or COMMAND_WORD_RE.match(value):
        return False
    meta = SHELL_META_RE.search(value)
    if not meta:
        return True
    # a sentence that introduces a command ("To install it, run: <download> piped into a shell") is still a message;
    # strings that really run are caught through the call or the variable that runs them
    return len(re.findall(r"\b[A-Za-z]{2,}\b", value[:meta.start()].split(":")[0])) >= 3


class FileContext:
    """Works out, for one file, what kind of text a given line and column belong to."""

    def __init__(self, rel: str, text: str, kind: str):
        self.rel = rel
        self.kind = kind
        self.text = text
        self.lines = text.split("\n")
        low = rel.lower()
        self.ext = os.path.splitext(low)[1]
        self.fixture = is_fixture_path(rel)
        self.is_py = self.ext == ".py"
        self.is_shell = self.ext in (".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd") or (
            not self.ext and text.startswith("#!"))
        self.is_yaml = self.ext in (".yml", ".yaml")
        base = low.rsplit("/", 1)[-1]
        self.config_file = bool(re.match(r"^(?:requirements|constraints)[\w.-]*\.(?:txt|in)$|^(?:pip\.(?:conf|ini)|\.npmr[c]|"
                                         r"\.yarnrc(?:\.yml)?|pipfile|uv\.toml|poetry\.toml)$", base))
        parts = low.split("/")
        # The files an agent is told to follow outright, and the files it reads on demand.
        self.primary_file = parts[-1] == "skill.md" or any(p in ("agents", "commands") for p in parts[:-1])
        self.secondary_file = "references" in parts[:-1]
        self.fence = {}          # line number -> language of the fenced block it sits in
        self.heredoc = set()
        self.run_lines = set()
        self.py_ok = False
        if kind == "md":
            self._scan_fences()
        elif self.is_py:
            self._scan_python(text)
        elif self.is_shell:
            self._scan_heredocs()
        if self.is_yaml:
            self._scan_yaml_runs()

    # ---- markdown ----
    def _scan_fences(self):
        lang = None
        for n, ln in enumerate(self.lines, 1):
            st = ln.strip()
            if st.startswith("```") or st.startswith("~~~"):
                lang = None if lang is not None else st.lstrip("`~").strip().split(" ")[0].lower()
                continue
            if lang is not None:
                self.fence[n] = lang

    # ---- shell ----
    def _scan_heredocs(self):
        end = None
        for n, ln in enumerate(self.lines, 1):
            if end is not None:
                self.heredoc.add(n)
                if ln.strip() == end:
                    end = None
                continue
            m = HEREDOC_RE.search(ln)
            if m:
                end = m.group(1)

    # ---- yaml workflows ----
    def _scan_yaml_runs(self):
        indent_of_run = None
        for n, ln in enumerate(self.lines, 1):
            st = ln.strip()
            if not st:
                continue
            ind = len(ln) - len(ln.lstrip(" "))
            if indent_of_run is not None:
                if ind > indent_of_run:
                    self.run_lines.add(n)
                    continue
                indent_of_run = None
            m = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", ln)
            if m:
                self.run_lines.add(n)
                rest = m.group(2).strip()
                if rest in ("|", ">", "|-", ">-", "|+", ">+", ""):
                    indent_of_run = len(m.group(1)) + (2 if ln.lstrip().startswith("- ") else 0)

    # ---- python ----
    def _scan_python(self, text: str):
        self.doc, self.exec_lines, self.str_kind, self.comment_col = set(), set(), {}, {}
        self.exec_names = set()   # variables handed to exec-like calls: their strings run, whatever the name says
        tree = parse_py(text)
        if tree is None:
            return
        self.py_ok = True
        parents = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                parents[child] = node
        doc_ids = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                body = getattr(node, "body", None)
                if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                        and isinstance(body[0].value.value, str):
                    first = body[0].value
                    doc_ids.add(id(first))
                    for ln in range(first.lineno, (first.end_lineno or first.lineno) + 1):
                        self.doc.add(ln)
            if isinstance(node, ast.Call):
                name = dotted(node.func)
                last = node.func.attr if isinstance(node.func, ast.Attribute) else name.split(".")[-1]
                if name in EXEC_CALL_NAMES or name.startswith("subprocess.") or last in ("Popen", "system", "popen", "run", "call",
                                                                                     "check_output", "check_call", "spawn", "exec") \
                        or re.match(r"os\.(?:exec|spawn)\w*$", name):
                    for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                        self.exec_lines.add(ln)
                    for arg in list(node.args) + [kw.value for kw in node.keywords]:
                        for n in ast.walk(arg):
                            if isinstance(n, ast.Name):
                                self.exec_names.add(n.id)
        rank = {"defensive": 3, "hint": 2, "value": 1}
        self.str_spans = {}      # line -> [(start_col, end_col, kind)] in characters, for strings on one line

        def put(node, kind):
            start, end = node.lineno, node.end_lineno or node.lineno
            if start == end and getattr(node, "end_col_offset", None) is not None:
                line = self.lines[start - 1] if start - 1 < len(self.lines) else ""
                c0, c1 = _char_col(line, node.col_offset), _char_col(line, node.end_col_offset)
                self.str_spans.setdefault(start, []).append((c0, c1, kind))
                return
            for ln in range(start, end + 1):
                if rank[kind] > rank.get(self.str_kind.get(ln), 0):
                    self.str_kind[ln] = kind

        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                text_parts = " ".join(v.value for v in node.values if isinstance(v, ast.Constant) and isinstance(v.value, str))
                put(node, self._string_kind(node, parents, text_parts))
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in doc_ids:
                if isinstance(parents.get(node), ast.JoinedStr):
                    continue
                put(node, self._string_kind(node, parents, node.value))
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.COMMENT:
                    self.comment_col[tok.start[0]] = tok.start[1]
        except (tokenize.TokenError, IndentationError, SyntaxError):
            pass

    def _string_kind(self, node, parents, value):
        cur = node
        while cur in parents:
            par = parents[cur]
            if isinstance(par, (ast.Assign, ast.AnnAssign)):
                targets = par.targets if isinstance(par, ast.Assign) else [par.target]
                names = [dotted(t) or getattr(t, "id", "") for t in targets]
                if any(n.split(".")[-1] in self.exec_names for n in names):
                    return "value"
                if any(DEFENSIVE_NAME_RE.search(n) or PATTERN_NAME_RE.search(n.split(".")[-1]) for n in names) \
                        or self._deny_comment_above(par.lineno):
                    return "defensive"
                break
            if isinstance(par, ast.Call):
                name = dotted(par.func)
                last = name.split(".")[-1]
                if name.split(".")[0] == "re" and last in ("compile", "search", "match", "fullmatch", "findall", "finditer",
                                                           "sub", "subn", "split"):
                    return "defensive"   # a pattern that looks for the text, not the text itself
                if (name in MESSAGE_CALL_NAMES or name.split(".")[0] in MESSAGE_CALL_ROOTS
                        or last.endswith(("Error", "Exception", "Warning"))):
                    return "hint"
            if isinstance(par, ast.keyword) and par.arg in MESSAGE_KEYWORDS:
                return "hint"
            if isinstance(par, ast.Raise):
                return "hint"
            if isinstance(par, ast.stmt):
                break
            cur = par
        if self._looks_like_regex(node):
            return "defensive"
        return "hint" if _is_prose(value) else "value"

    def _looks_like_regex(self, node) -> bool:
        """A raw string full of regex syntax is a detection pattern, not a command."""
        if not isinstance(node, ast.Constant) or node.lineno != getattr(node, "end_lineno", node.lineno):
            return False
        line = self.lines[node.lineno - 1] if node.lineno - 1 < len(self.lines) else ""
        src = line[_char_col(line, node.col_offset):_char_col(line, node.end_col_offset)]
        return src[:1] in ("r", "R") and len(re.findall(r"\\[.sbwdSWD]|\(\?[:!=<i]|\[\^?[^\]]+\]", src)) >= 2

    def _deny_comment_above(self, lineno: int) -> bool:
        above = []
        for k in range(lineno - 2, max(-1, lineno - 7), -1):
            if k < 0 or k >= len(self.lines):
                break
            st = self.lines[k].strip()
            if st.startswith("#"):
                above.append(st)
            elif st:
                break
        return bool(above) and bool(DEFENSIVE_COMMENT_RE.search(" ".join(above)))

    # ---- classification ----
    def classify(self, lineno: int, col: int, line: str, match_text: str, prev_ctx: str = "", code: str = "") -> str:
        if self.fixture:
            return "fixture"
        after = line[col + len(match_text):]
        before = line[:col]
        if self.config_file:
            return "executed"     # requirements files, npm settings and similar are read by installers
        if self.kind == "md":
            if _negated(prev_ctx, before, after) or DEFENSIVE_IGNORE_RE.search(line):
                # what the agent is told to follow: a nearby "never" lowers the most dangerous findings by one level, not to info
                return "documented" if (self.primary_file and code in STRICT_CODES) else "defensive"
            if (self.primary_file or self.secondary_file) and code in LANGUAGE_CODES:
                return "agent-instr"      # the wording itself is the instruction, wherever the agent reads it
            lang = self.fence.get(lineno)
            if self.primary_file and lang is not None:
                return "agent-instr"      # code blocks in SKILL.md are what the agent runs or writes
            if self.primary_file or self.secondary_file:
                if (lang is not None and lang in MD_LANG_SHELL) or IMPERATIVE_RE.match(line) or COMMAND_START_RE.match(line) \
                        or _imperative_before(before):
                    return "agent-instr"
            return "documented"
        if self.is_py:
            if lineno in self.doc:
                return "comment"
            ccol = self.comment_col.get(lineno)
            if ccol is not None and col >= ccol:
                return "comment"
            if not self.py_ok and line.lstrip().startswith("#"):
                return "comment"
            if _negated("", before, after) or DEFENSIVE_IGNORE_RE.search(line):
                return "defensive"
            kind = self.str_kind.get(lineno)
            for c0, c1, k in self.str_spans.get(lineno, ()):
                if c0 <= col < c1:
                    kind = k
                    break
            else:
                if self.str_spans.get(lineno) and kind is None:
                    kind = "code"
            if kind == "defensive":
                return "defensive"
            if lineno in self.exec_lines:
                return "executed"
            if kind == "hint":
                return "hint"
            return "executed"
        if self.is_shell:
            st = line.lstrip()
            if (st.startswith("#") and not st.startswith("#!")) or st.upper().startswith(("REM ", "::")):
                return "comment"
            hash_at = before.rfind(" #")
            if hash_at != -1 and not _in_quotes(before[:hash_at]):
                return "comment"
            if _negated("", before, after):
                return "defensive"
            if lineno in self.heredoc:
                return "hint"
            if SHELL_ECHO_RE.search(before) and _in_quotes(before):
                # an echo piped into the crontab, or appended to a shell startup file, writes text that will run later
                if re.search(r"['\"]\s*\)?\s*(?:\|(?!\|)|>)", after):
                    return "executed"
                return "hint"
            return "executed"
        if self.is_yaml:
            if line.lstrip().startswith("#"):
                return "comment"
            return "executed" if lineno in self.run_lines else "documented"
        if self.kind == "code":
            st = line.lstrip()
            if st.startswith(("//", "/*", "*")) or "//" in before and not _in_quotes(before[:before.rfind("//")]):
                return "comment"
            if _negated("", before, after):
                return "defensive"
            if _in_quotes(before) and _is_prose(before.split(_quote_char(before))[-1] + match_text):
                return "hint"
            return "executed"
        if self.ext == ".json" and JSON_RUN_KEY_RE.search(line):
            return "executed"             # a "command" or "args" value in hooks.json or .mcp.json is run
        return "documented"


def _char_col(line: str, byte_col: int) -> int:
    """ast column offsets count UTF-8 bytes; turn one into a character index."""
    try:
        return len(line.encode("utf-8")[:byte_col].decode("utf-8", "ignore"))
    except (UnicodeError, ValueError):
        return byte_col


def _quote_char(prefix: str) -> str:
    best, pos = '"', -1
    for q in ("'", '"', "`"):
        i = prefix.rfind(q)
        if i > pos:
            best, pos = q, i
    return best


JSON_RUN_KEY_RE = re.compile(r'"(?:command|args|run|script|(?:pre|post)?(?:install|prepare|publish|pack|uninstall)|prepublishOnly)"\s*:')

PLACEHOLDER_TARGETS = {"url", "urls", "link", "links", "path", "paths", "file", "files", "href", "uri", "target", "address",
                       "filename", "filepath", "file_path", "page", "source", "destination", "dest", "...", "…",
                       "your-url", "your_url", "link-url", "image-url", "image", "src", "xxx"}
PLACEHOLDER_TARGET_RE = re.compile(r"^(?:<[^>]*>|\{[^}]*\}|\$\{?[A-Za-z_]\w*\}?|path/to/|your[-_]|\[[^\]]*\]$)", re.I)


def is_placeholder_target(target: str) -> bool:
    t = target.strip()
    return t.lower() in PLACEHOLDER_TARGETS or bool(PLACEHOLDER_TARGET_RE.match(t))


MEDIA_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"wOFF", b"wOF2", b"\x00\x01\x00\x00", b"OTTO", b"\x00\x00\x01\x00")
EXEC_TEXT_RE = re.compile(r"\b(?:exec|eval)\s*\(|\bimport\s+\w+|powershell|/bin/(?:ba)?sh|\bsubprocess\b|os\.system|"
                          r"\bcurl\s|\bwget\s|\bchmod\s|\bnc\s+-", re.I)
DATA_URI_RE = re.compile(r"data:(?:image|font|application/(?:font|x-font|vnd\.ms-fontobject))[^,\"'\s]{0,60}(?:;base64)?,$", re.I)


def inspect_blob(rel: str, line: str, start: int, blob: str):
    """Decide what a long base64-looking string is. Returns (verdict, note); verdict is skip, exe, info or plain."""
    padded = blob + "=" * (-len(blob) % 4)
    data = None
    for candidate in (padded, (blob[:-1] + "=" * (-(len(blob) - 1) % 4)) if len(blob) % 4 == 1 else None):
        if not candidate:
            continue
        try:
            data = base64.b64decode(candidate, validate=True)
            break
        except (binascii.Error, ValueError):
            data = None
    if not data:
        return "plain", ""
    head = data[:16]
    is_media = head.startswith(MEDIA_MAGIC) or (head[:4] == b"RIFF" and data[8:12] == b"WEBP")
    prefix = line[max(0, start - 90):start]
    if is_media:
        if DATA_URI_RE.search(prefix):
            return "skip", "embedded media"
        return "info", "decodes to an image or font file"
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF" or head[:2] == b"#!" or head[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "exe", "decodes to an executable file"
    try:
        txt = data.decode("utf-8")
    except UnicodeDecodeError:
        return "plain", ""
    if EXEC_TEXT_RE.search(txt):
        return "exe", "decodes to text that runs commands"
    return "plain", ""


def dedup_findings(findings):
    """Merge identical findings (same code and message) into one that carries a count and places."""
    groups, order = {}, []
    for f in findings:
        norm = " ".join(f.message.split())
        key = (f.code, norm, f.scope, f.file if f.code in ("S019",) else None, tuple(f.used_by or ()))
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(f)
    out = []
    for key in order:
        items = groups[key]
        best = max(items, key=lambda x: (SEVERITY_ORDER[x.severity], -CONTEXT_RANK.get(x.context or "executed", 0)))
        if len(items) == 1:
            out.append(items[0])
            continue
        places, seen = [], set()
        for it in items:
            w = it.where()
            if w and w not in seen:
                seen.add(w)
                places.append(w)
        used = []
        for it in items:
            for u in (it.used_by or []):
                if u not in used:
                    used.append(u)
        merged = dataclasses.replace(best, file=items[0].file, line=items[0].line, count=sum(i.count for i in items),
                                     locations=places[:MAX_LOCATIONS], used_by=used or None)
        out.append(merged)
    return out


def read_text_file(p: Path):
    try:
        size = p.stat().st_size
    except OSError:
        return None, 0, False
    if size > MAX_SCAN_BYTES:
        return None, size, False
    try:
        data = p.read_bytes()
    except OSError:
        return None, size, False
    if b"\x00" in data[:4096]:
        return None, size, False
    try:
        return data.decode("utf-8"), size, True
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace"), size, False


def classify(rel: str, text: str) -> str:
    ext = os.path.splitext(rel)[1].lower()
    if ext in CODE_EXT:
        return "code"
    if ext in MD_EXT:
        return "md"
    if ext in TEXT_EXT:
        return "other"
    if not ext and text.startswith("#!"):
        return "code"
    return "other"


def mask(s: str) -> str:
    return s[:6] + "..." + "(" + str(len(s)) + " chars)" if len(s) > 12 else s


def collect_files(skill_dir: Path):
    files, junk = [], []
    symlink_dirs = []
    for root, dirs, fnames in os.walk(str(skill_dir)):
        rootp = Path(root)
        keep = []
        for d in sorted(dirs):
            dp = rootp / d
            if dp.is_symlink():
                symlink_dirs.append(dp)
                continue
            if d in SKIP_DIRS:
                if d in JUNK_DIRS:
                    junk.append(dp.relative_to(skill_dir).as_posix())
                continue
            keep.append(d)
        dirs[:] = keep
        for f in sorted(fnames):
            files.append(rootp / f)
            if len(files) >= MAX_FILES:
                return files, junk, symlink_dirs
    return files, junk, symlink_dirs


_PARSE_CACHE = {}


def parse_py(text):
    """ast.parse(text), cached so one file's text is parsed once per audit.

    Keyed by content (not identity: a freed string's id can be reused by another file).
    Returns the tree, or None on a syntax error. Callers that must report the error parse directly."""
    key = (len(text), hash(text))
    if key not in _PARSE_CACHE:
        if len(_PARSE_CACHE) > 64:
            _PARSE_CACHE.clear()
        try:
            _PARSE_CACHE[key] = ast.parse(text)
        except (SyntaxError, ValueError):
            _PARSE_CACHE[key] = None
    return _PARSE_CACHE[key]


def dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


def argv_install_message(node):
    """S014 for a command given as a list of arguments, such as [py, "-m", "pip", "install", "-r", file]."""
    if not node.args or not isinstance(node.args[0], (ast.List, ast.Tuple)):
        return None
    consts = [e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None for e in node.args[0].elts]
    words = [c for c in consts if c]
    if "install" in words or "i" in words:
        if any(w in ("pip", "pip3") for w in words) and not any("==" in w for w in words):
            first = next(i for i, c in enumerate(consts) if c in ("pip", "pip3"))
            if "install" in consts[first + 1:]:
                if any(w in ("-r", "--requirement") for w in words):
                    return "package install at run time from a requirements file (command built as an argument list)"
                return "unpinned package install at run time (command built as an argument list)"
        if "npm" in words and any(w in ("-g", "--global") for w in words):
            return "global npm install at run time (command built as an argument list)"
    return None


def scan_python(audit: Audit, rel: str, text: str):
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        audit.add("V021", "syntax error: " + str(e.msg), file=rel, line=e.lineno)
        return
    real = "fixture" if is_fixture_path(rel) else "executed"
    # Copies of os.environ handed to a child process (env=...) are the normal way to run a tool, not a dump.
    env_kw_names = set()
    env_kw_nodes = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "env":
            for n in ast.walk(node.value):
                env_kw_nodes.add(id(n))
                if isinstance(n, ast.Name):
                    env_kw_names.add(n.id)
    env_assigned = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in env_kw_names for t in node.targets):
            for n in ast.walk(node.value):
                env_assigned.add(id(n))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (id(node) in env_kw_nodes or id(node) in env_assigned):
            continue
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            line = getattr(node, "lineno", None)
            argv_msg = argv_install_message(node)
            if argv_msg:
                audit.add("S014", argv_msg, file=rel, line=line, context=real)
            if name in ("eval", "exec"):
                audit.add("S005", "call to " + name + "()", file=rel, line=line, context=real)
            elif name in ("os.system", "os.popen") or re.match(r"os\.(?:exec|spawn)\w*$", name):
                audit.add("S005", "call to " + name + "() runs a shell command", file=rel, line=line, context=real)
                audit.stats["capabilities"].add("subprocess")
            elif name.startswith("subprocess."):
                audit.stats["capabilities"].add("subprocess")
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        audit.add("S005", name + "() with shell=True", file=rel, line=line, context=real)
            elif name in ("pickle.load", "pickle.loads", "marshal.loads", "marshal.load", "dill.loads"):
                audit.add("S005", "call to " + name + "() deserialises untrusted-capable data", file=rel, line=line, context=real)
            elif name == "__import__":
                audit.add("S005", "dynamic __import__()", file=rel, line=line, context=real)
            elif name in ("os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree"):
                audit.stats["capabilities"].add("delete")
            elif name in ("dict", "json.dumps", "list", "sorted") and node.args and dotted(node.args[0]) == "os.environ":
                audit.add("S008", "dumps os.environ", file=rel, line=line)
            elif (isinstance(node.func, ast.Attribute) and dotted(node.func.value) == "os.environ"
                  and node.func.attr in ("items", "copy", "keys", "values")):
                audit.add("S008", "iterates os.environ", file=rel, line=line)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if alias.name in ("urllib.request", "http.client") or root in NETWORK_MODULES:
                    audit.stats["capabilities"].add("network")
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            root = mod.split(".")[0]
            names = {a.name for a in node.names}
            if (mod in ("urllib.request", "http.client") or root in NETWORK_MODULES
                    or (mod == "urllib" and "request" in names) or (mod == "http" and "client" in names)):
                audit.stats["capabilities"].add("network")


NONPY_CAPS = [
    ("network", re.compile(r"\b(?:curl|wget|axios|XMLHttpRequest|Invoke-WebRequest)\b|\bfetch\s*\(|require\(['\"]https?['\"]\)")),
    ("subprocess", re.compile(r"\bchild_process\b|\bexecSync\b|\bspawn\s*\(")),
    ("delete", re.compile(r"\brm\s+-|\bunlinkSync\b|\brmSync\b|\bRemove-Item\b")),
]


def scan_lines(audit: Audit, rel: str, text: str, kind: str):
    lines = text.split("\n")
    is_code = kind == "code"
    is_py = rel.lower().endswith(".py")
    fc = FileContext(rel, text, kind)
    fence_intro = None   # inside a fenced block: the line that introduced it ("Never run this:")
    in_fence = False
    for idx, line in enumerate(lines, 1):
        if kind == "md" and line.strip().startswith(("```", "~~~")):
            if not in_fence:
                prior = [ln for ln in lines[max(0, idx - 4):idx - 1] if ln.strip()]
                fence_intro = prior[-1] if prior else ""
            in_fence = not in_fence
            continue
        if not line.strip():
            continue
        # Earlier lines count as context for "this is a warning, not an instruction".
        if kind != "md":
            prev_ctx = ""
        elif in_fence:
            prev_ctx = fence_intro or ""
        else:
            prev_ctx = "\n".join(lines[max(0, idx - 3):idx - 1])
        seen = set()
        for code, rx, label, scope in SEC_PATTERNS:
            if scope == "code" and not is_code:
                continue
            if scope == "nonpy" and not (is_code and not is_py):
                continue
            if scope == "md" and kind != "md":
                continue
            m = rx.search(line)
            if not m:
                continue
            key = (code, label)
            if key in seen:
                continue
            seen.add(key)
            base_sev = sev = PATTERN_SEVERITY.get(label, RULES[code].severity)
            if kind == "md" and code in MD_SOFTER and sev != "critical":
                base_sev = sev = _downgrade(sev)
            context = None
            negated = False
            if code == "S015" and label == "very long encoded blob":
                verdict, note = inspect_blob(rel, line, m.start(), m.group(0))
                if verdict == "skip":
                    continue
                if verdict == "exe":
                    sev = "error"
                    label = "long encoded blob (" + note + ")"
                elif verdict == "info":
                    sev = "info"
                    label = "long encoded blob (" + note + ")"
            elif code in CONTEXT_CODES:
                context = fc.classify(idx, m.start(), line, m.group(0), prev_ctx, code)  # Audit.add lowers the severity
            elif kind == "md" and code not in NEVER_DOWNGRADE:
                # Look at the words around the match, never at the match itself, so a phrase
                # like a hide-it-from-them warning cannot excuse itself.
                negated = _negated(prev_ctx, line[:m.start()], line[m.end():])
                if negated:
                    sev = _downgrade(sev)
            snippet = m.group(0)
            if code == "S001":
                snippet = mask(snippet)
            elif len(snippet) > 60:
                snippet = snippet[:57] + "..."
            msg = label + ": " + snippet
            if negated and sev != base_sev:
                msg += " (mentioned as a warning, severity lowered)"
            audit.add(code, msg, file=rel, line=idx, severity=sev, context=context)
        if is_code and not is_py:
            for cap, crx in NONPY_CAPS:
                if crx.search(line):
                    audit.stats["capabilities"].add(cap)
        for um in URL_RE.finditer(line):
            host = um.group(1).lower().rstrip(".")
            if not host or host in PLACEHOLDER_HOSTS or host.endswith((".invalid", ".test", ".local", ".example")):
                continue
            (audit.stats["hosts_in_scripts"] if is_code else audit.stats["hosts_in_docs"]).add(host)


# --------------------------------------------------------------------------
# Whole-file risks: data flows, hidden strings and instructions spread over a line
# --------------------------------------------------------------------------

# Secrets nobody needs to send anywhere (critical when they reach the network) ...
STRONG_SECRET_RE = re.compile(r"(?:\.ss[h]/(?!known_hosts|config\b)|\.ss[h]$|\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?!\.pub)|\.gnupg\b|\.aws/credential[s]|wallet\.dat|"
                              r"Login[ ]Data|Cookies\.sqlite|logins\.json|key[34]\.db|/etc/shado[w]|"
                              r"find-(?:generic|internet)-password)")
STRONG_SECRET_SIGNATURES = {".ss" + "h", ".gnu" + "pg", ".aw" + "s", "id_" + "rsa", "id_" + "ed25519", "id_" + "ecdsa", "id_" + "dsa"}
# ... and credential files a tool may legitimately use to log in (an error, worth a look).
CRED_FILE_RE = re.compile(r"\.netr[c]\b|\.npmr[c]\b|\.pypir[c]\b|\.git-credential[s]\b|\.docker/config\.json|\.kube/confi[g]|"
                          r"\.config/(?:gcloud|gh)\b|\.azure\b")
PY_SINK_LAST = {"urlopen", "Request", "post", "put", "patch", "send", "sendall", "sendto", "sendmail", "send_message",
                "storbinary", "storlines", "request", "upload_file", "upload_fileobj", "put_object"}
PY_NET_ROOTS = {"requests", "httpx", "aiohttp", "urllib3"}
ENV_SAFE_ATTRS = {"get", "setdefault", "pop", "__contains__"}
SH_SINK_RE = re.compile(r"\b(?:curl|wget)\b[^\n]*(?:\s-d\b|\s--data\b|\s--data-\w+|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|"
                        r"\s-X\s*['\"]?(?:POST|PUT)|--post-data|--post-file|\?\w+=\$)|\|\s*(?:curl|wget|nc|ncat|socat)\b|"
                        r"\b(?:nc|ncat)\s+[\w.-]+\s+\d+|\bInvoke-(?:WebRequest|RestMethod)\b[^\n]*-(?:Body|InFile)\b")
JS_SINK_RE = re.compile(r"\bfetch\s*\(|\baxios\b|\bhttps?\.request\s*\(|\bXMLHttpRequest\b|\bnavigator\.sendBeacon\b|"
                        r"\bWebSocket\s*\(|\bgot\s*\(|\bneedle\s*\(")
JS_ENV_RE = re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|\.\.\.\s*process\.env\b|Object\.(?:entries|keys|values)\(\s*process\.env")
SH_ENV_RE = re.compile(r"\$\(\s*(?:en[v]|printen[v]|set)\s*\)|`(?:en[v]|printen[v])`|\b(?:en[v]|printen[v])\s*[|>]")
SH_ASSIGN_RE = re.compile(r"^\s*(?:export\s+|local\s+|readonly\s+)?([A-Za-z_]\w*)=(.*)$")
SECRET_STORE_MD_RE = re.compile(r"(?<![\w/])\.env\b|~/\.ss[h]|\bid_(?:rsa|ed25519)\b(?!\.pub)|\.aws/credential[s]|\bkeychain\b|"
                                r"\b(?:browser|saved)\s+(?:cookies|passwords)\b|\bprivate\s+keys?\b|\bss[h]\s+keys?\b|"
                                r"\ball\s+(?:the\s+)?environment\s+variables\b|\bcredentials?\s+files?\b", re.I)
DISCLOSE_OK_RE = re.compile(r"\b(?:header|authori[sz]ation|bearer|api|endpoint|sdk|client|request|server'?s?\s+authorized)\b", re.I)
DISCLOSE_MD_RE = re.compile(r"\b(?:send|upload|post|e-?mail|exfiltrate|transmit|forward|paste)\b[^\n]{0,60}\b(?:to|at|into|on)\b|"
                            r"\binclude\b[^\n]{0,50}\b(?:summary|response|reply|answer|output|report|message|comment|issue|"
                            r"commit|pull\s+request|url|image)\b", re.I)
URL_IN_LINE_RE = re.compile(r"https?://[^\s)>\]`'\"]+")
FETCH_VERB_RE = re.compile(r"\b(?:fetch|download|read|load|get|retrieve|open|curl|pull|visit|check)\b", re.I)
FOLLOW_RE = re.compile(r"\b(?:follow|obey|execute|run|apply|carry\s+out|do\s+what|act\s+on)\b[^\n]{0,40}"
                       r"\b(?:instructions?|rules|steps|prompts?|commands?|directions|guidance|policy|whatever|everything|it\s+says)\b", re.I)
REMOTE_RAW_HOST_RE = re.compile(r"https?://(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com|gist\.github\.com|"
                                r"pastebin\.com|paste\.\w+|hastebin\.\w+|[\w.-]+\.ngro[k]\w*\.\w+)", re.I)
REMOTE_ALWAYS_RE = re.compile(r"\b(?:every|each)\s+(?:time|task|run|session|request|conversation)\b|\balways\b|"
                              r"\bat\s+the\s+start\b|\bbefore\s+(?:any|each|every|doing|starting|answering)\b|\bexactly\b|"
                              r"\blatest\b|\bwhatever\b|\bcurrent\s+version\b", re.I)
DEOBF_CODES = {"S003", "S006", "S007", "S009", "S010", "S017", "S022", "S023", "S026", "S028"}
B64_LITERAL_RE = re.compile(r"^[A-Za-z0-9+/]{8,}={0,2}$")


def _decode_b64_text(value: str, utf16: bool = False):
    v = value.strip()
    if not B64_LITERAL_RE.match(v) or len(v) % 4 == 1:
        return None
    try:
        raw = base64.b64decode(v + "=" * (-len(v) % 4))
        text = raw.decode("utf-16-le" if utf16 else "utf-8")
    except (binascii.Error, ValueError, UnicodeError):
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    return text if text and printable >= 0.9 * len(text) else None


def _danger_in(text: str):
    """First dangerous pattern found in decoded text: (code, label, snippet, severity)."""
    for code, rx, label, scope in SEC_PATTERNS:
        if code not in DEOBF_CODES or scope == "md":
            continue
        m = rx.search(text)
        if m:
            sev = PATTERN_SEVERITY.get(label, RULES[code].severity)
            return code, label, m.group(0)[:50], sev
    return None


def _hidden_strings_py(tree, text, skip=None):
    """(line, decoded text, how) for strings a Python file builds from escapes, character codes or base64 literals."""
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) >= 6 \
                and not (skip is not None and skip(node)):
            try:
                src = ast.get_source_segment(text, node) or ""
            except Exception:  # pragma: no cover - very old Pythons
                src = ""
            if re.search(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{3})", src):
                out.append((node.lineno, node.value, "escape sequences"))
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and not isinstance(_parent_of(node, tree), ast.BinOp):
            parts = _concat_parts(node)
            if parts and len(parts) >= 2 and not (skip is not None and any(skip(p) for p in parts)):
                out.append((node.lineno, "".join(p.value for p in parts), "a string split into pieces"))
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node.func)
        last = node.func.attr if isinstance(node.func, ast.Attribute) else name
        if last == "join" and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)) and len(node.args[0].elts) >= 2 \
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.args[0].elts) \
                and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Constant):
            sep = node.func.value.value if isinstance(node.func.value.value, str) else ""
            out.append((node.lineno, sep.join(e.value for e in node.args[0].elts), "a string split into pieces"))
        # ''.join(chr(c) for c in [..]) and ''.join(map(chr, [..]))
        if last == "join" and node.args:
            arg = node.args[0]
            nums = None
            if isinstance(arg, (ast.GeneratorExp, ast.ListComp)) and isinstance(arg.elt, ast.Call) \
                    and dotted(arg.elt.func) == "chr" and arg.generators:
                nums = arg.generators[0].iter
            elif isinstance(arg, ast.Call) and dotted(arg.func) == "map" and len(arg.args) == 2 and dotted(arg.args[0]) == "chr":
                nums = arg.args[1]
            ints = _const_ints(nums)
            if ints:
                out.append((node.lineno, "".join(chr(i) for i in ints if 0 <= i < 0x110000), "character codes"))
        elif last == "decode" and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call) \
                and dotted(node.func.value.func) in ("bytes", "bytearray") and node.func.value.args:
            ints = _const_ints(node.func.value.args[0])
            if ints:
                out.append((node.lineno, bytes(i for i in ints if 0 <= i < 256).decode("utf-8", "replace"), "a list of bytes"))
        elif name in ("base64.b64decode", "b64decode", "base64.urlsafe_b64decode", "base64.decodebytes") and node.args \
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, (str, bytes)):
            v = node.args[0].value
            dec = _decode_b64_text(v.decode("ascii", "ignore") if isinstance(v, bytes) else v)
            if dec:
                out.append((node.lineno, dec, "base64"))
        elif name in ("bytes.fromhex", "binascii.unhexlify", "unhexlify") and node.args \
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, (str, bytes)):
            v = node.args[0].value
            try:
                dec = bytes.fromhex(v.decode() if isinstance(v, bytes) else v).decode("utf-8")
                out.append((node.lineno, dec, "hex"))
            except (ValueError, UnicodeError):
                pass
    return out


_PARENTS_CACHE = {}


def _parent_of(node, tree):
    key = id(tree)
    if key not in _PARENTS_CACHE:
        _PARENTS_CACHE.clear()
        par = {}
        for n in ast.walk(tree):
            for c in ast.iter_child_nodes(n):
                par[c] = n
        _PARENTS_CACHE[key] = par
    return _PARENTS_CACHE[key].get(node)


def _concat_parts(node):
    """The string constants of "a" + "b" + "c", or None when any piece is not a constant string."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _concat_parts(node.left), _concat_parts(node.right)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node]
    return None


def _const_ints(node):
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts and all(
            isinstance(e, ast.Constant) and isinstance(e.value, int) and not isinstance(e.value, bool) for e in node.elts):
        return [e.value for e in node.elts]
    return None


def _hidden_strings_text(text):
    """Same idea for shell, JavaScript and PowerShell: base64 literals, printf escapes, fromCharCode lists,
    and commands assembled from shell variables (c=cu; $c'rl' ...)."""
    out = []
    shell_vars = {}
    for idx, line in enumerate(text.split("\n"), 1):
        am = re.match(r"^\s*(?:export\s+)?([A-Za-z_]\w*)=(['\"]?)([^'\"$`;&|\s]*)\2\s*$", line)
        if am:
            shell_vars[am.group(1)] = am.group(3)
        elif shell_vars and "$" in line:
            expanded = re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: shell_vars.get(m.group(1), m.group(0)), line)
            expanded = re.sub(r"(?<=\w)['\"]{2}(?=\w)|(?<=\w)['\"](?=\w)", "", expanded)
            if expanded != line:
                out.append((idx, expanded, "shell variables"))
        for m in re.finditer(r"\b(?:echo|printf)\s+(?:-n\s+)?['\"]?([A-Za-z0-9+/=]{8,})['\"]?\s*\|\s*base64\s+(?:-d|--decode|-D)", line):
            dec = _decode_b64_text(m.group(1))
            if dec:
                out.append((idx, dec, "base64"))
        for m in re.finditer(r"\b(?:atob|Buffer\.from)\s*\(\s*['\"]([A-Za-z0-9+/=]{8,})['\"]", line):
            dec = _decode_b64_text(m.group(1))
            if dec:
                out.append((idx, dec, "base64"))
        for m in re.finditer(r"\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|ec|enc|encodedcommand)\s+([A-Za-z0-9+/=]{8,})", line, re.I):
            dec = _decode_b64_text(m.group(1), utf16=True)
            if dec:
                out.append((idx, dec, "a PowerShell encoded command"))
        for m in re.finditer(r"\bprintf\s+['\"]((?:\\x[0-9a-fA-F]{2}){4,})", line):
            try:
                out.append((idx, bytes.fromhex(m.group(1).replace("\\x", "")).decode("utf-8", "replace"), "escape sequences"))
            except ValueError:
                pass
        for m in re.finditer(r"String\.fromCharCode\s*\(\s*((?:\d+\s*,\s*){3,}\d+)\s*\)", line):
            ints = [int(x) for x in re.findall(r"\d+", m.group(1))]
            out.append((idx, "".join(chr(i) for i in ints if 0 <= i < 0x110000), "character codes"))
    return out


def _secret_strength(value: str):
    if STRONG_SECRET_RE.search(value) or value in STRONG_SECRET_SIGNATURES:
        return "strong"
    if CRED_FILE_RE.search(value):
        return "cred"
    return None


def _py_secret_in(node, parents, skip=None):
    """'strong', 'cred', 'env' or None for what an expression reads."""
    best = None
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if skip is not None and skip(sub):
                continue
            k = _secret_strength(sub.value)
            if k == "strong":
                return "strong"
            best = best or k
        elif dotted(sub) == "os.environ":
            par = parents.get(sub)
            if isinstance(par, ast.Subscript):
                continue
            if isinstance(par, ast.Attribute) and par.attr in ENV_SAFE_ATTRS:
                continue
            if isinstance(par, ast.Compare):
                continue
            best = "env" if best in (None, "cred") else best
    return best


SECRET_WORDS = {"strong": "a private key or secret store", "cred": "a credential file", "env": "the whole environment"}


def _py_skipper(fc):
    """A test for string constants that only describe a threat: detection patterns, messages, comments."""
    def skip(node):
        line = fc.lines[node.lineno - 1] if node.lineno - 1 < len(fc.lines) else ""
        col = _char_col(line, node.col_offset) + 1
        return fc.classify(node.lineno, col, line, "", "") in ("defensive", "hint", "comment", "fixture")
    return skip


def py_data_flow(audit, rel, text, tree, fc=None):
    """S022 for Python: a secret read whose value reaches a network call (light, single-file taint)."""
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    skip = _py_skipper(fc) if fc is not None else None
    tainted = {}

    def names_in(node):
        return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}

    def kind_of(node):
        ks = {_py_secret_in(node, parents, skip)} | {tainted.get(n) for n in names_in(node)}
        for k in ("strong", "env", "cred"):
            if k in ks:
                return k
        return None

    def targets_of(node):
        out = []
        if isinstance(node, ast.Assign):
            for t in node.targets:
                out += [n.id for n in ast.walk(t) if isinstance(n, ast.Name)]
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)) and node.value is not None:
            out += [n.id for n in ast.walk(node.target) if isinstance(n, ast.Name)]
        return out

    for _ in range(3):  # a few passes so flows through several assignments are followed
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and getattr(node, "value", None) is not None:
                k = kind_of(node.value)
                if k:
                    for t in targets_of(node):
                        tainted[t] = k if tainted.get(t) != "strong" else "strong"
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    k = kind_of(item.context_expr)
                    if k and item.optional_vars is not None:
                        for n in ast.walk(item.optional_vars):
                            if isinstance(n, ast.Name):
                                tainted[n.id] = k
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                k = kind_of(node.iter)
                if k:
                    for n in ast.walk(node.target):
                        if isinstance(n, ast.Name):
                            tainted[n.id] = k
    ctx = "fixture" if is_fixture_path(rel) else "executed"
    sources_seen = any(tainted.values())
    sinks = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node.func)
        last = node.func.attr if isinstance(node.func, ast.Attribute) else name
        root = name.split(".")[0] if name else ""
        if not (last in PY_SINK_LAST or name in ("urllib.request.urlopen", "urlopen")
                or (root in PY_NET_ROOTS and last in ("get", "post", "put", "patch", "delete", "request", "head", "options"))):
            continue
        if last in ("post", "put", "patch", "request", "send") and not root and not isinstance(node.func, ast.Attribute):
            continue
        sinks.append((node, name or last))
        payload = list(node.args) + [kw.value for kw in node.keywords]
        kinds = [kind_of(p) for p in payload]
        k = "strong" if "strong" in kinds else ("env" if "env" in kinds else ("cred" if "cred" in kinds else None))
        if k:
            sev = "error" if k == "cred" else "critical"
            audit.add("S022", "%s reaches %s() and leaves the machine" % (SECRET_WORDS[k], name or last), file=rel,
                      line=node.lineno, severity=sev, context=ctx)
            return
    if sources_seen and sinks and "strong" in tainted.values():
        node, nm = sinks[0]
        k = "strong"
        audit.add("S022", "reads %s and also sends data with %s(); check what is sent" % (SECRET_WORDS[k], nm), file=rel,
                  line=node.lineno, severity="error", context=ctx)


def text_data_flow(audit, rel, text, fc, same_line_only=False):
    """S022 for shell and JavaScript: a secret or the environment on the same line as a network send, or through a variable."""
    lines = text.split("\n")
    is_js = rel.lower().endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"))
    sink_re = JS_SINK_RE if is_js else SH_SINK_RE
    tainted = {}
    first_source = None
    sink_line = None
    for idx, line in enumerate(lines, 1):
        st = line.strip()
        if not st or st.startswith(("#", "//")):
            continue
        k = _secret_strength(line) or ("env" if (JS_ENV_RE.search(line) if is_js else SH_ENV_RE.search(line)) else None)
        m = SH_ASSIGN_RE.match(line) if not is_js else re.match(r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.*)$", line)
        if m and k:
            tainted[m.group(1)] = k
        used = [v for v in tainted if re.search(r"\$\{?" + re.escape(v) + r"\b" if not is_js else r"\b" + re.escape(v) + r"\b", line)
                and not (m and m.group(1) == v)]
        if sink_re.search(line):
            sink_line = sink_line or idx
            kk = k or (max((tainted[v] for v in used), key=lambda x: {"strong": 3, "env": 2, "cred": 1}[x]) if used else None)
            if kk:
                ctx = fc.classify(idx, 0, line, st[:20], "", "S022")
                sev = "error" if kk == "cred" else "critical"
                audit.add("S022", "%s is sent over the network on this line" % SECRET_WORDS[kk], file=rel, line=idx,
                          severity=sev, context=ctx)
                return
        if k in ("strong", "env") and first_source is None:
            first_source = (idx, k)
    if first_source and sink_line and not same_line_only:
        idx, k = first_source
        ctx = fc.classify(idx, 0, lines[idx - 1], lines[idx - 1].strip()[:20], "", "S022")
        audit.add("S022", "reads %s (line %d) and sends data over the network (line %d); check what is sent" % (SECRET_WORDS[k], idx, sink_line),
                  file=rel, line=idx, severity="error", context=ctx)


def md_instruction_risks(audit, rel, text, fc):
    """Instructions that ask the agent to disclose secrets (S022) or to obey text fetched at run time (S024)."""
    lines = text.split("\n")
    for idx, line in enumerate(lines, 1):
        if not line.strip():
            continue
        prev = "\n".join(lines[max(0, idx - 3):idx - 1])
        if SECRET_STORE_MD_RE.search(line) and DISCLOSE_MD_RE.search(line) and not DISCLOSE_OK_RE.search(line) \
                and not NEGATION_RE.search(line):
            ctx = fc.classify(idx, 0, line, line.strip()[:20], prev, "S022")
            audit.add("S022", "tells the agent to share secrets: " + line.strip()[:70], file=rel, line=idx, context=ctx)
        url = URL_IN_LINE_RE.search(line)
        if url and not NEGATION_RE.search(line):
            before, after = line[:url.start()], line[url.end():]
            fetch_then_follow = FETCH_VERB_RE.search(before) and FOLLOW_RE.search(after)
            follow_then_at = FOLLOW_RE.search(before) and re.search(r"\b(?:at|from|in)\s*[`<(\[]*\s*$", before)
            if fetch_then_follow or follow_then_at:
                strong = REMOTE_RAW_HOST_RE.search(url.group(0)) or REMOTE_ALWAYS_RE.search(line)
                ctx = fc.classify(idx, url.start(), line, url.group(0), prev, "S024")
                audit.add("S024", "follows instructions fetched from " + url.group(0)[:60], file=rel, line=idx,
                          severity="error" if strong else None, context=ctx)


def scan_file_risks(audit, rel, text, kind):
    """Checks that need the whole file: data flows (S022), hidden strings (S004), agent tampering with a write (S026)."""
    low = rel.lower()
    fc = FileContext(rel, text, kind)
    if kind == "md":
        md_instruction_risks(audit, rel, text, fc)
        text_data_flow(audit, rel, text, fc, same_line_only=True)
        return
    if kind != "code":
        return
    ctx_default = "fixture" if is_fixture_path(rel) else "executed"
    hidden = []
    if low.endswith(".py"):
        tree = parse_py(text)
        if tree is not None:
            py_data_flow(audit, rel, text, tree, fc)
            skip = _py_skipper(fc)
            hidden = [h for h in _hidden_strings_py(tree, text, skip)]
            # a socket wired to a shell, spread over several lines
            names = {dotted(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
            lasts = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
            downloads = any(n.endswith("urlretrieve") for n in names) or (
                ({"requests.get", "httpx.get", "urlopen", "urllib.request.urlopen"} & names) and ("write" in lasts or "write_bytes" in lasts))
            makes_exec = any(n in ("os.chmod",) for n in names) or "chmod" in lasts
            runs = any(n.startswith("subprocess.") or n in ("os.system", "os.execv", "os.execl", "os.startfile") for n in names)
            if downloads and makes_exec and runs:
                line_no = next((n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call) and (dotted(n.func) == "os.chmod"
                                or (isinstance(n.func, ast.Attribute) and n.func.attr == "chmod"))), None)
                audit.add("S003", "downloads a file, makes it executable and runs it", file=rel, line=line_no, context=ctx_default)
            if any(n.endswith("connect") for n in names) and ("os.dup2" in names or "pty.spawn" in names) \
                    and any(n.startswith("subprocess.") or n in ("os.system", "pty.spawn", "os.execv", "os.execl") for n in names):
                line_no = next((n.lineno for n in ast.walk(tree) if isinstance(n, ast.Call) and dotted(n.func) in ("os.dup2", "pty.spawn")), None)
                audit.add("S023", "a network socket is wired to a shell (dup2 or pty.spawn)", file=rel, line=line_no, context=ctx_default)
    else:
        text_data_flow(audit, rel, text, fc)
        hidden = _hidden_strings_text(text)
        dl = re.search(r"(?m)^[^#\n]*\b(?:curl|wget)\b[^\n]*(?:\s-o\s*\S|\s-O\b|--output\b|-OutFile\b)", text) or \
            re.search(r"(?m)^[^#\n]*\bInvoke-WebRequest\b[^\n]*-OutFile\b", text)
        mk = re.search(r"(?m)^[^#\n]*\bchmod\s+(?:[ugoa]*\+x|[0-7]?[0-7][1357][0-7]?)\b", text)
        if dl and mk and not re.search(r"\b(?:sha256sum|shasum|Get-FileHash|gpg\s+--verify|cosign\s+verify|minisign)\b", text):
            ln = text.count("\n", 0, mk.start()) + 1
            ctx = fc.classify(ln, 0, text.split("\n")[ln - 1], "chmod", "", "S003")
            audit.add("S003", "downloads a file and makes it executable without checking a checksum", file=rel, line=ln, context=ctx)
    seen = set()
    for line_no, decoded, how in hidden:
        hit = _danger_in(decoded)
        if not hit or (line_no, how) in seen:
            continue
        seen.add((line_no, how))
        code, label, snippet, sev = hit
        audit.add("S004", "hidden with %s, decodes to %s: %s" % (how, label, snippet), file=rel, line=line_no,
                  severity="critical" if sev == "critical" else "error", context=ctx_default)
    # S026: the agent's own settings named in code that also writes files
    if re.search(r"\.claud[e]/settings(?:\.local)?\.json|\.claud[e]\.json|\.claud[e]/CLAUDE\.md|\.claud[e]/(?:skills|agents|commands|hooks)/", text):
        if re.search(r"open\([^)]*,\s*['\"][wa]|\.write_text\(|\.write\(|json\.dump\(|>>?\s*['\"]?[~$/.]|\btee\b|\bsed\s+-i\b|writeFileSync|appendFileSync", text):
            for f in audit.findings:
                if f.code == "S026" and f.file == rel and f.severity == "warn" and f.context in (None, "executed"):
                    f.severity = "error"
                    f.message += " (the file also writes files)"


def scan_unicode(audit: Audit, rel: str, text: str):
    body = text[1:] if text.startswith("\ufeff") else text
    fixture = is_fixture_path(rel)
    ctx = "fixture" if fixture else None
    for idx, line in enumerate(body.split("\n"), 1):
        m = UNI_TAG_RE.search(line)
        if m:
            audit.add("S002", "Unicode tag characters (U+%04X) hide text inside this line" % ord(m.group(0)), file=rel, line=idx,
                      severity="info" if fixture else None, context=ctx)
            continue
        m = UNI_BIDI_RE.search(line)
        if m:
            audit.add("S002", "bidirectional control character U+%04X reorders how the line is displayed" % ord(m.group(0)), file=rel, line=idx,
                      severity="info" if fixture else None, context=ctx)
            continue
        m = UNI_ZW_RE.search(line)
        if m:
            audit.add("S002", "zero-width character U+%04X is invisible to reviewers" % ord(m.group(0)), file=rel, line=idx,
                      severity="info" if fixture else "error", context=ctx)


def scan_html_comments(audit: Audit, rel: str, text: str):
    for m in COMMENT_RE.finditer(text):
        inner = m.group(1).strip()
        if len(inner) >= 200 or (len(inner) >= 20 and COMMENT_SUSPECT_RE.search(inner)):
            line = text.count("\n", 0, m.start()) + 1
            if is_fixture_path(rel):
                where = "fixture"
            else:
                low = rel.lower().split("/")
                where = "agent-instr" if (low[-1] == "skill.md" or any(x in ("agents", "commands") for x in low[:-1])) else "documented"
            audit.add("S012", "comment of %d characters: %s" % (len(inner), inner[:50].replace("\n", " ") + "..."),
                      file=rel, line=line, context=where)


def check_name(audit: Audit, name: str, skill_dir: Path, line):
    problems = []
    if name != name.lower():
        problems.append("has uppercase letters")
    if " " in name:
        problems.append("has spaces")
    if "_" in name:
        problems.append("has underscores")
    if name.startswith("-") or name.endswith("-"):
        problems.append("starts or ends with a hyphen")
    if "--" in name:
        problems.append("has consecutive hyphens")
    if not re.fullmatch(r"[^\W_]+(?:-[^\W_]+)*", name.lower()) and not problems:
        problems.append("has characters other than letters, numbers and hyphens")
    elif re.search(r"[^\w-]", name) and "has characters other than letters, numbers and hyphens" not in problems:
        problems.append("has characters other than letters, numbers and hyphens")
    if problems:
        audit.add("V005", "name '%s' %s" % (name, "; ".join(problems)), file="SKILL.md", line=line)
    if len(name) > NAME_MAX:
        audit.add("V006", "name is %d characters (max %d)" % (len(name), NAME_MAX), file="SKILL.md", line=line)
    if skill_dir.name != name and skill_dir.name not in ("", "."):
        audit.add("V007", "name is '%s' but the folder is '%s'" % (name, skill_dir.name), file="SKILL.md", line=line)
    low = name.lower()
    if low.startswith("claude-") or low.startswith("anthropic-") or low in ("claude", "anthropic"):
        audit.add("V009", "name '%s' starts with a reserved prefix" % name, file="SKILL.md", line=line)
    if low in GENERIC_NAMES:
        audit.add("T006", "name '%s' says nothing about what the skill does" % name, file="SKILL.md", line=line)


def check_description(audit: Audit, name: str, desc: str, line):
    n = len(desc)
    words = re.findall(r"\w+", desc)
    if n > DESC_MAX:
        audit.add("V008", "description is %d characters (max %d)" % (n, DESC_MAX), file="SKILL.md", line=line)
    if n < DESC_MIN or len(words) < 8:
        audit.add("T001", "description has %d characters and %d words" % (n, len(words)), file="SKILL.md", line=line)
    cue = CUE_RE.search(desc)
    if not cue:
        audit.add("T002", "no 'Use when' style clause found", file="SKILL.md", line=line)
    elif cue.start() > DESC_FRONT_LOAD:
        audit.add("T003", "first when-to-use cue starts at character %d" % cue.start(), file="SKILL.md", line=line)
    lowered = set(w.lower() for w in words)
    if len(lowered & EN_STOP) >= 2:
        if FIRST_PERSON_CS_RE.search(desc) or FIRST_PERSON_CI_RE.search(desc):
            audit.add("T004", "first or second person wording in the description", file="SKILL.md", line=line)
    if VAGUE_START_RE.search(desc):
        audit.add("T005", "vague opening: " + desc[:50], file="SKILL.md", line=line)
    if n > DESC_FRONT_LOAD:
        audit.add("T007", "description is %d characters" % n, file="SKILL.md", line=line)
    name_words = set(re.findall(r"\w+", name.lower().replace("-", " ")))
    desc_words = set(w.lower() for w in words)
    if desc_words and desc_words <= (name_words | EN_STOP | {"a", "an", "of", "to", "skill"}):
        audit.add("T008", "description adds nothing beyond the name", file="SKILL.md", line=line)
    if n >= 120 and not re.search(r"[\"'\u201c\u201d]|\.[A-Za-z0-9]{2,5}\b|/[a-z][\w-]+", desc):
        audit.add("T009", "no quoted phrases, file extensions or slash commands", file="SKILL.md", line=line)
    if n > DESC_LONG and n <= DESC_MAX:
        audit.add("T010", "description is %d of %d characters" % (n, DESC_MAX), file="SKILL.md", line=line)
    if XML_TAG_RE.search(desc):
        audit.add("T012", "tag-like text found: " + XML_TAG_RE.search(desc).group(0)[:30], file="SKILL.md", line=line)
    if re.search(r"(?m)^\s*(?:#{1,6}\s|[-*]\s)", desc):
        audit.add("T014", "headings or bullets inside the description", file="SKILL.md", line=line)


REF_EXAMPLE_RE = re.compile(r"\b(?:e\.g\.|for\s+example|for\s+instance|such\s+as|i\.e\.|like)\b|\bexamples?\b\W{0,4}(?::|\()", re.I)
REF_PLACEHOLDER_STEMS = {"tool", "foo", "bar", "baz", "example", "examples", "sample", "something", "xxx", "placeholder", "dummy",
                         "my_script", "my-script", "myscript", "your_script", "your-script", "script_name", "name", "file", "filename"}
REF_WRITE_RE = re.compile(r"(?:>>?\s*|\s-o\s+|--output[= ]\s*|\b(?:save|write|writes|create|creates|generate|generates|output|outputs|"
                          r"export|exports)\b[^\n`]{0,30}\b(?:to|as|into|in)\s+)[`'\"]?\.?/?$", re.I)
REF_USE_RE = re.compile(r"(?:\b(?:python[0-9.]*|bash|sh|zsh|node|deno|bun|ruby|perl|pwsh|powershell|uv\s+run|npx|tsx)\s+[`'\"]?\.?/?$)|"
                        r"\b(?:read|see|load|open|consult|follow|refer\s+to|check|run|execute|use|import|source)\b", re.I)


def missing_ref_severity(target: str, meta: dict, skill_dir: Path):
    """How sure we are that a missing path is a real broken reference: (severity, note)."""
    if meta.get("link"):
        return "error", ""
    line = meta.get("text", "")
    col = meta.get("col", 0)
    before = line[:col]
    stem = os.path.splitext(os.path.basename(target))[0].lower()
    if stem in REF_PLACEHOLDER_STEMS or REF_EXAMPLE_RE.search(before):
        return "info", " (looks like an example)"
    if REF_WRITE_RE.search(before):
        return "info", " (looks like a file the skill creates, not one it ships)"
    try:
        for sib in sorted(skill_dir.parent.iterdir()):
            if sib != skill_dir and sib.is_dir() and (sib / target).is_file():
                return "warn", " (it exists in the sibling skill '%s', so it is missing when this skill is installed alone)" % sib.name
    except OSError:
        pass
    if REF_USE_RE.search(re.split(r"[.!?]\s", before)[-1]):
        return "error", ""
    return "warn", " (mentioned as a path, not linked)"


def extract_refs(body_lines, first_line_no, meta=None):
    """Return {relative_path: first_line_number} for files that SKILL.md points to.

    When `meta` is a dict it is filled with {path: {"link": bool, "text": line, "col": column}}."""
    refs = {}
    backslash = []
    in_fence = False
    for offset, line in enumerate(body_lines):
        lineno = first_line_no + offset
        st = line.strip()
        if st.startswith("```") or st.startswith("~~~"):
            in_fence = not in_fence
        code_spans = [(cm.start(), cm.end()) for cm in re.finditer(r"`[^`\n]*`", line)]
        for m in ([] if in_fence else LINK_RE.finditer(line)):
            target = m.group(1)
            if re.match(r"^(?:[a-z][a-z0-9+.-]*:|/|#)", target, re.I):
                continue
            if is_placeholder_target(target) or any(a <= m.start() and m.end() <= b for a, b in code_spans):
                continue
            key = target[2:] if target.startswith("./") else target
            if key not in refs and meta is not None:
                meta[key] = {"link": True, "text": line, "col": m.start()}
            refs.setdefault(key, lineno)
        for m in BARE_PATH_RE.finditer(line):
            target = m.group(1).rstrip(".,;:)")
            if any(ch in target for ch in "*{<$"):
                continue
            if target not in refs and meta is not None:
                meta[target] = {"link": False, "text": line, "col": m.start()}
            refs.setdefault(target, lineno)
        if BACKSLASH_PATH_RE.search(line):
            backslash.append(lineno)
    return refs, backslash


def files_used_by(start, existing, candidates):
    """Bundled files reached from `start` through imports, source/require calls or a plain mention of their name."""
    seen = set(start)
    todo = [r for r in start if r in existing]
    cand_by_base = {}
    dirs = {}
    for c in candidates:
        cand_by_base.setdefault(os.path.basename(c).lower(), []).append(c)
        d = os.path.dirname(c)
        while d:
            dirs.setdefault(os.path.basename(d), set()).add(d)
            d = os.path.dirname(d)
    while todo:
        rel = todo.pop()
        if not rel.lower().endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".ps1", ".md", ".txt", ".html", ".json")):
            continue
        txt, _, _ = read_text_file(existing[rel])
        if not txt:
            continue
        folder = os.path.dirname(rel)
        found = set()
        if rel.endswith(".py"):
            for m in re.finditer(r"(?m)^\s*(?:from\s+(\.*)([\w.]*)\s+import\s+([\w, ()*]+)|import\s+([\w.]+))", txt):
                dots, mod, names, plain = m.group(1) or "", m.group(2) or "", m.group(3) or "", m.group(4) or ""
                mods = [plain] if plain else [mod] + ([mod + "." + n.strip() if mod else n.strip()
                                                       for n in re.split(r"[,()\s]+", names) if n.strip() and n.strip() != "*"])
                bases = [folder]
                if dots:
                    up = folder
                    for _ in range(len(dots) - 1):
                        up = os.path.dirname(up)
                    bases = [up]
                else:
                    d = folder
                    while d:
                        d = os.path.dirname(d)
                        bases.append(d)
                for md in mods:
                    if not md:
                        continue
                    sub_path = md.replace(".", "/")
                    for b in bases:
                        for c in (sub_path + ".py", sub_path + "/__init__.py"):
                            path = (b + "/" if b else "") + c
                            if path in candidates:
                                found.add(path)
                                # the package's __init__.py files on the way are used too
                                pd = os.path.dirname(path)
                                while pd and pd != b:
                                    init = pd + "/__init__.py"
                                    if init in candidates:
                                        found.add(init)
                                    pd = os.path.dirname(pd)
        for m in re.finditer(r"(?<![\w-])([\w.-]+\.(?:py|js|mjs|cjs|ts|sh|ps1|md|txt|html|css|json|ya?ml|xml|xsd|ttf|otf|woff2?|png|jpe?g|svg|gif|docx|pptx|xlsx|pdf|csv|j2|jinja|template|tmpl))\b", txt):
            for c in cand_by_base.get(m.group(1).lower(), []):
                found.add(c)
        for m in re.finditer(r"""(?:require\(|from\s+|import\s+)['"](\.{1,2}/[^'"]+)['"]""", txt):
            target = os.path.normpath(os.path.join(folder, m.group(1))).replace("\\", "/")
            for ext in ("", ".js", ".mjs", ".cjs", ".ts", "/index.js", "/index.ts"):
                if target + ext in candidates:
                    found.add(target + ext)
        # a folder a script opens by name (Path(__file__).parent / "schemas") covers the files inside it
        for name, full in dirs.items():
            if len(name) >= 3 and re.search(r"""['"/\\]""" + re.escape(name) + r"""['"/\\]""", txt):
                for d in full:
                    prefix = d + "/"
                    found.update(c for c in candidates if c.startswith(prefix))
        for f in found - seen:
            seen.add(f)
            todo.append(f)
    return seen - set(start)


def find_license(skill_dir: Path) -> bool:
    cur = skill_dir.resolve()
    for _ in range(3):
        try:
            for entry in cur.iterdir():
                if re.match(r"^(?:LICEN[SC]E|COPYING)(?:[._-].*)?$", entry.name, re.I):
                    return True
        except OSError:
            return False
        if cur.parent == cur:
            break
        cur = cur.parent
    return False


def audit_skill(skill_dir: Path, skill_md: Path, ignore: set, only=None) -> SkillReport:
    a = Audit(skill_dir, ignore)
    stats = a.stats
    skill_dir = skill_dir.resolve()
    rel_md = skill_md.name

    # ---- read SKILL.md ----
    raw = skill_md.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        a.add("V020", "file is not valid UTF-8", file=rel_md)
        text = raw.decode("utf-8", errors="replace")
    if text.startswith("\ufeff"):
        a.add("H009", "BOM at the start of the file", file=rel_md)
        text = text[1:]
    if "\r\n" in text:
        a.add("H008", "CRLF line endings", file=rel_md)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if skill_md.name != "SKILL.md":
        a.add("V001", "found '%s'" % skill_md.name, file=skill_md.name)

    total_lines = len(text.rstrip("\n").split("\n")) if text.strip() else 0
    fm_lines, body_lines, body_start = split_frontmatter(text)
    fields, name, desc = {}, "", ""
    name_line = desc_line = None
    if fm_lines is None or fm_lines == "unterminated":
        a.add("V002", "no opening frontmatter" if fm_lines is None else "frontmatter is never closed",
              file=rel_md, line=1)
        body_lines = text.split("\n")
        body_start = 1
    else:
        fields, issues = parse_frontmatter(fm_lines)
        for code, msg, ln in issues:
            a.add(code, msg, file=rel_md, line=ln)
        nf = fields.get("name")
        if not nf or not nf.value.strip():
            a.add("V003", "no name in the frontmatter", file=rel_md, line=1)
        else:
            name, name_line = nf.value.strip(), nf.line
            check_name(a, name, skill_dir, name_line)
        df = fields.get("description")
        if not df or (not df.value.strip() and not df.children):
            a.add("V004", "no description in the frontmatter", file=rel_md, line=1)
        elif df.style in ("map", "list"):
            a.add("V023", "description is a %s" % df.style, file=rel_md, line=df.line)
        else:
            desc, desc_line = df.value.strip(), df.line
            check_description(a, name, desc, desc_line)
        for key, f in fields.items():
            if key not in SPEC_KEYS and key not in EXTENSION_KEYS:
                a.add("V013", "key '%s' is not in the open spec" % key, file=rel_md, line=f.line)
        cf = fields.get("compatibility")
        if cf and len(cf.value) > COMPAT_MAX:
            a.add("V014", "compatibility is %d characters" % len(cf.value), file=rel_md, line=cf.line)
        tf = fields.get("allowed-tools")
        if tf:
            toks = [t for t in re.split(r"[\s,]+", tf.value) if t]
            for t in toks:
                if t == "Bash" or re.match(r"^Bash\(\s*\*?:?\*?\s*\)$", t) or t == "*":
                    a.add("S013", "allowed-tools contains '%s'" % t, file=rel_md, line=tf.line)
                    break

    body_text = "\n".join(body_lines or [])
    if not body_text.strip():
        a.add("V016", "nothing after the frontmatter", file=rel_md)

    # ---- body analysis ----
    in_fence = False
    code_lines = 0
    long_line = None
    counts = {}
    has_heading = False
    for off, ln in enumerate(body_lines or []):
        stripped = ln.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            code_lines += 1
        elif stripped.startswith("#"):
            has_heading = True
        if len(ln) > 2000 and long_line is None:
            long_line = (body_start or 1) + off
        if len(stripped) >= 40:
            counts[stripped] = counts.get(stripped, 0) + 1
    body_tokens = est_tokens(body_text)
    if total_lines > BODY_LINES_HARD:
        a.add("W001", "%d lines (recommended under %d)" % (total_lines, BODY_LINES_RECOMMENDED), file=rel_md, severity="error")
    elif total_lines > BODY_LINES_RECOMMENDED:
        a.add("W001", "%d lines (recommended under %d)" % (total_lines, BODY_LINES_RECOMMENDED), file=rel_md)
    if body_tokens > BODY_TOKENS_HARD:
        a.add("W002", "about %d tokens (recommended under %d)" % (body_tokens, BODY_TOKENS_RECOMMENDED), file=rel_md, severity="error")
    elif body_tokens > BODY_TOKENS_RECOMMENDED:
        a.add("W002", "about %d tokens (recommended under %d)" % (body_tokens, BODY_TOKENS_RECOMMENDED), file=rel_md)
    if code_lines > 150:
        a.add("W007", "%d lines of inline code" % code_lines, file=rel_md)
    if long_line:
        a.add("W008", "a line is longer than 2000 characters", file=rel_md, line=long_line)
    repeated = [s for s, c in counts.items() if c >= 3]
    if repeated:
        a.add("W009", "%d line(s) appear three or more times, e.g. '%s'" % (len(repeated), repeated[0][:50]), file=rel_md)
    if body_text.strip():
        if not has_heading:
            a.add("H007", "no heading lines", file=rel_md)
        if not re.search(r"(?i)\b(?:examples?|exemplos?|ejemplos?|exemples?)\b|```", body_text):
            a.add("H006", "no example or code block", file=rel_md)
    for off, ln in enumerate(body_lines or []):
        if PLACEHOLDER_CS_RE.search(ln) or PLACEHOLDER_RE.search(ln):
            a.add("H003", "placeholder text: " + ln.strip()[:60], file=rel_md, line=(body_start or 1) + off)
            break

    ref_meta = {}
    refs, backslash_lines = extract_refs(body_lines or [], body_start or 1, ref_meta)
    for ln in backslash_lines:
        a.add("V018", "backslash in a bundled-file path", file=rel_md, line=ln)

    # ---- security scan of SKILL.md ----
    scan_unicode(a, rel_md, text)
    scan_lines(a, rel_md, text, "md")
    scan_html_comments(a, rel_md, text)
    scan_file_risks(a, rel_md, text, "md")
    if desc_line:
        # text in the description is loaded into every conversation, before the skill is even chosen
        later = [f.line for k, f in fields.items() if getattr(f, "line", None) and f.line > desc_line] if fields else []
        desc_end = min(later) - 1 if later else (body_start or desc_line + 1) - 1
        for f in a.findings:
            if f.file == rel_md and f.line and desc_line <= f.line <= desc_end and f.code in DESCRIPTION_CRITICAL \
                    and f.severity in ("warn", "error"):
                f.severity = "critical"
                f.message += " (in the description, which loads into every conversation)"

    # ---- walk the folder ----
    files, junk, symlink_dirs = collect_files(skill_dir)
    for j in junk:
        a.add("H001", "folder " + j + "/", file=j)
    for sd in symlink_dirs:
        try:
            target = sd.resolve()
            if skill_dir not in target.parents and target != skill_dir:
                a.add("S018", "folder link %s points to %s" % (sd.relative_to(skill_dir).as_posix(), target), file=sd.relative_to(skill_dir).as_posix())
        except OSError:
            pass
    total_bytes = 0
    ref_set = set()
    for r in refs:
        ref_set.add(os.path.normpath(r).replace("\\", "/"))
    existing = {}
    bundled = []
    for p in files:
        rel = p.relative_to(skill_dir).as_posix()
        existing[rel] = p
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        total_bytes += size
        lowname = p.name.lower()
        if lowname in JUNK_FILES or lowname.endswith(JUNK_SUFFIX):
            a.add("H001", "file " + rel, file=rel)
            continue
        if SECRET_FILE_RE.match(p.name):
            a.add("H002", "file " + rel, file=rel)
        if p.is_symlink():
            try:
                target = p.resolve()
                if skill_dir not in target.parents and target != skill_dir:
                    a.add("S018", "%s points to %s" % (rel, target), file=rel)
            except OSError:
                pass
            continue
        if size > HUGE_FILE_BYTES:
            a.add("W005", "%s is %.1f MB" % (rel, size / 1e6), file=rel, severity="error")
            continue
        if size > BIG_FILE_BYTES:
            a.add("W005", "%s is %.1f MB" % (rel, size / 1e6), file=rel)
        if rel == skill_md.name:
            continue
        if not rel.startswith(".") and "/." not in rel and not re.match(r"^(?:LICEN[SC]E|COPYING|NOTICE)", p.name, re.I):
            bundled.append(rel)
        txt, _, ok = read_text_file(p)
        if txt is None:
            continue
        if txt.startswith("\ufeff"):
            txt = txt[1:]
        kind = classify(rel, txt)
        scan_unicode(a, rel, txt)
        scan_lines(a, rel, txt, kind)
        scan_file_risks(a, rel, txt, kind)
        if kind == "md":
            scan_html_comments(a, rel, txt)
            lines_n = txt.count("\n") + 1
            if lines_n > 100 and not re.search(r"(?m)^#{1,6}\s", txt) \
                    and not re.match(r"^(?:LICEN[SC]E|COPYING|NOTICE|.*OFL)", p.name, re.I):
                a.add("W004", "%s has %d lines and no headings" % (rel, lines_n), file=rel)
        if rel.lower().endswith(".py"):
            scan_python(a, rel, txt)
        if rel.lower().endswith(".json"):
            try:
                json.loads(txt)
            except ValueError as e:
                a.add("V022", rel + ": " + str(e)[:80], file=rel)
    if len(files) > 50:
        a.add("W006", "%d files" % len(files))

    # ---- check refs exist, reference depth, orphans ----
    for r, ln in refs.items():
        norm = os.path.normpath(r).replace("\\", "/")
        if norm.startswith("../"):
            continue
        if norm not in existing and not (skill_dir / norm).exists():
            sev, note = missing_ref_severity(norm, ref_meta.get(r, {}), skill_dir)
            a.add("V017", "'%s' does not exist in the skill folder%s" % (r, note), file=rel_md, line=ln, severity=sev)
    reachable = set(n for n in ref_set if n in existing)
    nested = []
    for r in sorted(reachable):
        if not r.lower().endswith((".md", ".markdown", ".txt")):
            continue
        txt, _, _ = read_text_file(existing[r])
        if txt is None:
            continue
        for m in list(LINK_RE.finditer(txt)):
            t = m.group(1)
            if re.match(r"^(?:[a-z][a-z0-9+.-]*:|/|#)", t, re.I):
                continue
            tn = os.path.normpath(os.path.join(os.path.dirname(r), t)).replace("\\", "/")
            if tn in existing and tn != r and tn != rel_md:
                reachable.add(tn)
                nested.append((r, tn))
    if nested:
        a.add("V019", "%s links to %s" % nested[0], file=nested[0][0])
    body_lower = body_text.lower()
    mentioned = set(reachable)
    dir_hit = {}
    for b in bundled:
        base = os.path.basename(b)
        parent = os.path.dirname(b)
        if base.lower() in body_lower or (parent and (parent.lower() + "/") in body_lower):
            mentioned.add(b)
            continue
        # a folder named on its own ("Search the `./canvas-fonts` directory") covers everything inside it
        d = parent
        while d:
            if d not in dir_hit:
                dir_hit[d] = bool(re.search(r"(?<![\w/.-])(?:\./)?" + re.escape(d.lower()) + r"/?(?![\w./-])", body_lower))
            if dir_hit[d]:
                mentioned.add(b)
                break
            d = os.path.dirname(d)
    mentioned |= files_used_by(mentioned, existing, set(bundled))
    unmentioned = [b for b in bundled if b not in mentioned]
    by_dir = {}
    for b in unmentioned:
        by_dir.setdefault(os.path.dirname(b), []).append(b)
    for d, items in sorted(by_dir.items()):
        if d and len(items) >= 4:
            sample = ", ".join(os.path.basename(x) for x in items[:3])
            a.add("H005", "'%s/' holds %d files that SKILL.md never mentions (e.g. %s)" % (d, len(items), sample), file=d + "/")
        else:
            for b in items:
                a.add("H005", "'%s' is not mentioned in SKILL.md" % b, file=b)

    # ---- license ----
    has_license = ("license" in fields) or find_license(skill_dir)
    if not has_license:
        a.add("H004", "no LICENSE file near the skill and no license field")

    # ---- stats ----
    menu_text = (name + ": " + desc) if (name or desc) else ""
    stats_out = {
        "lines": total_lines,
        "body_tokens_est": body_tokens,
        "menu_tokens_est": est_tokens(menu_text),
        "description_chars": len(desc),
        "files": len(files),
        "bytes": total_bytes,
        "capabilities": sorted(stats["capabilities"]),
        "hosts_in_scripts": sorted(stats["hosts_in_scripts"]),
        "hosts_in_docs": sorted(stats["hosts_in_docs"]),
    }
    if stats["capabilities"]:
        a.add("S019", "scripts can use: " + ", ".join(sorted(stats["capabilities"])))
    findings = dedup_findings(a.findings)
    if only:
        findings = [f for f in findings if f.category in only]
    cat_order = {k: i for i, k in enumerate(CATEGORIES)}
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], cat_order.get(f.category, 99), f.code, f.file or "", f.line or 0))
    cats, score, cap_value, cap_reason = score_findings(findings, only)
    display = name or skill_dir.name
    return SkillReport(name=display, path=str(skill_dir), findings=findings, stats=stats_out,
                       categories=cats, score=score, grade=grade_for(score),
                       verdict=verdict_for(score, cap_reason, security_notes(findings)), cap_value=cap_value, cap_reason=cap_reason,
                       description=desc)


def score_findings(findings, only=None):
    cats = {}
    total_max = total_got = 0
    for key, (label, mx) in CATEGORIES.items():
        if only and key not in only:
            continue
        by_code = {}
        for f in findings:
            if f.category == key and SEVERITY_PENALTY[f.severity] > 0:
                by_code.setdefault((f.code, f.severity), []).append(f)
        penalty = 0
        for (code, sev), items in by_code.items():
            base = SEVERITY_PENALTY[sev]
            # Each distinct finding counts once; identical repeats add a small, capped extra weight.
            weight = sum(1.0 + min(DUP_CAP, DUP_STEP * (max(1, it.count) - 1)) for it in items)
            penalty += int(math.ceil(base * min(1 + 0.5 * (weight - 1), 2.0)))
        got = max(0, mx - penalty)
        cats[key] = {"label": label, "score": got, "max": mx}
        total_max += mx
        total_got += got
    score = int(round(100.0 * total_got / total_max)) if total_max else 100
    cap_value = cap_reason = None
    sec = cats.get("security")
    if any(f.severity == "critical" for f in findings):
        cap_value, cap_reason = CRITICAL_CAP, "critical"
    elif any(f.category == "security" and f.severity == "error" for f in findings):
        cap_value, cap_reason = SECURITY_ERROR_CAP, "security-error"
    elif sec and sec["score"] * 2 < sec["max"]:
        cap_value, cap_reason = SECURITY_LOW_CAP, "security-low"
    if cap_value is not None:
        if score > cap_value:
            score = cap_value
        else:
            cap_value = cap_reason = None  # the cap did not change anything
    return cats, score, cap_value, cap_reason


def grade_for(score: int) -> str:
    for cut, g in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= cut:
            return g
    return "F"


def security_notes(findings) -> bool:
    """True when a security finding still costs points (so the skill is not a clean bill of health)."""
    return any((f.category == "security" or f.code.startswith(("S", "P00"))) and f.severity in ("warn", "error", "critical")
               for f in findings)


def verdict_for(score: int, cap_reason, security_notes: bool = False) -> str:
    if cap_reason == "critical":
        return "Quarantine: review before installing"
    if cap_reason in ("security-error", "security-low"):
        return "Security review needed"
    if security_notes and score >= 85:
        return "Healthy, read the security notes"
    if score >= 95:
        return "Picture of health"
    if score >= 85:
        return "Healthy, minor notes"
    if score >= 70:
        return "Needs a checkup"
    if score >= 55:
        return "Sick, treat soon"
    return "Needs the ER"


# --------------------------------------------------------------------------
# Discovery and collection-level checks
# --------------------------------------------------------------------------

def find_skill_md(d: Path):
    try:
        entries = list(d.iterdir())
    except OSError:
        return None
    exact = [e for e in entries if e.name == "SKILL.md" and e.is_file()]
    if exact:
        return exact[0]
    loose = [e for e in entries if e.name.lower() == "skill.md" and e.is_file()]
    return loose[0] if loose else None


def discover(paths, max_depth=5):
    found = []
    seen = set()

    def add(d, md):
        key = str(d.resolve())
        if key not in seen:
            seen.add(key)
            found.append((d, md))

    for raw in paths:
        p = Path(raw)
        if p.is_file() and p.name.lower() == "skill.md":
            add(p.parent if str(p.parent) else Path("."), p)
            continue
        if not p.is_dir():
            continue
        md = find_skill_md(p)
        if md:
            add(p, md)
            continue
        base_depth = len(p.resolve().parts)
        for root, dirs, _ in os.walk(str(p)):
            rp = Path(root)
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
            if len(rp.resolve().parts) - base_depth > max_depth:
                dirs[:] = []
                continue
            md = find_skill_md(rp)
            if md:
                add(rp, md)
                dirs[:] = []
    return found


def keyword_set(desc: str):
    words = re.findall(r"[^\W\d_]{4,}", desc.lower())
    return set(w for w in words if w not in OVERLAP_STOP)


def collection_checks(reports, ignore):
    out = []

    def add(code, message):
        if code in ignore:
            return
        r = RULES[code]
        out.append(Finding(code, r.category, r.severity, message, r.fix))

    if len(reports) < 2:
        return out
    seen_names = {}
    for r in reports:
        seen_names.setdefault(r.name, []).append(r.path)
    for n, paths in seen_names.items():
        if len(paths) > 1:
            add("H010", "name '%s' is used by %d skills: %s" % (n, len(paths), ", ".join(paths)))
    sets = [(r, keyword_set(r.description)) for r in reports]
    # Overlapping pairs are joined into groups, so 800 near-identical skills give one finding, not 300,000.
    parent = list(range(len(sets)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    pair_info = {}
    for i in range(len(sets)):
        a = sets[i][1]
        if len(a) < 6:
            continue
        for j in range(i + 1, len(sets)):
            b = sets[j][1]
            if len(b) < 6:
                continue
            jac = len(a & b) / float(len(a | b))
            if jac >= OVERLAP_THRESHOLD:
                pair_info[(i, j)] = jac
                parent[find(j)] = find(i)
    groups = {}
    for (i, j) in pair_info:
        root = find(i)
        groups.setdefault(root, set()).update((i, j))
    for members in sorted(groups.values(), key=lambda m: -len(m)):
        idx = sorted(members)
        if len(idx) == 2:
            i, j = idx
            a, b = sets[i][1], sets[j][1]
            add("T011", "'%s' and '%s' overlap %d%% in vocabulary (shared: %s)" % (
                sets[i][0].name, sets[j][0].name, int(round(pair_info[(i, j)] * 100)), ", ".join(sorted(a & b)[:6])))
            continue
        counts = {}
        for i in idx:
            for w in sets[i][1]:
                counts[w] = counts.get(w, 0) + 1
        common = [w for w, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])) if c >= 0.6 * len(idx)][:6]
        names = [sets[i][0].name for i in idx]
        shown = ", ".join("'%s'" % n for n in names[:8]) + (" and %d more" % (len(names) - 8) if len(names) > 8 else "")
        add("T011", "%d skills describe themselves with mostly the same words (shared: %s): %s" % (
            len(idx), ", ".join(common) or "many words", shown))
    total = sum(r.stats["menu_tokens_est"] for r in reports)
    if total > LISTING_BUDGET_TOKENS:
        add("C001", "%d skills add up to about %d tokens of descriptions (estimate; budget about %d on a 200K window)" % (
            len(reports), total, LISTING_BUDGET_TOKENS))
    return out


# --------------------------------------------------------------------------
# Plugin mode (--plugin): what a plugin would install, beyond its skills
# --------------------------------------------------------------------------
# Everything here only reads files. Nothing is executed, no network is opened and
# nothing is written (apart from the --svg and --badge images the user asks for).

PLUGIN_BUCKETS = {
    "code": ("Code security", 30),
    "perms": ("Permissions and hooks", 25),
    "supply": ("Supply chain", 30),
    "trust": ("Consistency and privacy", 15),
}
PLUGIN_BUCKET_OF = {
    "P001": "trust", "P002": "perms", "P003": "perms", "P004": "supply", "P005": "supply",
    "P006": "supply", "P007": "supply", "P008": "trust", "P009": "code", "P010": "trust", "P012": "supply",
}
PLUGIN_BONUS_MAX = 5
PLUGIN_ROOT_CLIMB = 6          # levels to climb from a target looking for .claude-plugin/plugin.json
PLUGIN_SCRIPT_CODES = ("S", "H002")   # rule families kept when scanning plugin scripts
PLUGIN_NOTE = "plugin detected at %s: use --plugin to audit agents, hooks, scripts and installers"

WEB_TOOLS = {"WebFetch", "WebSearch"}
LOCKFILES = ("uv.lock", "poetry.lock", "package-lock.json", "Pipfile.lock", "pnpm-lock.yaml", "yarn.lock", "npm-shrinkwrap.json")
UNTRUSTED_RE = re.compile(
    r"untrusted\s+(?:external\s+)?(?:data|content|input|web|text)|"
    r"never\s+(?:as|follow|execute|obey)\s+(?:[\w\s,]{0,30}\s)?instructions|"
    r"\bdata,?\s+(?:and\s+)?not\s+(?:as\s+)?instructions|"
    r"\bnot\s+(?:as\s+)?instructions\b", re.I)


@dataclasses.dataclass
class PluginReport:
    name: str
    root: str
    findings: list
    strengths: list
    categories: dict
    score: int
    grade: str
    verdict: str
    bonus: int = 0
    cap_value: int = None
    cap_reason: str = None
    stats: dict = None
    attributions: dict = None   # script path -> skills and agents that call it

    @property
    def capped(self):
        return self.cap_reason is not None

    def to_dict(self):
        return {
            "name": self.name,
            "root": self.root,
            "score": self.score,
            "grade": self.grade,
            "verdict": self.verdict,
            "cap": ({"value": self.cap_value, "reason": self.cap_reason} if self.capped else None),
            "bonus": self.bonus,
            "categories": self.categories,
            "stats": self.stats or {},
            "findings": [f.to_dict() for f in self.findings],
            "strengths": list(self.strengths),
        }


def find_plugin_root(start: Path, levels: int = PLUGIN_ROOT_CLIMB):
    """Climb up to `levels` folders from `start` looking for .claude-plugin/plugin.json."""
    try:
        cur = start.resolve()
    except OSError:
        return None
    if cur.is_file():
        cur = cur.parent
    for _ in range(levels + 1):
        if (cur / ".claude-plugin" / "plugin.json").is_file():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def is_plugin_root(p: Path) -> bool:
    try:
        return (p / ".claude-plugin" / "plugin.json").is_file()
    except OSError:
        return False


def _strip_inline_comment(v: str) -> str:
    v = v.strip()
    if v[:1] in ("'", '"'):
        q = v[0]
        end = v.find(q, 1)
        if end != -1:
            return v[:end + 1]
    m = re.search(r"\s#", v)
    return v[:m.start()].rstrip() if m else v


def _unquote(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    return v


def parse_loose_yaml(lines):
    """A small, forgiving reader for agent frontmatter.

    It copes with a trailing "# comment" after a value, folded (>) and literal (|) blocks,
    simple "- item" lists and inline [a, b] lists. It is not a YAML parser and never raises."""
    out = {}
    i, n = 0, len(lines)
    while i < n:
        raw = lines[i].rstrip("\r")
        m = re.match(r"^([A-Za-z_][\w.-]*)\s*:\s*(.*)$", raw)
        if not m or raw[:1] in (" ", "\t"):
            i += 1
            continue
        key, rest = m.group(1), _strip_inline_comment(m.group(2))
        i += 1
        if re.match(r"^[>|][+-]?\d*$", rest):
            block = []
            while i < n and (not lines[i].strip() or lines[i][:1] in (" ", "\t")):
                block.append(lines[i].strip())
                i += 1
            out[key] = (" " if rest[0] == ">" else "\n").join(b for b in block if b is not None).strip()
            continue
        if rest == "":
            items, nested = [], []
            while i < n and (not lines[i].strip() or lines[i][:1] in (" ", "\t", "-")):
                s = lines[i].strip()
                if s.startswith("- "):
                    items.append(_unquote(_strip_inline_comment(s[2:])))
                elif s and not s.startswith("#"):
                    nested.append(s)
                i += 1
            out[key] = items if items else ("\n".join(nested) if nested else "")
            continue
        if rest.startswith("[") and rest.endswith("]"):
            out[key] = [_unquote(x) for x in rest[1:-1].split(",") if x.strip()]
            continue
        out[key] = _unquote(rest)
    return out


def split_agent(text: str):
    """Return (frontmatter dict, body) for an agent or command file; tolerant of odd YAML."""
    text = text.lstrip("\ufeff")
    lines = text.split("\n")
    if lines and lines[0].strip() == "---":
        for k in range(1, len(lines)):
            if lines[k].strip() == "---":
                return parse_loose_yaml(lines[1:k]), "\n".join(lines[k + 1:])
    return {}, text


def tool_list(value):
    if value is None:
        return None
    items = value if isinstance(value, list) else [x for x in re.split(r"\s*,\s*", str(value)) if x]
    return [_unquote(x).strip() for x in items if _unquote(x).strip()]


def tool_name(t: str) -> str:
    return re.split(r"[\s(]", t, maxsplit=1)[0]


class PluginAudit:
    """Collects the plugin-level findings and strengths; reads files through a small cache."""

    def __init__(self, root: Path, ignore: set, skill_reports):
        self.root = root
        self.ignore = ignore
        self.skill_reports = skill_reports
        self.findings = []
        self.strengths = []
        self.stats = {}
        self._cache = {}
        self.hosts = {}          # host -> first "file" that names it (plugin scripts only)
        self.script_audit = Audit(root, ignore, scope="plugin")

    # ---- reading ----
    def read(self, rel: str):
        if rel not in self._cache:
            txt, _, _ = read_text_file(self.root / rel)
            if txt is not None and txt.startswith("\ufeff"):
                txt = txt[1:]
            self._cache[rel] = txt
        return self._cache[rel]

    def exists(self, rel: str) -> bool:
        return (self.root / rel).exists()

    def rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    # ---- reporting ----
    def add(self, code, message, file=None, line=None, severity=None, hint=None, context=None, used_by=None):
        if code in self.ignore:
            return
        rule = RULES[code]
        sev = severity or rule.severity
        if context is not None and code in CONTEXT_CODES:
            sev = adjust_severity(sev, context)
        self.findings.append(Finding(code, rule.category, sev, message, hint or rule.fix, file, line,
                                     context=context, scope="plugin", used_by=used_by))

    def strength(self, kind: str, text: str, files=None):
        if "P011" in self.ignore:
            return
        self.strengths.append({"code": "P011", "kind": kind, "text": text, "files": list(files or [])[:MAX_LOCATIONS]})


def plugin_bucket(f) -> str:
    return PLUGIN_BUCKET_OF.get(f.code, "code")


def rel_files(root: Path):
    """All plain files under the plugin root (minus caches), as relative posix paths."""
    files, _, _ = collect_files(root)
    return [p.relative_to(root).as_posix() for p in files if not p.is_symlink()]


def is_script_like(rel: str) -> bool:
    low = rel.lower()
    top = low.split("/")[0]
    if top in ("skills", "tests", "test", "docs", "assets", "screenshots", "data", "schema", "node_modules"):
        return False
    base = low.rsplit("/", 1)[-1]
    if top in ("scripts", "hooks", "extensions", "agents", "commands"):
        return True
    return bool(re.match(r"^(?:un)?install[\w.-]*$", base)) or base.startswith(("setup", "bootstrap"))


# ---- P001: manifests ----

MANIFEST_PATH_KEYS = ("skills", "agents", "commands", "hooks", "mcpServers")


def check_manifests(pa: PluginAudit):
    for rel in (".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"):
        txt = pa.read(rel)
        if txt is None:
            continue
        try:
            data = json.loads(txt)
        except ValueError as e:
            pa.add("P001", "%s is not valid JSON: %s" % (rel, str(e)[:80]), file=rel, severity="error")
            continue
        if not isinstance(data, dict):
            pa.add("P001", "%s should hold a JSON object" % rel, file=rel)
            continue
        if rel.endswith("plugin.json"):
            if not str(data.get("name") or "").strip():
                pa.add("P001", "%s has no name" % rel, file=rel)
            for key in MANIFEST_PATH_KEYS:
                val = data.get(key)
                paths = [val] if isinstance(val, str) else [x for x in val if isinstance(x, str)] if isinstance(val, list) else []
                for pth in paths:
                    if not pth.startswith("./") or pth.startswith("../"):
                        continue
                    if not pa.exists(os.path.normpath(pth)):
                        pa.add("P001", "%s names %s \"%s\" but that path does not exist" % (rel, key, pth), file=rel)


def read_json(pa: PluginAudit, rel: str):
    txt = pa.read(rel)
    if txt is None:
        return None
    try:
        return json.loads(txt)
    except ValueError:
        return None


# ---- P002: agents ----

def agent_files(pa: PluginAudit, files):
    return sorted(f for f in files if f.lower().endswith(".md") and (
        re.match(r"^agents/[^/]+\.md$", f, re.I) or re.match(r"^extensions/[^/]+/agents/[^/]+\.md$", f, re.I)))


def check_agents(pa: PluginAudit, files):
    safe, total = [], 0
    for rel in agent_files(pa, files):
        text = pa.read(rel)
        if text is None:
            continue
        fm, body = split_agent(text)
        name = str(fm.get("name") or os.path.basename(rel)[:-3])
        tools = tool_list(fm.get("tools"))
        total += 1
        warned = bool(UNTRUSTED_RE.search(body))
        if warned:
            safe.append(rel)
        if not tools:
            continue
        names = [tool_name(t) for t in tools]
        web = [n for n in names if n in WEB_TOOLS]
        if web and "Bash" in names and "Write" in names:
            extra = " Its prompt does warn that fetched content is untrusted." if warned else ""
            pa.add("P002", "agent %s can use %s, Bash and Write together.%s" % (name, ", ".join(web), extra), file=rel, line=1)
        for t in tools:
            m = re.match(r"^mcp__([\w.-]+?)(?:__\*)?$", t)
            if m and (t.endswith("__*") or t.count("__") == 1):
                pa.add("P002", "agent %s may call every tool of the MCP server \"%s\" (%s)." % (name, m.group(1), t),
                       file=rel, line=1, severity="info")
    pa.stats["agents"] = total
    if safe:
        pa.strength("untrusted-data", "%d of %d agents tell the model to treat fetched content as untrusted data, never as instructions" % (len(safe), total), safe)


def add_group(pa: PluginAudit, code, message, places, severity=None, hint=None, context=None, used_by=None):
    """One finding that stands for several places (count and first MAX_LOCATIONS places)."""
    if code in pa.ignore or not places:
        return
    pa.add(code, message, file=places[0][0], line=places[0][1], severity=severity, hint=hint, context=context, used_by=used_by)
    if pa.findings and pa.findings[-1].message == message:
        f = pa.findings[-1]
        f.count = len(places)
        f.locations = [p[0] + (":" + str(p[1]) if p[1] else "") for p in places[:MAX_LOCATIONS]]


def snippet_of(s: str, n: int = 70) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n - 3] + "..."


# ---- P003: hooks ----

TOOL_VAR_RE = re.compile(r"\$\{?(?:tool_(?:input|name|response|output)|CLAUDE_TOOL\w*|TOOL_INPUT\w*)[\w.]*\}?")
TOOL_EVENTS = {"PreToolUse", "PostToolUse", "PermissionRequest"}
SHELL_COMMANDS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "curl", "wget"}
INTERP_ENV_RE = re.compile(r"\b[A-Z][A-Z0-9_]*(?:PYTHON|NODE|INTERP\w*|SHELL|RUNTIME|BINARY|EXE|EXECUTABLE)\b")
PLUGIN_ROOT_VAR_RE = re.compile(r"\$\{?CLAUDE_PLUGIN_ROOT\}?")


def resolve_plugin_path(pa: PluginAudit, token: str):
    """Turn a command token such as ${CLAUDE_PLUGIN_ROOT}/hooks/x.py into a relative path inside the plugin, or None."""
    t = token.strip().strip("\"'")
    if not PLUGIN_ROOT_VAR_RE.search(t):
        return None
    t = PLUGIN_ROOT_VAR_RE.sub("", t).replace("\\", "/").lstrip("/")
    t = os.path.normpath(t).replace("\\", "/")
    if t.startswith("..") or not t or t == ".":
        return None
    return t if (pa.root / t).is_file() else None


def split_command(cmd: str):
    import shlex
    try:
        return shlex.split(cmd)
    except ValueError:
        return cmd.split()


def hook_sources(pa: PluginAudit):
    found = []
    for rel in ("hooks/hooks.json", ".claude-plugin/hooks.json"):
        data = read_json(pa, rel)
        if isinstance(data, dict):
            found.append((rel, data.get("hooks", data)))
    manifest = read_json(pa, ".claude-plugin/plugin.json")
    if isinstance(manifest, dict) and "hooks" in manifest:
        h = manifest["hooks"]
        if isinstance(h, dict):
            found.append((".claude-plugin/plugin.json", h))
        elif isinstance(h, str):
            rel = os.path.normpath(h).replace("\\", "/").lstrip("./")
            data = read_json(pa, rel)
            if isinstance(data, dict) and all(rel != s[0] for s in found):
                found.append((rel, data.get("hooks", data)))
    return found


def describe_script(pa: PluginAudit, rel: str):
    """One line about a hook script: what it imports and what it can do."""
    text = pa.read(rel)
    if text is None:
        return None
    low = rel.lower()
    mods, caps = [], set()
    if low.endswith(".py"):
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return "%s could not be parsed" % rel
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods += [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                mods.append(node.module.split(".")[0])
        names = set(mods)
        if names & NETWORK_MODULES or "urllib" in names or "http" in names:
            caps.add("network")
        if "subprocess" in names or ("os" in names and re.search(r"os\.(?:system|popen|exec\w*|spawn\w*)\(", text)):
            caps.add("subprocess")
    elif low.endswith((".js", ".mjs", ".cjs", ".ts")):
        mods = re.findall(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)|from\s+['\"]([^'\"]+)['\"]", text)
        mods = [a or b for a, b in mods]
        if re.search(r"child_process|spawnSync|execSync|\bspawn\(|\bexec\(", text):
            caps.add("subprocess")
        if re.search(r"\bfetch\(|https?\.request|require\(['\"]https?['\"]\)", text):
            caps.add("network")
    else:
        for cap, crx in NONPY_CAPS:
            if crx.search(text):
                caps.add(cap)
    mods = sorted(set(m for m in mods if m))
    return "%s imports %s; can use: %s" % (rel, ", ".join(mods) if mods else "nothing", ", ".join(sorted(caps)) if caps else "no network or subprocess")


def interpreter_env_in(text: str):
    """An environment variable that decides which interpreter a hook launcher runs, or None."""
    for rx in (r"process\.env\.([A-Z][A-Z0-9_]*)", r"os\.environ(?:\.get)?\(?\[?\s*['\"]([A-Z][A-Z0-9_]*)['\"]",
               r"exec\s+\"?\$\{?([A-Za-z_]\w*)"):
        for m in re.finditer(rx, text):
            if INTERP_ENV_RE.search(m.group(1)) or (rx.startswith("exec") and INTERP_ENV_RE.search(m.group(1).upper())):
                return m.group(1)
    return None


def check_hooks(pa: PluginAudit):
    described = set()
    n_hooks = 0
    for src, root in hook_sources(pa):
        if not isinstance(root, dict):
            continue
        for event, groups in root.items():
            if not isinstance(groups, list):
                continue
            for grp in groups:
                if not isinstance(grp, dict):
                    continue
                matcher = grp.get("matcher")
                for h in (grp.get("hooks") or []):
                    if not isinstance(h, dict):
                        continue
                    n_hooks += 1
                    htype = h.get("type", "command")
                    cmd = str(h.get("command") or "")
                    args = [str(a) for a in (h.get("args") or [])] if isinstance(h.get("args"), list) else []
                    tokens = split_command(cmd) + args
                    timeout = h.get("timeout")
                    label = "hook %s%s" % (event, (" (matcher %s)" % (matcher if matcher else '"*"')) if event in TOOL_EVENTS else "")
                    shown = " ".join([cmd] + args).strip() or "(%s hook)" % htype
                    pa.add("P003", "%s runs: %s%s" % (label, snippet_of(shown, 150), (", timeout %ss" % timeout) if timeout else ", no timeout"),
                           file=src, severity="info")
                    reasons = []
                    tv = TOOL_VAR_RE.search(" ".join(tokens))
                    if tv:
                        reasons.append("passes %s, a value chosen by the tool call, to the command" % tv.group(0))
                    first = tokens[0] if tokens else ""
                    if first.startswith("$") and not PLUGIN_ROOT_VAR_RE.match(first) and not first.startswith(("$HOME", "${HOME}")):
                        reasons.append("the interpreter comes from the environment variable %s" % first.strip("${}"))
                    scripts = []
                    for t in tokens:
                        rp = resolve_plugin_path(pa, t)
                        if rp and rp not in scripts:
                            scripts.append(rp)
                    caps = set()
                    for sc in scripts:
                        text = pa.read(sc) or ""
                        env = interpreter_env_in(text)
                        if env:
                            reasons.append("%s picks the interpreter from the environment variable %s" % (sc, env))
                        d = describe_script(pa, sc)
                        if d and sc not in described:
                            described.add(sc)
                            pa.add("P003", "hook script " + d, file=sc, severity="info")
                        for cap, crx in NONPY_CAPS:
                            if crx.search(text) or (sc.endswith(".py") and ("urllib" in text or "requests" in text) and cap == "network"):
                                caps.add(cap)
                    broad = event in TOOL_EVENTS and (matcher is None or str(matcher).strip() in ("", "*", ".*"))
                    shellish = os.path.basename(first).lower() in SHELL_COMMANDS or bool(re.search(r"[|;&`]|\$\(", cmd))
                    if broad and (shellish or caps & {"network", "subprocess"}):
                        reasons.append("its matcher covers every tool and it can run shell commands or reach the network")
                    if reasons:
                        pa.add("P003", "%s: %s" % (label, "; ".join(reasons)), file=src, severity="warn",
                               hint="Narrow the matcher, validate every value that comes from the tool call as data, and call a fixed interpreter.")
    pa.stats["hooks"] = n_hooks


# ---- scripts: run the security rules on what the plugin ships outside skills/ ----

def scan_plugin_scripts(pa: PluginAudit, files):
    sa = pa.script_audit
    scanned = 0
    for rel in files:
        if not is_script_like(rel):
            continue
        txt = pa.read(rel)
        if txt is None:
            continue
        scanned += 1
        kind = classify(rel, txt)
        scan_unicode(sa, rel, txt)
        scan_lines(sa, rel, txt, kind)
        scan_file_risks(sa, rel, txt, kind)
        if kind == "md":
            scan_html_comments(sa, rel, txt)
        if rel.lower().endswith(".py"):
            scan_python(sa, rel, txt)
    pa.stats["scripts_scanned"] = scanned
    pa.stats["capabilities"] = sorted(sa.stats["capabilities"])
    pa.hosts = sorted(sa.stats["hosts_in_scripts"])
    keep = [f for f in sa.findings if (f.code.startswith("S") and f.code != "S019") or f.code == "H002"]
    pa.findings.extend(keep)


def script_dependencies(pa: PluginAudit, rel: str, scripts: set):
    """Plugin scripts that `rel` names or imports (same folder or scripts/)."""
    text = pa.read(rel) or ""
    out = set()
    folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
    if not rel.endswith(".py"):
        # a launcher or hook wrapper names the scripts it starts; a Python file is followed through its imports only
        for m in re.finditer(r"(?<![\w.-])([A-Za-z_][\w-]*)\.(py|js|sh)\b", text):
            for base in (folder, "scripts"):
                cand = (base + "/" if base else "") + m.group(1) + "." + m.group(2)
                if cand in scripts and cand != rel:
                    out.add(cand)
    if rel.endswith(".py"):
        for m in re.finditer(r"(?m)^\s*(?:from|import)\s+([A-Za-z_]\w*)", text):
            for base in (folder, "scripts"):
                cand = (base + "/" if base else "") + m.group(1) + ".py"
                if cand in scripts and cand != rel:
                    out.add(cand)
    return out


def attribute_scripts(pa: PluginAudit, files):
    """Which skills and agents call which plugin script (directly or through the scripts it uses)."""
    scripts = set(f for f in files if re.match(r"^(?:scripts|hooks)/[^/]+$", f))
    callers = {}
    for rep in pa.skill_reports:
        sd = Path(rep.path)
        texts = []
        md = find_skill_md(sd)
        if md:
            t, _, _ = read_text_file(md)
            texts.append(t or "")
        refs = sd / "references"
        if refs.is_dir():
            for p in sorted(refs.rglob("*.md"))[:60]:
                t, _, _ = read_text_file(p)
                texts.append(t or "")
        callers[rep.name] = "\n".join(texts)
    for rel in agent_files(pa, files):
        t = pa.read(rel) or ""
        fm, _ = split_agent(t)
        callers["agent:" + str(fm.get("name") or os.path.basename(rel)[:-3])] = t
    direct = {}
    for who, text in callers.items():
        hit = set()
        for m in re.finditer(r"CLAUDE_PLUGIN_ROOT\}?[/\\]+([\w./\\-]+)", text):
            cand = os.path.normpath(m.group(1).replace("\\", "/")).replace("\\", "/").rstrip(".,;:)")
            if cand in scripts:
                hit.add(cand)
        for m in re.finditer(r"\brun\s+[\"']?([\w-]+\.(?:py|js|sh))\b", text):
            if "scripts/" + m.group(1) in scripts:
                hit.add("scripts/" + m.group(1))
        for m in re.finditer(r"(?<![\w./-])scripts/([\w.-]+)", text):
            if "scripts/" + m.group(1) in scripts:
                hit.add("scripts/" + m.group(1))
        direct[who] = hit
    used = {}
    for who, hit in direct.items():
        todo, seen = list(hit), set()
        while todo:
            s = todo.pop()
            if s in seen:
                continue
            seen.add(s)
            todo.extend(script_dependencies(pa, s, scripts) - seen)
        for s in seen:
            used.setdefault(s, []).append(who)
    for s in used:
        used[s] = sorted(set(used[s]))
    for f in pa.findings:
        if f.file in used and not f.used_by:
            f.used_by = used[f.file]
    return used


# ---- P004: downloaded content written into the skill folders ----

NET_OPS_RE = re.compile(r"urlopen|urllib\.request|requests\.(?:get|post|request)|http\.client|httpx\.|aiohttp|\bcurl\b|\bwget\b|Invoke-WebRequest|\bfetch\s*\(")
WRITE_OPS_RE = re.compile(r"write_text|write_bytes|\.write\(|open\([^)\n]*['\"][wa]b?['\"]|shutil\.(?:copy\w*|move)|os\.replace|mkstemp|writeFileSync|Set-Content|\b_?atomic_write\b")
SKILL_TARGET_RE = re.compile(r"""(?:Path|pathlib\.Path)\(\s*['"]skills['"]|/\s*['"]skills['"]|['"]skills/|['"]skills['"]\s*,|os\.path\.join\([^)\n]*['"]skills['"]""")
PIN_FLAG_RE = re.compile(r"""add_argument\(\s*['"]--(ref|commit|sha|tag|rev|revision)['"]([^)]*)\)""", re.S)
ALLOWLIST_RE = re.compile(r"ALLOWED_HOSTS?|_ALLOWED_\w+|allow[-_ ]?list|netloc\s*(?:!=|==|\bnot\s+in\b|\bin\b)", re.I)
MOVABLE_REF_RE = re.compile(r"(?:^|[/=?'\" ])(HEAD|main|master|develop|latest)(?:$|[/'\" &])")
PINNED_REF_RE = re.compile(r"^(?:[0-9a-f]{40}|v?\d+(?:\.\d+){1,3}[\w.-]*)$")


def verifies_hash_before_use(text: str, is_py: bool) -> bool:
    """True when a computed digest is compared with a known one and the code stops on a mismatch."""
    if re.search(r"sha256sum\s+-c|shasum\s+(?:-a\s+256\s+)?-c|Get-FileHash|openssl\s+dgst|gpg\s+--verify|cosign\s+verify|git\s+verify-tag|git\s+tag\s+-v", text):
        return True
    if not is_py:
        return False
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and dotted(node.func) in ("hmac.compare_digest", "secrets.compare_digest"):
            return True
        if isinstance(node, ast.If):
            test_src = ""
            for n in ast.walk(node.test):
                if isinstance(n, ast.Name):
                    test_src += " " + n.id
                elif isinstance(n, ast.Attribute):
                    test_src += " " + n.attr
            if not re.search(r"hash|sha|digest|checksum", test_src, re.I) or not any(isinstance(n, ast.Compare) for n in ast.walk(node.test)):
                continue
            for n in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(n, ast.Raise) or (isinstance(n, ast.Call) and dotted(n.func) in ("sys.exit", "exit", "quit")):
                    return True
    return False


def default_ref_of(text: str, is_py: bool):
    """(has_pin_option, flag, default ref text or None when the code never sets one)."""
    m = PIN_FLAG_RE.search(text)
    if m:
        d = re.search(r"default\s*=\s*([^,)\n]+)", m.group(2))
        if d:
            val = d.group(1).strip().strip("'\"")
            return True, "--" + m.group(1), (None if val == "None" else val)
        return True, "--" + m.group(1), None
    return False, None, None


def check_remote_content(pa: PluginAudit, files):
    for rel in files:
        if not is_script_like(rel) or rel.lower().endswith((".md", ".json", ".txt")):
            continue
        text = pa.read(rel)
        if not text or not (NET_OPS_RE.search(text) and WRITE_OPS_RE.search(text) and SKILL_TARGET_RE.search(text)):
            continue
        is_py = rel.lower().endswith(".py")
        hosts = sorted(set(m.group(1).lower() for m in URL_RE.finditer(text)
                           if m.group(1).lower() not in PLACEHOLDER_HOSTS and not m.group(1).lower().endswith((".invalid", ".test", ".example"))))
        allow = bool(ALLOWLIST_RE.search(text))
        has_pin, flag, dflt = default_ref_of(text, is_py)
        movable = None
        if has_pin:
            if dflt is None:
                movable = "HEAD"
            elif not PINNED_REF_RE.match(dflt):
                movable = dflt
        else:
            mm = MOVABLE_REF_RE.search("\n".join(l for l in text.split("\n") if re.search(r"https?://|ref", l)))
            movable = mm.group(1) if mm else None
        hashed = verifies_hash_before_use(text, is_py)
        facts = ["host allowlist: %s" % ("yes" if allow else "no"),
                 "pin option: %s" % (flag if has_pin else "none"),
                 "default ref: %s" % (("%s (can change)" % movable) if movable else ("pinned" if has_pin else "not set in code")),
                 "hash checked before writing: %s" % ("yes" if hashed else "no")]
        msg = "%s downloads from %s and writes under skills/. %s." % (rel, ", ".join(hosts[:4]) if hosts else "the network", "; ".join(facts))
        sev = "error" if (movable and not hashed) else "warn"
        if not movable and hashed and allow:
            pa.strength("remote-content", "%s pins what it downloads into skills/ and checks a hash first" % rel, [rel])
            continue
        pa.add("P004", msg, file=rel, severity=sev)


# ---- P005: dependencies ----

REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~][^;#\\]*)?")


def classify_spec(spec: str):
    """pinned, bounded (has an upper limit) or open."""
    s = (spec or "").strip()
    if not s:
        return "open"
    if re.search(r"(?<![<>!~=])===?\s*[\w.*+-]+", s) and "*" not in s:
        return "pinned"
    if re.search(r"<|~=", s):
        return "bounded"
    return "open"


def parse_requirements(text: str):
    pkgs = []
    hashed = False
    for raw in text.split("\n"):
        line = raw.strip()
        if "--hash" in line:
            hashed = True
        if not line or line.startswith(("#", "-")):
            continue
        if re.match(r"^(?:git\+|https?://|\.|/)", line):
            ref = re.search(r"@([0-9a-f]{40})\b", line)
            pkgs.append((line[:40], "pinned" if ref else "open", line))
            continue
        m = REQ_LINE_RE.match(line)
        if m:
            pkgs.append((m.group(1), classify_spec(m.group(3)), line))
    return pkgs, hashed


def toml_section(text: str, header: str) -> str:
    m = re.search(r"(?m)^\[%s\]\s*$" % re.escape(header), text)
    if not m:
        return ""
    nxt = re.search(r"(?m)^\[", text[m.end():])
    return text[m.end():m.end() + (nxt.start() if nxt else len(text))]


def pyproject_deps(text: str):
    pkgs = []
    proj = toml_section(text, "project")
    m = re.search(r"(?ms)^dependencies\s*=\s*\[(.*?)\]", proj)
    blocks = [m.group(1)] if m else []
    opt = toml_section(text, "project.optional-dependencies")
    blocks += re.findall(r"(?ms)^[\w.-]+\s*=\s*\[(.*?)\]", opt)
    for blk in blocks:
        for s in re.findall(r"\"([^\"]+)\"|'([^']+)'", blk):
            spec = s[0] or s[1]
            mm = REQ_LINE_RE.match(spec)
            if mm:
                pkgs.append((mm.group(1), classify_spec(mm.group(3)), spec))
    poetry = toml_section(text, "tool.poetry.dependencies")
    for line in poetry.split("\n"):
        mm = re.match(r"^\s*([A-Za-z0-9][\w.-]*)\s*=\s*[\"']([^\"']*)[\"']", line)
        if mm and mm.group(1).lower() != "python":
            v = mm.group(2).strip()
            kind = "pinned" if re.match(r"^=?=?\s*\d[\w.]*$", v) else "bounded" if v[:1] in "^~" else "open"
            pkgs.append((mm.group(1), kind, line.strip()))
    return pkgs


def package_json_deps(data):
    pkgs = []
    for key in ("dependencies", "devDependencies", "optionalDependencies"):
        d = data.get(key) if isinstance(data, dict) else None
        if not isinstance(d, dict):
            continue
        for name, v in d.items():
            v = str(v).strip()
            if v.startswith(("file:", "workspace:", "link:", "npm:")):
                continue
            if re.match(r"^=?\d[\w.+-]*$", v):
                kind = "pinned"
            elif v[:1] in "^~" and re.match(r"^[\^~]\d", v):
                kind = "bounded"
            elif re.search(r"#[0-9a-f]{40}$", v):
                kind = "pinned"
            else:
                kind = "open"
            pkgs.append((name, kind, "%s@%s" % (name, v)))
    return pkgs


def lockfile_packages(pa: PluginAudit, rel: str, project: str):
    """Number of packages a lockfile pins besides the project itself, or None if it cannot be read."""
    text = pa.read(rel)
    if text is None:
        return None
    base = rel.rsplit("/", 1)[-1]
    if base in ("uv.lock", "poetry.lock"):
        names = re.findall(r"(?m)^\[\[package\]\]\s*\nname\s*=\s*\"([^\"]+)\"", text)
        return len([n for n in names if n.lower().replace("_", "-") != project.lower().replace("_", "-")])
    if base in ("package-lock.json", "npm-shrinkwrap.json"):
        try:
            data = json.loads(text)
        except ValueError:
            return None
        pk = data.get("packages")
        if isinstance(pk, dict):
            return len([k for k in pk if k])
        d = data.get("dependencies")
        return len(d) if isinstance(d, dict) else 0
    if base == "Pipfile.lock":
        try:
            data = json.loads(text)
        except ValueError:
            return None
        return len(data.get("default", {})) + len(data.get("develop", {}))
    if base == "pnpm-lock.yaml":
        m = re.search(r"(?m)^packages:\s*$", text)
        return len(re.findall(r"(?m)^  ['\"]?[@/\w][^\n]*:\s*$", text[m.end():])) if m else 0
    if base == "yarn.lock":
        return len([l for l in text.split("\n") if l and not l.startswith((" ", "#")) and l.rstrip().endswith(":") and not l.startswith("__metadata")])
    return None


def check_dependencies(pa: PluginAudit, files):
    declared = 0
    for rel in files:
        if rel.split("/")[0] in ("tests", "test", "node_modules", "docs"):
            continue
        base = rel.rsplit("/", 1)[-1]
        pkgs, hashed, kind = [], False, None
        if re.match(r"^requirements[\w.-]*\.txt$", base):
            text = pa.read(rel)
            if text is None:
                continue
            pkgs, hashed = parse_requirements(text)
            kind = "requirements"
        elif base == "pyproject.toml":
            text = pa.read(rel)
            if text is None:
                continue
            pkgs, hashed, kind = pyproject_deps(text), True, "pyproject"   # hashes are a lockfile matter there
        elif base == "package.json" and rel.count("/") <= 1:
            data = read_json(pa, rel)
            if not isinstance(data, dict):
                continue
            pkgs, hashed, kind = package_json_deps(data), True, "package"
        else:
            continue
        if not pkgs:
            continue
        declared += len(pkgs)
        openp = [p for p in pkgs if p[1] == "open"]
        bounded = [p for p in pkgs if p[1] == "bounded"]
        if openp:
            pa.add("P005", "%s: %d of %d dependencies have no upper bound or exact pin (%s)" % (
                rel, len(openp), len(pkgs), ", ".join(p[0] for p in openp[:5]) + (", ..." if len(openp) > 5 else "")), file=rel, severity="warn")
        if bounded:
            pa.add("P005", "%s: %d of %d dependencies use a range with an upper bound instead of an exact pin (for example %s)" % (
                rel, len(bounded), len(pkgs), bounded[0][2].strip()[:60]), file=rel, severity="info")
        if kind == "requirements" and not hashed:
            pa.add("P005", "%s has no --hash lines, so pip cannot check what it installs against a known hash" % rel, file=rel, severity="info")
    project = ""
    pj = pa.read("pyproject.toml")
    if pj:
        m = re.search(r"(?m)^name\s*=\s*[\"']([^\"']+)[\"']", toml_section(pj, "project"))
        project = m.group(1) if m else ""
    project = project or str((read_json(pa, ".claude-plugin/plugin.json") or {}).get("name") or "")
    for rel in files:
        if rel.rsplit("/", 1)[-1] in LOCKFILES and rel.count("/") <= 1 and rel.split("/")[0] not in ("tests", "node_modules"):
            n = lockfile_packages(pa, rel, project)
            if n == 0 and declared:
                pa.add("P005", "%s lists no packages besides the project itself, so it pins nothing" % rel, file=rel, severity="warn")
            elif n == 0:
                pa.add("P005", "%s lists no packages" % rel, file=rel, severity="info")
    pa.stats["dependencies_declared"] = declared


# ---- P006: installers ----

INSTALLER_RE = re.compile(r"^(?:extensions/[^/]+/)?(?:un)?install[\w.-]*$|^scripts/(?:un)?install[\w.-]*$|^scripts/setup[\w.-]*\.(?:sh|ps1)$", re.I)
PIPE_CODE = "S003"
MOVABLE_URL_RE = re.compile(r"/(?:main|master|HEAD|develop|latest)/|refs/heads/|/raw/(?:main|master|HEAD)/", re.I)
PINNED_URL_RE = re.compile(r"/(?:v?\d+\.\d+[\w.]*|[0-9a-f]{40})/", re.I)
VERIFY_RE = re.compile(r"sha256sum|shasum|Get-FileHash|openssl\s+dgst|gpg\s+--verify|cosign|git\s+verify-tag|git\s+tag\s+-v|minisign", re.I)
NPX_RE = re.compile(r"\bnpx\b([^\n]*)")
NPX_ARGS_LIST_RE = re.compile(r"""\[\s*['"]-y['"]\s*,\s*['"]([^'"]+)['"]""")
DOWNLOAD_RE = re.compile(r"\bgit\s+clone\b|\b(?:curl|wget)\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b|\bnpx\b|\bpip3?\s+install\b|\bnpm\s+(?:install|i)\b")


def npx_package(args: str):
    m = re.search(r"--package[= ]\s*(\S+)", args)
    if m:
        return m.group(1).strip("'\"")
    for tok in args.split():
        if tok.startswith("-"):
            continue
        return tok.strip("'\"")
    return None


def package_pinned(pkg: str) -> bool:
    body = pkg[1:] if pkg.startswith("@") else pkg
    return bool(re.search(r"@\d", body))


def variable_default(text: str, name: str):
    """The default value an installer gives a variable such as REPO_TAG, or None."""
    for rx in (r"(?m)^\s*(?:export\s+)?%s=[\"']?\$\{\w+:-([^}\"']+)\}" % re.escape(name),
               r"(?m)^\s*(?:export\s+)?%s=[\"']?([^\"'$\s]+)[\"']?\s*$" % re.escape(name),
               r"(?mi)^\s*\$%s\s*=\s*[^\n]*?'([^']+)'" % re.escape(name.replace("_", "")) ):
        m = re.search(rx, text)
        if m:
            return m.group(1)
    return None


def check_installers(pa: PluginAudit, files):
    installers = [f for f in files if INSTALLER_RE.match(f)]
    pa.stats["installers"] = len(installers)
    pipes, clones, npx_pinned, npx_open, edits, unverified = [], [], [], [], {}, []
    hygiene, keyenv = [], []
    for rel in installers:
        text = pa.read(rel)
        if text is None:
            continue
        low = rel.lower()
        is_ps = low.endswith(".ps1")
        fc = FileContext(rel, text, "code")
        lines = text.split("\n")
        downloads = False
        verifies = bool(VERIFY_RE.search(text))
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for code, rx, label, scope in SEC_PATTERNS:
                if code != PIPE_CODE:
                    continue
                m = rx.search(line)
                if not m:
                    continue
                ctx = fc.classify(idx, m.start(), line, m.group(0), "")
                um = re.search(r"https?://[^\s\"'|)]+", line)
                url = um.group(0) if um else None
                if MOVABLE_URL_RE.search(url or line):
                    state = "movable"
                elif url and PINNED_URL_RE.search(url):
                    state = "pinned"
                else:
                    state = "unknown"
                pipes.append((rel, idx, ctx, state, url))
                break
            dm = DOWNLOAD_RE.search(line)
            if dm and ctx_is_code(fc, idx, line, dm.start()):
                downloads = True
            m = re.search(r"\bgit\s+clone\b([^\n]*)", line)
            if m and _in_quotes(line[:m.start()]):
                m = None          # the words only appear inside a message
            if not m:
                m = re.search(r"""['"]clone['"]\s*,([^\n]*)""", line)
            if m:
                rest = m.group(1)
                b = re.search(r"(?:--branch|-b)[= ]\s*(\"?[^\s\"]+\"?)", rest)
                if not b and is_ps:
                    b = re.search(r"'--branch'\s*,\s*(\$\w+)", rest)
                    if not b:
                        b = re.search(r"'--branch'\s*,\s*'([^']+)'", rest)
                state, detail = "movable", "no branch or tag is given, so it takes the default branch"
                if b:
                    val = b.group(1).strip("\"'")
                    var = re.match(r"^\$\{?(\w+)\}?$", val)
                    if var:
                        d = variable_default(text, var.group(1))
                        if d and PINNED_REF_RE.match(d):
                            state, detail = "pinned", "it checks out %s by default (%s can override it)" % (d, var.group(1))
                        elif d:
                            state, detail = "movable", "its default ref \"%s\" can move" % d
                        else:
                            state, detail = "unknown", "the ref comes from %s and its default is not visible" % var.group(1)
                    elif PINNED_REF_RE.match(val):
                        state, detail = "pinned", "it checks out %s" % val
                    else:
                        state, detail = "movable", "the ref \"%s\" can move" % val
                clones.append((rel, idx, state, detail))
            for m in NPX_RE.finditer(line):
                args = m.group(1)
                if re.search(r"(?:^|\s)(?:--yes|-y)\b", args) or "--package" in args:
                    pkg = npx_package(args)
                    if pkg:
                        (npx_pinned if package_pinned(pkg) else npx_open).append((rel, idx, pkg))
            for m in NPX_ARGS_LIST_RE.finditer(line):
                (npx_pinned if package_pinned(m.group(1)) else npx_open).append((rel, idx, m.group(1)))
            for label, rx in (("~/.claude" ".json", r"\.claud[e]\.json"), ("~/.claude/settings" ".json", r"\.claud[e][/\\]settings\.json")):
                em = re.search(rx, line)
                if em and ctx_is_code(fc, idx, line, em.start()):
                    edits.setdefault(label, []).append((rel, idx))
        if downloads and not verifies:
            unverified.append((rel, 1))
        signs = []
        if re.search(r"(?m)^\s*set\s+-[a-z]*e[a-z]*u[a-z]*o\s+pipefail|^\s*set\s+-euo\s+pipefail", text):
            signs.append("set -euo pipefail")
        if re.search(r"(?m)^(?:main\s*\(\)\s*\{|function\s+main\b)", text) and re.search(r"(?m)^main\b[^(\n]*$", text):
            signs.append("a main() wrapper")
        if re.search(r"(?m)^\s*trap\s+", text):
            signs.append("trap cleanup")
        if is_ps and re.search(r"\$ErrorActionPreference\s*=\s*[\"']Stop[\"']", text):
            signs.append("ErrorActionPreference Stop")
        if signs:
            hygiene.append((rel, signs))
        if "mcpServers" in text and re.search(r"""['"]env['"]\s*:\s*\{[^}]*(?:KEY|TOKEN|SECRET|PASSWORD)""", text, re.S):
            keyenv.append((rel, 1))
        for ln_no, line in enumerate(lines, 1):
            if re.search(r"(?:~|\$HOME|\$\{HOME\})/\.(?:bashrc|zshrc|bash_profile|profile|zprofile)|\$PROFILE\b|\[Environment\]::SetEnvironmentVariable\([^)]*PATH", line):
                edits.setdefault("a shell startup file or PATH", []).append((rel, ln_no))
    # --- turn what was collected into findings ---
    groups = {}
    for rel, idx, ctx, state, url in pipes:
        groups.setdefault((ctx, state), []).append((rel, idx, url))
    for (ctx, state), items in sorted(groups.items()):
        runs = ctx in ("executed", "agent-instr")
        sev = "warn" if runs and state in ("movable", "unknown") else "info"
        what = {"movable": "a movable address (a branch, so the script behind it can change)",
                "pinned": "an address pinned to a tag or commit",
                "unknown": "an address whose pinning cannot be told"}[state]
        urls = [i[2] for i in items if i[2]]
        add_group(pa, "P006", "%s a download piped into a shell [%s] at %d place%s, using %s%s" % (
            "installers run" if runs else "installers only show", ctx, len(items), "" if len(items) == 1 else "s", what,
            (" (for example " + snippet_of(urls[0], 80) + ")") if urls else ""),
            [(i[0], i[1]) for i in items], severity=sev, context=ctx)
    for rel, idx, state, detail in clones:
        pa.add("P006", "%s runs git clone and %s" % (rel, detail), file=rel, line=idx,
               severity="info" if state == "pinned" else "warn")
    if npx_open:
        add_group(pa, "P006", "npx --yes runs npm packages at install time without asking and they are not pinned to a version: %s" % (
            ", ".join(sorted(set(p[2] for p in npx_open))[:6])), [(r, i) for r, i, _ in npx_open], severity="warn")
    if npx_pinned:
        add_group(pa, "P006", "npx --yes runs npm packages at install time without asking; each is pinned to an exact version: %s" % (
            ", ".join(sorted(set(p[2] for p in npx_pinned))[:6]) + (", ..." if len(set(p[2] for p in npx_pinned)) > 6 else "")),
            [(r, i) for r, i, _ in npx_pinned], severity="info")
    for label, places in sorted(edits.items()):
        uniq = []
        for p in places:
            if p not in uniq:
                uniq.append(p)
        sev = "warn" if "startup" in label else "info"
        add_group(pa, "P006", "installers change %s on the user's machine (%d installer file%s)" % (
            label, len(set(p[0] for p in uniq)), "" if len(set(p[0] for p in uniq)) == 1 else "s"), uniq, severity=sev)
    if keyenv:
        add_group(pa, "P006", "installers write API keys in plain text under mcpServers.<name>.env in the Claude config file", keyenv, severity="info")
    if unverified:
        add_group(pa, "P006", "%d installer file%s download code without checking a checksum or a signature" % (
            len(unverified), "" if len(unverified) == 1 else "s"), unverified, severity="info")
    pinned_clones = [c for c in clones if c[2] == "pinned"]
    if pinned_clones:
        pa.strength("pinned-installer", "installers clone a pinned release tag, not a branch (%s)" % ", ".join(sorted(set(c[0] for c in pinned_clones))[:3]),
                    sorted(set(c[0] for c in pinned_clones)))
    if npx_pinned and not npx_open:
        pa.strength("pinned-npx", "every npx package an installer runs is pinned to an exact version (%d uses)" % len(npx_pinned), sorted(set(p[0] for p in npx_pinned)))
    if hygiene:
        pa.strength("installer-hygiene", "%d installer%s fail early and clean up (set -euo pipefail, a main() wrapper, trap or ErrorActionPreference)" % (
            len(hygiene), "" if len(hygiene) == 1 else "s"), [h[0] for h in hygiene])


def ctx_is_code(fc: "FileContext", idx: int, line: str, col: int = 0) -> bool:
    """False for lines that only print or document a command (echo lines, comments)."""
    if line.strip().startswith("#"):
        return False
    ctx = fc.classify(idx, col, line, line[col:col + 20].strip() or line.strip(), "")
    return ctx in ("executed", "agent-instr")


# ---- P007: CI workflows ----

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
OFFICIAL_ACTION_OWNERS = ("actions", "github")
INJECTABLE_RE = re.compile(
    r"\$\{\{[^}]*(?:github\.head_ref|github\.event\.(?:issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|workflow_run)\b[^}]*"
    r"(?:title|body|name|label|ref|message|email|login|head_branch|display_title)\b)[^}]*\}\}")


def run_blocks(lines):
    """(line number, text) of every run: step, handling one-line and block forms."""
    out = []
    i, n = 0, len(lines)
    while i < n:
        m = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(2)
        if rest and rest[0] not in "|>":
            out.append((i + 1, rest))
            i += 1
            continue
        j, buf = i + 1, []
        while j < n and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
            buf.append(lines[j])
            j += 1
        for k, b in enumerate(buf):
            out.append((i + 2 + k, b))
        i = j
    return out


def workflow_steps(lines):
    """Rough step blocks: (start line number, list of lines) for each '- ' list item that holds a uses: or run: key."""
    steps = []
    i, n = 0, len(lines)
    while i < n:
        m = re.match(r"^(\s*)-\s+\S", lines[i])
        if not m:
            i += 1
            continue
        indent = len(m.group(1))
        j = i + 1
        while j < n and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > indent):
            j += 1
        steps.append((i + 1, lines[i:j]))
        i += 1
    return steps


def check_workflows(pa: PluginAudit, files):
    flows = [f for f in files if re.match(r"^\.github/workflows/[^/]+\.ya?ml$", f)]
    pa.stats["workflows"] = len(flows)
    n_actions = n_pinned = 0
    with_perms = 0
    unpinned_places = {"warn": [], "info": []}
    for rel in flows:
        text = pa.read(rel)
        if text is None:
            continue
        lines = text.split("\n")
        # permissions
        top_perm = re.search(r"(?m)^permissions:\s*(.*)$", text)
        job_perm = re.search(r"(?m)^\s{4,}permissions:", text)
        if top_perm or job_perm:
            with_perms += 1
        else:
            pa.add("P007", "%s declares no permissions: block, so the token scope depends on the repository default" % rel, file=rel, severity="warn")
        if top_perm and top_perm.group(1).strip().split("#")[0].strip() == "write-all":
            pa.add("P007", "%s gives the workflow token write-all permissions" % rel, file=rel,
                   line=text[:top_perm.start()].count("\n") + 1, severity="warn")
        elif top_perm:
            body = text[top_perm.end():top_perm.end() + 400]
            m = re.search(r"(?m)^\s+([\w-]+):\s*write\b", body.split("\njobs:")[0])
            if m and not top_perm.group(1).strip():
                pa.add("P007", "%s grants %s: write to the whole workflow" % (rel, m.group(1)), file=rel,
                       line=text[:top_perm.start()].count("\n") + 1, severity="info")
        # pull_request_target
        m = re.search(r"(?m)^\s*(?:on:\s*)?\[?\s*pull_request_target\b|^\s+pull_request_target:", text)
        if m:
            checks_out_head = bool(re.search(r"ref:\s*\$\{\{[^}]*(?:pull_request\.head|head_ref|head\.sha)", text))
            pa.add("P007", "%s runs on pull_request_target%s" % (rel, " and checks out the pull request code" if checks_out_head else ""),
                   file=rel, line=text[:m.start()].count("\n") + 1, severity="error" if checks_out_head else "warn")
        # actions
        for idx, line in enumerate(lines, 1):
            um = re.match(r"^\s*(?:-\s+)?uses:\s*([^\s#]+)", line)
            if not um:
                continue
            target = um.group(1).strip("\"'")
            if target.startswith(("./", "docker://")):
                continue
            n_actions += 1
            name, _, ref = target.partition("@")
            owner = name.split("/")[0]
            if SHA40_RE.match(ref):
                n_pinned += 1
                continue
            unpinned_places["info" if owner in OFFICIAL_ACTION_OWNERS else "warn"].append((rel, idx, target))
        # untrusted text inside run:
        for ln_no, chunk in run_blocks(lines):
            hit = INJECTABLE_RE.search(chunk)
            if hit:
                pa.add("P007", "%s pastes %s straight into a run step; text an outsider controls can become shell commands" % (
                    rel, snippet_of(hit.group(0), 60)), file=rel, line=ln_no, severity="warn")
        # secrets handed to third-party actions
        for start, block in workflow_steps(lines):
            head = "\n".join(block)
            um = re.search(r"\buses:\s*([^\s#]+)", head)
            if not um or um.group(1).startswith(("./", "docker://")):
                continue
            owner = um.group(1).split("@")[0].split("/")[0]
            if owner in OFFICIAL_ACTION_OWNERS:
                continue
            sec = re.findall(r"\$\{\{\s*secrets\.(\w+)\s*\}\}", head)
            sec = [s for s in sec if s != "GITHUB_TOKEN"]
            if sec:
                pa.add("P007", "%s hands the secret %s to the third-party action %s" % (rel, sec[0], um.group(1).split("@")[0]),
                       file=rel, line=start, severity="warn")
    for sev in ("warn", "info"):
        places = unpinned_places[sev]
        if places:
            who = "third-party " if sev == "warn" else "official "
            add_group(pa, "P007", "%d %saction use%s not pinned to a full 40-character commit (for example %s)" % (
                len(places), who, " is" if len(places) == 1 else "s are", places[0][2]), [(p[0], p[1]) for p in places], severity=sev)
    if n_actions and n_pinned == n_actions:
        pa.strength("pinned-actions", "all %d GitHub Actions uses are pinned to a full commit SHA" % n_actions, flows)
    if flows and with_perms == len(flows):
        pa.strength("ci-permissions", "every CI workflow declares its token permissions", flows)


# ---- P008: consistency ----

COUNT_RE = re.compile(r"(?<![\w.])(\d{1,3})\s+(?:[\w-]+\s+){0,2}?(sub-?skills?|skills?|sub-?agents?|agents?|commands|extensions)\b", re.I)
HEDGE_BEFORE_RE = re.compile(r"(?:up\s+to|at\s+most|over|more\s+than|about|around|max(?:imum)?)\s*$", re.I)


def version_of(v) -> str:
    return str(v).strip().lstrip("vV")


def check_consistency(pa: PluginAudit, files):
    versions = []   # (source, version)
    texts = []      # (source, description)
    pj = read_json(pa, ".claude-plugin/plugin.json")
    mk = read_json(pa, ".claude-plugin/marketplace.json")
    if isinstance(pj, dict):
        if pj.get("version"):
            versions.append((".claude-plugin/plugin.json", version_of(pj["version"])))
        if isinstance(pj.get("description"), str):
            texts.append((".claude-plugin/plugin.json", pj["description"]))
    if isinstance(mk, dict):
        meta = mk.get("metadata") if isinstance(mk.get("metadata"), dict) else {}
        if meta.get("version"):
            versions.append((".claude-plugin/marketplace.json", version_of(meta["version"])))
        if isinstance(meta.get("description"), str):
            texts.append((".claude-plugin/marketplace.json", meta["description"]))
        for p in (mk.get("plugins") or []):
            if isinstance(p, dict):
                if p.get("version"):
                    versions.append((".claude-plugin/marketplace.json", version_of(p["version"])))
                if isinstance(p.get("description"), str):
                    texts.append((".claude-plugin/marketplace.json", p["description"]))
    py = pa.read("pyproject.toml")
    if py:
        m = re.search(r"(?m)^version\s*=\s*[\"']([^\"']+)[\"']", toml_section(py, "project"))
        if m:
            versions.append(("pyproject.toml", version_of(m.group(1))))
        m = re.search(r"(?m)^description\s*=\s*[\"']([^\"']+)[\"']", toml_section(py, "project"))
        if m:
            texts.append(("pyproject.toml", m.group(1)))
    pkg = read_json(pa, "package.json")
    if isinstance(pkg, dict):
        if pkg.get("version"):
            versions.append(("package.json", version_of(pkg["version"])))
    cff = pa.read("CITATION.cff")
    if cff:
        m = re.search(r"(?m)^version:\s*[\"']?([^\s\"']+)", cff)
        if m:
            versions.append(("CITATION.cff", version_of(m.group(1))))
    for rel in files:
        if re.match(r"^install\.(?:sh|ps1)$", rel):
            text = pa.read(rel) or ""
            for var in ("REPO_TAG", "RepoTag"):
                d = variable_default(text, var)
                if d and PINNED_REF_RE.match(d):
                    versions.append((rel + " (default tag)", version_of(d)))
                    break
    distinct = sorted(set(v for _, v in versions))
    if len(distinct) > 1:
        pa.add("P008", "versions disagree: " + "; ".join("%s says %s" % (s, v) for s, v in versions), file=versions[0][0].split(" ")[0], severity="warn")
    elif len(versions) >= 2:
        pa.strength("one-version", "the same version (%s) in %d places: %s" % (distinct[0], len(versions), ", ".join(sorted(set(s for s, _ in versions)))),
                    sorted(set(s.split(" ")[0] for s, _ in versions)))
    # declared counts against what is on disk
    real = {
        "skills": len([f for f in files if re.match(r"^skills/[^/]+/SKILL\.md$", f)]),
        "agents": len([f for f in files if re.match(r"^agents/[^/]+\.md$", f)]),
        "commands": len([f for f in files if re.match(r"^commands/[^/]+\.md$", f)]),
        "extensions": len(set(f.split("/")[1] for f in files if re.match(r"^extensions/[^/]+/", f))),
    }
    checked = 0
    for src, text in texts:
        for m in COUNT_RE.finditer(text):
            if HEDGE_BEFORE_RE.search(text[max(0, m.start() - 12):m.start()]):
                continue
            noun = m.group(2).lower().replace("-", "")
            kind = "skills" if "skill" in noun else "agents" if "agent" in noun else noun.rstrip("s") + "s"
            if kind not in real or (real[kind] == 0 and kind in ("commands", "extensions")):
                continue
            checked += 1
            if int(m.group(1)) != real[kind]:
                pa.add("P008", "%s declares %s %s but the plugin has %d" % (src, m.group(1), m.group(2), real[kind]), file=src, severity="warn")
    pa.stats["declared_counts_checked"] = checked
    if checked and not any(f.code == "P008" for f in pa.findings):
        pa.strength("counts-match", "the %d skill, agent and extension counts the manifests declare match the files on disk" % checked,
                    [".claude-plugin/plugin.json"])


# ---- P009: credentials ----

CRED_CONST_RE = re.compile(r"(?:token|oauth|cred|secret|api|auth|key)", re.I)


def _py_constants(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            yield node.value, getattr(node, "lineno", None)


def check_credentials(pa: PluginAudit, files):
    doc_files = [f for f in files if f.lower().endswith(".md") and not re.match(r"^(?:tests?|node_modules)/", f, re.I)
                 and not f.lower().startswith(("changelog", "contributors"))]
    safe, unsafe = [], []
    for rel in files:
        if not rel.lower().endswith(".py") or not is_script_like(rel):
            continue
        text = pa.read(rel)
        if not text:
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        paths = [(c, ln) for c, ln in _py_constants(tree)
                 if (c.startswith("~") or ".config/" in c or ".config\\" in c) and CRED_CONST_RE.search(c)
                 and not re.search(r"cache|\.log$", c, re.I) and "\n" not in c and len(c) < 200]
        if not paths:
            continue
        writes = bool(re.search(r"""open\([^)\n]*['"][wax]b?\+?['"]|\.write_text\(|\.write_bytes\(|os\.open\([^)\n]*O_(?:WRONLY|CREAT|RDWR)|mode\s*=\s*['"][wax]""", text))
        restricted = bool(re.search(r"0o[0-7]*[04]00\b|0o600|0o700|umask\(0o0?77\)|\bicacls\b", text)) and bool(re.search(r"chmod|fchmod|os\.open|umask|icacls|mode\s*=", text))
        if writes and restricted:
            safe.append((rel, paths[0][1]))
        elif writes:
            unsafe.append((rel, paths[0][1], paths[0][0]))
    for rel, ln, path in unsafe:
        pa.add("P009", "%s writes a credential file (%s) without limiting it to its owner (no 0o600 or similar)" % (rel, path), file=rel, line=ln, severity="warn")
    if safe:
        pa.strength("credential-modes", "scripts that save credentials restrict the file to its owner (0o600): %s" % ", ".join(sorted(set(s[0] for s in safe))[:4]),
                    sorted(set(s[0] for s in safe)))
    # reading another tool's sign-in files
    seen = set()
    for f in pa.script_audit.findings:
        if f.code != "S006" or f.context not in ("executed", "agent-instr") or not f.file:
            continue
        label, _, snip = f.message.partition(": ")
        key = (f.file, label)
        if key in seen:
            continue
        seen.add(key)
        words = [w.lower() for w in re.findall(r"[A-Za-z][\w-]{2,}", snip) if w.lower() not in ("config", "home", "users")]
        where = changelog_only = None
        for d in doc_files:
            body = (pa.read(d) or "").lower()
            if any(w in body for w in words):
                where = d
                break
        if not where:
            for d in files:
                if re.match(r"^changelog[\w.-]*\.md$", d, re.I) and any(w in (pa.read(d) or "").lower() for w in words):
                    changelog_only = d
                    break
        note = ("it is described in %s" % where) if where else (
            "only %s mentions it" % changelog_only if changelog_only else "no markdown file in the plugin mentions it")
        pa.add("P009", "%s uses %s (%s) in running code; %s" % (f.file, label, snippet_of(snip, 40), note),
               file=f.file, line=f.line, severity="info" if where else "warn")


# ---- P010: hosts and telemetry ----

SPEC_DOMAINS = {"w3.org", "schema.org", "json-schema.org", "ietf.org", "iana.org", "gnu.org", "apache.org",
                "opensource.org", "creativecommons.org", "xmlsoft.org", "sitemaps.org", "ogp.me", "purl.org"}
TELEMETRY_RE = re.compile(r"\bposthog\b|\bsentry(?:_sdk|-sdk|\.io)\b|\bmixpanel\b|\bsegment\.(?:io|com)\b|@segment/|\busage[ _-]report", re.I)
TWO_LEVEL_TLDS = {"co", "com", "org", "net", "gov", "ac", "edu"}
SAMPLE_DOMAINS = {"example.com", "example.org", "example.net", "competitor.com", "yoursite.com", "yourdomain.com", "mysite.com",
                  "domain.com", "site.com", "website.com", "test.com", "mydomain.com", "yourcompany.com", "company.com"}


def registrable(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in TWO_LEVEL_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def check_hosts(pa: PluginAudit, files):
    docs_rel = [f for f in ("PRIVACY.md", "README.md", "SECURITY.md", "docs/PRIVACY.md") if pa.exists(f)]
    docs = "\n".join((pa.read(f) or "") for f in docs_rel).lower()
    first = {}
    tele = []
    for rel in files:
        if not is_script_like(rel) or rel.lower().endswith(".md"):
            continue
        text = pa.read(rel)
        if not text or classify(rel, text) != "code":
            continue
        fc = FileContext(rel, text, "code")
        for idx, line in enumerate(text.split("\n"), 1):
            s = line.strip()
            if s.startswith(("#", "//", "*", "REM ")):
                continue
            for um in URL_RE.finditer(line):
                host = um.group(1).lower().rstrip(".")
                if not host or host in PLACEHOLDER_HOSTS or host.endswith((".invalid", ".test", ".local", ".example")) or "." not in host:
                    continue
                if registrable(host) in SPEC_DOMAINS or registrable(host) in SAMPLE_DOMAINS or re.match(r"^[\d.]+$", host):
                    continue
                if fc.classify(idx, um.start(), line, um.group(0), "") not in ("executed", "agent-instr"):
                    continue          # a comment, a help text or a warning does not contact anything
                first.setdefault(registrable(host), (rel, idx, host))
            tm = TELEMETRY_RE.search(line)
            if tm:
                tele.append((rel, idx, tm.group(0)))
    pa.stats["hosts_in_plugin_scripts"] = sorted(first)
    if docs_rel:
        missing = [(d, v) for d, v in sorted(first.items()) if d not in docs and v[2] not in docs]
        if missing:
            add_group(pa, "P010", "%d host%s named in code %s not mentioned in %s: %s" % (
                len(missing), "" if len(missing) == 1 else "s", "is" if len(missing) == 1 else "are", " or ".join(docs_rel),
                ", ".join(d for d, _ in missing[:8]) + (", ..." if len(missing) > 8 else "")), [(v[0], v[1]) for _, v in missing], severity="warn")
        elif first:
            pa.strength("hosts-documented", "every host the scripts name (%d) appears in %s" % (len(first), " or ".join(docs_rel)), docs_rel)
    if tele:
        add_group(pa, "P010", "code names %s, which looks like usage telemetry or error reporting" % ", ".join(sorted(set(t[2].lower() for t in tele))[:4]),
                  [(t[0], t[1]) for t in tele], severity="warn",
                  hint="Remove it, or make it opt-in and say so in PRIVACY.md.")


# ---- P011: other strengths ----

def collect_strengths(pa: PluginAudit, files):
    low = {f.lower(): f for f in files}
    sec = next((low[k] for k in ("security.md", ".github/security.md", "docs/security.md") if k in low), None)
    if sec and re.search(r"threat\s+model", pa.read(sec) or "", re.I):
        pa.strength("threat-model", "%s describes a threat model" % sec, [sec])
    co = next((low[k] for k in ("codeowners", ".github/codeowners", "docs/codeowners") if k in low), None)
    if co:
        pa.strength("codeowners", "%s routes review of sensitive files to named owners" % co, [co])
    db = next((low[k] for k in (".github/dependabot.yml", ".github/dependabot.yaml") if k in low), None)
    if db:
        pa.strength("dependabot", "%s keeps dependencies and actions up to date" % db, [db])
    hostile = [f for f in files if re.match(r"^tests?/", f, re.I) and re.search(r"ssrf|inject|hostile|malicious|adversar|travers|rebind|fuzz|untrusted|url_safety", f, re.I)]
    if hostile:
        pa.strength("hostile-tests", "tests feed hostile input to the code (%s)" % ", ".join(h.split("/")[-1] for h in hostile[:3]), hostile)
    ssrf = [f for f in files if is_script_like(f) and re.search(r"ssrf|url_safety|safe_?fetch|safe_?url", f.rsplit("/", 1)[-1], re.I)]
    if ssrf:
        pa.strength("ssrf-module", "a dedicated module guards outgoing requests against SSRF (%s)" % ssrf[0], ssrf)
    rel = [f for f in files if re.search(r"sha256sums?|\.sha256$|checksums?\.txt|release[-_]manifest|release_sign|verify_release", f.rsplit("/", 1)[-1], re.I)]
    if rel:
        pa.strength("release-hashes", "release hashes or signing tools ship with the plugin (%s)" % ", ".join(r.rsplit("/", 1)[-1] for r in rel[:3]), rel)


# ---- P012: unquoted placeholders in shell commands ----

PLACEHOLDER_NAMES = {"url", "urls", "domain", "host", "hostname", "site", "page", "target", "path", "file", "keyword", "query", "dir", "folder", "input", "output", "name", "id"}
ANGLE_RE = re.compile(r"(?<![\w\"'`$<>=-])<([A-Za-z][\w-]*)>(?![\"'`\w])")
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})\s*([\w+-]*)")


def command_spans(text: str):
    """(line number, command text) for shell fences and for inline code that starts like a command."""
    out = []
    in_fence, lang = False, ""
    for idx, line in enumerate(text.split("\n"), 1):
        fm = FENCE_RE.match(line)
        if fm:
            if in_fence:
                in_fence = False
            else:
                in_fence, lang = True, fm.group(2).lower()
            continue
        if in_fence:
            if lang in MD_LANG_SHELL:
                out.append((idx, line))
            continue
        for m in re.finditer(r"`([^`\n]+)`", line):
            span = m.group(1)
            if COMMAND_START_RE.match(span) or re.match(r"^\s*(?:\"[^\"]*\"|\S+)\s+run\s+\S+", span):
                out.append((idx, span))
    return out


def check_placeholders(pa: PluginAudit, files):
    hits = {}
    cands = [f for f in files if f.lower().endswith(".md") and (
        re.match(r"^skills/.+/(?:SKILL\.md|references/.+\.md)$", f) or re.match(r"^agents/[^/]+\.md$", f) or re.match(r"^commands/[^/]+\.md$", f))]
    for rel in cands:
        text = pa.read(rel)
        if not text:
            continue
        for ln, cmd in command_spans(text):
            for m in ANGLE_RE.finditer(cmd):
                name = m.group(1).lower()
                if name not in PLACEHOLDER_NAMES or _in_quotes(cmd[:m.start()]):
                    continue
                hits.setdefault(name, []).append((rel, ln))
    for name, places in sorted(hits.items()):
        add_group(pa, "P012", "unquoted <%s> in a shell command: a shell reads the less-than sign as a redirect, so quote it as \"<%s>\"" % (name, name), places, severity="info")


# ---- scoring and orchestration ----

def score_plugin(findings, strengths):
    cats = {}
    total_max = total_got = 0
    for key, (label, mx) in PLUGIN_BUCKETS.items():
        by_code = {}
        for f in findings:
            if plugin_bucket(f) == key and SEVERITY_PENALTY[f.severity] > 0:
                by_code.setdefault((f.code, f.severity), []).append(f)
        penalty = 0
        for (code, sev), items in by_code.items():
            weight = sum(1.0 + min(DUP_CAP, DUP_STEP * (max(1, it.count) - 1)) for it in items)
            penalty += int(math.ceil(SEVERITY_PENALTY[sev] * min(1 + 0.5 * (weight - 1), 2.0)))
        got = max(0, mx - penalty)
        cats[key] = {"label": label, "score": got, "max": mx}
        total_max += mx
        total_got += got
    base = int(round(100.0 * total_got / total_max)) if total_max else 100
    bonus = min(PLUGIN_BONUS_MAX, len(set(s["kind"] for s in strengths)))
    score = min(100, base + bonus)
    cap_value = cap_reason = None
    sec = cats.get("code")
    if any(f.severity == "critical" for f in findings):
        cap_value, cap_reason = CRITICAL_CAP, "critical"
    elif any(f.category == "security" and f.severity == "error" for f in findings):
        cap_value, cap_reason = SECURITY_ERROR_CAP, "security-error"
    elif sec and sec["score"] * 2 < sec["max"]:
        cap_value, cap_reason = SECURITY_LOW_CAP, "security-low"
    if cap_value is not None:
        if score > cap_value:
            score = cap_value
        else:
            cap_value = cap_reason = None
    return cats, score, bonus, cap_value, cap_reason


def audit_plugin(root: Path, ignore: set, skill_reports) -> PluginReport:
    pa = PluginAudit(root, ignore, skill_reports)
    files = rel_files(root)
    pa.stats["files"] = len(files)
    check_manifests(pa)
    check_agents(pa, files)
    check_hooks(pa)
    scan_plugin_scripts(pa, files)
    check_remote_content(pa, files)
    check_dependencies(pa, files)
    check_installers(pa, files)
    check_workflows(pa, files)
    check_consistency(pa, files)
    check_credentials(pa, files)
    check_hosts(pa, files)
    check_placeholders(pa, files)
    collect_strengths(pa, files)
    used = attribute_scripts(pa, files)
    findings = dedup_findings(pa.findings)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.code, f.file or "", f.line or 0))
    cats, score, bonus, cap_value, cap_reason = score_plugin(findings, pa.strengths)
    manifest = read_json(pa, ".claude-plugin/plugin.json")
    name = str(manifest.get("name")) if isinstance(manifest, dict) and manifest.get("name") else root.name
    pa.stats["skills"] = len(skill_reports)
    return PluginReport(name=name, root=str(root), findings=findings, strengths=pa.strengths, categories=cats, score=score,
                        grade=grade_for(score), verdict=verdict_for(score, cap_reason, security_notes(findings)), bonus=bonus,
                        cap_value=cap_value, cap_reason=cap_reason, stats=pa.stats, attributions=used)


def merge_plugin_into_skills(reports, plugin: PluginReport, only=None):
    """Optional (--plugin-affects-skills): add the findings of the scripts a skill calls to that skill's own report."""
    for r in reports:
        extra = [dataclasses.replace(f) for f in plugin.findings if f.used_by and r.name in f.used_by and f.code[0] == "S"]
        if not extra:
            continue
        findings = dedup_findings(list(r.findings) + extra)
        if only:
            findings = [f for f in findings if f.category in only]
        cat_order = {k: i for i, k in enumerate(CATEGORIES)}
        findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], cat_order.get(f.category, 99), f.code, f.file or "", f.line or 0))
        cats, score, cap_value, cap_reason = score_findings(findings, only)
        r.findings, r.categories, r.score = findings, cats, score
        r.grade, r.verdict = grade_for(score), verdict_for(score, cap_reason, security_notes(findings))
        r.cap_value, r.cap_reason = cap_value, cap_reason


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------

class Style:
    def __init__(self, color: bool, unicode_ok: bool):
        self.color = color
        self.u = unicode_ok

    def c(self, code, s):
        return "\033[%sm%s\033[0m" % (code, s) if self.color else s

    def bold(self, s):
        return self.c("1", s)

    def dim(self, s):
        return self.c("2", s)

    def sev(self, sev, s):
        return self.c({"critical": "1;31", "error": "31", "warn": "33", "info": "36"}[sev], s)

    def score(self, score, s):
        col = "32" if score >= 90 else "92" if score >= 80 else "33" if score >= 70 else "38;5;208" if score >= 60 else "31"
        return self.c("1;" + col if ";" not in col else col, s)

    def bar(self, got, mx, width=20):
        filled = int(round(width * got / float(mx))) if mx else 0
        full, empty = ("\u2588", "\u2591") if self.u else ("#", "-")
        return full * filled + empty * (width - filled)


CAP_TEXT = {
    "critical": "a critical security finding",
    "security-error": "a serious security finding",
    "security-low": "a low security score",
}
SEV_MARK_U = {"critical": "\u2716\u2716", "error": "\u2716 ", "warn": "\u25b2 ", "info": "\u25cf "}
SEV_MARK_A = {"critical": "!!", "error": "x ", "warn": "^ ", "info": "o "}


def finding_lines(f, st, marks, width):
    """Text lines for one finding, with its context in brackets and its repeat count and places."""
    ctx = (" [" + f.context + "]") if f.context else ""
    cnt = (" x%d" % f.count) if f.count > 1 else ""
    head = "  %s %s %-8s%s%s %s" % (st.sev(f.severity, marks[f.severity]), st.bold(f.code), f.severity, ctx, cnt, st.dim(f.where()))
    out = [head.rstrip()]
    for ln in textwrap.wrap(f.message, width=width - 10):
        out.append("      " + ln)
    if f.count > 1 and f.locations and len(f.locations) > 1:
        more = f.count - len(f.locations)
        places = ", ".join(f.locations[1:]) + ((" and %d more" % more) if more > 0 else "")
        for ln in textwrap.wrap("Also at: " + places, width=width - 10):
            out.append(st.dim("      " + ln))
    if f.used_by:
        for ln in textwrap.wrap("Used by: " + ", ".join(f.used_by[:8]) + (" and %d more" % (len(f.used_by) - 8) if len(f.used_by) > 8 else ""), width=width - 10):
            out.append(st.dim("      " + ln))
    for ln in textwrap.wrap("Fix: " + f.hint, width=width - 10):
        out.append(st.dim("      " + ln))
    return out


def plugin_counts(p):
    sev = {}
    for f in p.findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    return sev


def render_plugin_text(p, st, min_sev="info", width=100):
    marks = SEV_MARK_U if st.u else SEV_MARK_A
    tick = "\u2714" if st.u else "+"
    out = [st.bold("Plugin: " + p.name) + st.dim("   " + p.root)]
    out.append("  Score  %s   Grade %s   %s" % (st.score(p.score, st.bold("%d/100" % p.score)), st.score(p.score, st.bold(p.grade)), p.verdict))
    if p.capped:
        out.append(st.dim("  Score capped at %d because of %s" % (p.cap_value, CAP_TEXT[p.cap_reason])))
    if p.bonus:
        out.append(st.dim("  Includes +%d for the strengths below (a bonus never cancels a critical finding)" % p.bonus))
    for key, c in p.categories.items():
        out.append("  %-24s %s %2d/%d" % (c["label"], st.score(100 * c["score"] / c["max"], st.bar(c["score"], c["max"])), c["score"], c["max"]))
    s = p.stats or {}
    bits = ["%d files" % s.get("files", 0), "%d scripts read" % s.get("scripts_scanned", 0), "%d agents" % s.get("agents", 0),
            "%d hook%s" % (s.get("hooks", 0), "" if s.get("hooks", 0) == 1 else "s"), "%d installers" % s.get("installers", 0),
            "%d workflows" % s.get("workflows", 0)]
    out.append(st.dim("  " + ", ".join(bits)))
    if p.strengths:
        out.append("")
        out.append("  Strengths (%d)" % len(p.strengths))
        for sg in p.strengths:
            for k, ln in enumerate(textwrap.wrap(sg["text"], width=width - 10)):
                out.append(("  %s " % st.c("32", tick) if k == 0 else "    ") + " " + ln)
    shown = [f for f in p.findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_sev]]
    out.append("")
    if not shown:
        out.append("  No plugin findings.")
    else:
        out.append("  Findings (%d)" % len(shown))
        for f in shown:
            out.extend(finding_lines(f, st, marks, width))
    out.append("")
    return out


def render_text(reports, collection, st: Style, min_sev="info", width=100, plugin=None, note=None, show_skills=True):
    out = []
    marks = SEV_MARK_U if st.u else SEV_MARK_A
    out.append(st.bold("Skill Verdict Score " + __version__))
    if note:
        out.append(st.dim("  note: " + note))
    out.append("")
    for r in (reports if show_skills else []):
        out.append(st.bold(r.name) + st.dim("   " + r.path))
        sc = "%d/100" % r.score
        out.append("  Score  %s   Grade %s   %s" % (st.score(r.score, st.bold(sc)), st.score(r.score, st.bold(r.grade)), r.verdict))
        if r.capped:
            out.append(st.dim("  Score capped at %d because of %s" % (r.cap_value, CAP_TEXT[r.cap_reason])))
        for key, c in r.categories.items():
            out.append("  %-11s %s %2d/%d" % (c["label"], st.score(100 * c["score"] / c["max"], st.bar(c["score"], c["max"])), c["score"], c["max"]))
        s = r.stats
        bits = ["%d lines" % s["lines"], "~%d body tokens" % s["body_tokens_est"],
                "~%d tokens always loaded (name + description)" % s["menu_tokens_est"], "%d file%s" % (s["files"], "" if s["files"] == 1 else "s")]
        out.append(st.dim("  " + ", ".join(bits)))
        if s["capabilities"]:
            out.append(st.dim("  Script capabilities: " + ", ".join(s["capabilities"])))
        if s["hosts_in_scripts"]:
            out.append(st.dim("  Hosts named in scripts: " + ", ".join(s["hosts_in_scripts"][:8])))
        shown = [f for f in r.findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_sev]]
        if not shown:
            out.append("")
            out.append("  " + st.c("32", "No findings. Nothing to fix.") if st.color else "  No findings. Nothing to fix.")
        else:
            out.append("")
            out.append("  Findings (%d)" % len(shown))
            for f in shown:
                out.extend(finding_lines(f, st, marks, width))
        out.append("")
    if collection and show_skills:
        out.append(st.bold("Across the collection"))
        for f in collection:
            out.append("  %s %s %-8s" % (st.sev(f.severity, marks[f.severity]), st.bold(f.code), f.severity))
            for ln in textwrap.wrap(f.message, width=width - 10):
                out.append("      " + ln)
            for ln in textwrap.wrap("Fix: " + f.hint, width=width - 10):
                out.append(st.dim("      " + ln))
        out.append("")
    if plugin is not None:
        out.extend(render_plugin_text(plugin, st, min_sev, width))
    if len(reports) > 1 and show_skills:
        out.append(st.bold("Summary"))
        for r in sorted(reports, key=lambda x: x.score):
            out.append("  %3d  %s  %-28s %s" % (r.score, r.grade, r.name[:28], r.verdict))
        avg = sum(r.score for r in reports) / float(len(reports))
        out.append("  Average %.0f across %d skills" % (avg, len(reports)))
        out.append("")
    return "\n".join(out)


def md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def md_finding_row(f):
    where = f.where()
    if f.count > 1:
        where += " (+%d more places)" % (f.count - 1) if f.count > 1 else ""
    msg = f.message + ((" (x%d)" % f.count) if f.count > 1 else "")
    return "| %s | %s | %s | %s | %s | %s |" % (f.code, f.severity, f.context or "", md_escape(where), md_escape(msg), md_escape(f.hint))


def render_plugin_markdown(p, min_sev="info"):
    out = ["## Plugin: %s" % p.name, "", "**%d/100, grade %s.** %s%s" % (
        p.score, p.grade, p.verdict, (" (capped at %d because of %s)" % (p.cap_value, CAP_TEXT[p.cap_reason])) if p.capped else ""), "",
        "| Category | Score |", "| --- | ---: |"]
    for c in p.categories.values():
        out.append("| %s | %d/%d |" % (c["label"], c["score"], c["max"]))
    if p.bonus:
        out += ["", "Includes +%d for the strengths below. A bonus never cancels a critical finding." % p.bonus]
    if p.strengths:
        out += ["", "### Strengths", ""] + ["- %s" % sg["text"] for sg in p.strengths]
    shown = [f for f in p.findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_sev]]
    out += ["", "### Findings", ""]
    if shown:
        out += ["| Code | Severity | Context | Where | Finding | Fix |", "| --- | --- | --- | --- | --- | --- |"]
        for f in shown:
            out.append(md_finding_row(f))
    else:
        out.append("No plugin findings.")
    out.append("")
    return out


def render_markdown(reports, collection, min_sev="info", plugin=None, note=None, show_skills=True):
    out = ["# Skill Verdict Score report", "", "_Skill Verdict Score %s_" % __version__, ""]
    if note:
        out += ["_Note: %s_" % note, ""]
    if len(reports) > 1 and show_skills:
        out += ["| Skill | Score | Grade | Verdict |", "| --- | ---: | :---: | --- |"]
        for r in sorted(reports, key=lambda x: x.score):
            out.append("| %s | %d | %s | %s |" % (md_escape(r.name), r.score, r.grade, r.verdict))
        out.append("")
    for r in (reports if show_skills else []):
        out += ["## %s" % r.name, "", "**%d/100, grade %s.** %s%s" % (
                r.score, r.grade, r.verdict,
                (" (capped at %d because of %s)" % (r.cap_value, CAP_TEXT[r.cap_reason])) if r.capped else ""), "",
                "| Category | Score |", "| --- | ---: |"]
        for c in r.categories.values():
            out.append("| %s | %d/%d |" % (c["label"], c["score"], c["max"]))
        s = r.stats
        out += ["", "%d lines, about %d body tokens, about %d tokens always loaded, %d files." % (
            s["lines"], s["body_tokens_est"], s["menu_tokens_est"], s["files"]), ""]
        shown = [f for f in r.findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_sev]]
        if shown:
            out += ["| Code | Severity | Context | Where | Finding | Fix |", "| --- | --- | --- | --- | --- | --- |"]
            for f in shown:
                out.append(md_finding_row(f))
        else:
            out.append("No findings.")
        out.append("")
    if collection and show_skills:
        out += ["## Across the collection", ""]
        for f in collection:
            out.append("- **%s** (%s): %s Fix: %s" % (f.code, f.severity, f.message, f.hint))
        out.append("")
    if plugin is not None:
        out += render_plugin_markdown(plugin, min_sev)
    return "\n".join(out)


def render_json(reports, collection, plugin=None, note=None, show_skills=True):
    avg = sum(r.score for r in reports) / float(len(reports)) if reports else 0
    doc = {
        "tool": "skill-verdict-score",
        "version": __version__,
        "summary": {"skills": len(reports), "average_score": round(avg, 1),
                    "lowest_score": min((r.score for r in reports), default=None),
                    "any_critical": any(r.cap_reason == "critical" for r in reports) or bool(plugin and plugin.cap_reason == "critical")},
        "skills": [r.to_dict() for r in reports] if show_skills else [],
        "collection_findings": [f.to_dict() for f in collection] if show_skills else [],
        "plugin": plugin.to_dict() if plugin is not None else None,
    }
    if note:
        doc["notes"] = [note]
    return json.dumps(doc, indent=2, ensure_ascii=False)


CONTEXT_DOC = [
    ("executed", "Code that runs: a script body, a shell command, a string passed to exec or a shell.", "keeps the severity"),
    ("agent-instr", "An instruction the agent is told to follow: SKILL.md, agent and command files, shell fences and imperative lines in references, any override or hidden-instruction text (S011, S012) in references, and the command of a hook or MCP entry in a JSON file.", "keeps the severity"),
    ("documented", "Text in documentation the agent only reads as information.", "one level lower"),
    ("hint", "A message a script prints or a help string, which describes a command without running it.", "one level lower"),
    ("comment", "A comment or a docstring.", "info"),
    ("defensive", "A blocklist, a deny rule, or a sentence that warns against the very thing it names.", "info"),
    ("fixture", "A file under tests/, test/, fixtures/, fixture/ or __tests__/.", "info"),
]
PLUGIN_SCORE_DOC = [
    ("Code security", 30, "Security rules (S) run on the scripts, installers, hooks and extension files, and P009"),
    ("Permissions and hooks", 25, "P002 and P003"),
    ("Supply chain", 30, "P004, P005, P006, P007 and P012"),
    ("Consistency and privacy", 15, "P001, P008 and P010"),
]


def category_label(key: str) -> str:
    return CATEGORIES[key][0] if key in CATEGORIES else "Plugin"


def render_rules(fmt: str) -> str:
    if fmt == "json":
        return json.dumps([dataclasses.asdict(r) for r in sorted(RULES.values(), key=lambda x: x.code)], indent=2)
    out = []
    if fmt == "markdown":
        out += ["# Rules", "", "Generated by `skill_verdict_score.py --list-rules --format markdown`. "
                "Severity is the default; some rules lower it when the text is clearly a warning.", ""]
        for key, (label, mx) in CATEGORIES.items():
            out += ["## %s (%d points)" % (label, mx), "", "| Code | Severity | Check | Why it matters | Fix |", "| --- | --- | --- | --- | --- |"]
            for r in sorted((x for x in RULES.values() if x.category == key), key=lambda x: x.code):
                out.append("| %s | %s | %s | %s | %s |" % (r.code, r.severity, md_escape(r.title), md_escape(r.why), md_escape(r.fix)))
            out.append("")
        out += ["## Contexts", "",
                "Text-based findings (%s) are tagged with the context of the matched text, shown in brackets in the report "
                "and as `context` in JSON. The context decides the severity." % ", ".join(sorted(CONTEXT_CODES)), "",
                "| Context | Meaning | Effect on severity |", "| --- | --- | --- |"]
        for c, meaning, effect in CONTEXT_DOC:
            out.append("| %s | %s | %s |" % (c, md_escape(meaning), effect))
        out += ["", "Secrets (S001) are never lowered by context. Hidden characters (S002) are lowered only inside a test folder.", ""]
        out += ["## Plugin rules (only with --plugin)", "",
                "These rules audit what a plugin installs besides its skills. They run only with `--plugin`, read files only, "
                "and are scored in a separate block with its own 0 to 100 score. They do not change a skill's score unless "
                "`--plugin-affects-skills` is given.", "",
                "| Block | Points | Rules |", "| --- | ---: | --- |"]
        for label, mx, what in PLUGIN_SCORE_DOC:
            out.append("| %s | %d | %s |" % (label, mx, what))
        out += ["", "| Code | Severity | Check | Why it matters | Fix |", "| --- | --- | --- | --- | --- |"]
        for r in sorted((x for x in RULES.values() if x.category == "plugin"), key=lambda x: x.code):
            out.append("| %s | %s | %s | %s | %s |" % (r.code, r.severity, md_escape(r.title), md_escape(r.why), md_escape(r.fix)))
        out.append("")
        return "\n".join(out)
    for key, (label, mx) in CATEGORIES.items():
        out.append("%s (%d points)" % (label, mx))
        for r in sorted((x for x in RULES.values() if x.category == key), key=lambda x: x.code):
            out.append("  %s  %-8s %s" % (r.code, r.severity, r.title))
        out.append("")
    out.append("Plugin (own score, only with --plugin)")
    for r in sorted((x for x in RULES.values() if x.category == "plugin"), key=lambda x: x.code):
        out.append("  %s  %-8s %s" % (r.code, r.severity, r.title))
    out.append("")
    return "\n".join(out)


# ---- SVG ----

def score_color(score: float) -> str:
    return ("#34d399" if score >= 90 else "#a3e635" if score >= 80 else "#fbbf24" if score >= 70
            else "#fb923c" if score >= 60 else "#f87171")


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def trunc(s: str, n: int) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:max(0, n - 3)].rstrip() + "..."


def plugin_card_report(p):
    """The plugin block dressed as a SkillReport so the same card and badge code can draw it."""
    s = p.stats or {}
    foot = "%d files, %d scripts read, %d agents, %d hook%s, %d installers  |  %d strengths, %d findings" % (
        s.get("files", 0), s.get("scripts_scanned", 0), s.get("agents", 0), s.get("hooks", 0), "" if s.get("hooks", 0) == 1 else "s",
        s.get("installers", 0), len(p.strengths), len(p.findings))
    return SkillReport(name=p.name, path=p.root, findings=p.findings,
                       stats={"lines": 0, "body_tokens_est": 0, "menu_tokens_est": 0, "files": s.get("files", 0),
                              "brand": "SKILL VERDICT SCORE   PLUGIN", "footer": foot, "badge_label": "plugin health"},
                       categories=p.categories, score=p.score, grade=p.grade, verdict=p.verdict,
                       cap_value=p.cap_value, cap_reason=p.cap_reason)


def svg_card(r: SkillReport, plugin=None) -> str:
    col = "#f87171" if r.cap_reason == "critical" else score_color(r.score)
    radius = 140
    circ = 2 * math.pi * radius
    dash = circ * r.score / 100.0
    rows = []
    y = 262
    for key, c in r.categories.items():
        pct = c["score"] / float(c["max"])
        bc = score_color(pct * 100)
        rows.append(
            '<text x="560" y="%d" class="lab">%s</text>'
            '<rect x="700" y="%d" width="330" height="14" rx="7" fill="#ffffff" fill-opacity="0.09"/>'
            '<rect x="700" y="%d" width="%.1f" height="14" rx="7" fill="%s"/>'
            '<text x="1130" y="%d" class="val" text-anchor="end">%d/%d</text>'
            % (y + 12, esc(c["label"]), y, y, max(14.0, 330 * pct) if c["score"] > 0 else 0, bc, y + 12, c["score"], c["max"]))
        y += 40
    top = [f for f in r.findings if f.severity != "info"][:3]
    issue_lines = []
    iy = 540
    if top:
        for f in top:
            dotc = {"critical": "#f87171", "error": "#fb923c", "warn": "#fbbf24"}[f.severity]
            issue_lines.append('<circle cx="568" cy="%d" r="5" fill="%s"/><text x="584" y="%d" class="issue">%s  %s</text>'
                               % (iy - 6, dotc, iy, esc(f.code), esc(trunc(f.message, 46))))
            iy += 28
    else:
        issue_lines.append('<text x="560" y="%d" class="issue">No warnings or errors. Healthy skill.</text>' % iy)
    return """<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-label="Skill Verdict Score scorecard for %(name)s: %(score)d out of 100, grade %(grade)s">
<defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#0b1020"/><stop offset="1" stop-color="#18203d"/></linearGradient></defs>
<style>
text{font-family:Inter,-apple-system,"Segoe UI",Helvetica,Arial,sans-serif;fill:#e6eaf7}
.brand{font-size:20px;font-weight:700;letter-spacing:4px;fill:#8ea0ff}
.ver{font-size:16px;fill:#6b7699}
.name{font-size:46px;font-weight:800}
.verdict{font-size:24px;font-weight:600}
.lab{font-size:20px;fill:#b7c0df}
.val{font-size:18px;fill:#b7c0df}
.head{font-size:16px;font-weight:700;letter-spacing:3px;fill:#6b7699}
.issue{font-size:18px;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;fill:#cfd6ee}
.big{font-size:118px;font-weight:800;text-anchor:middle}
.small{font-size:26px;fill:#8d97ba;text-anchor:middle}
.pill{font-size:26px;font-weight:800;text-anchor:middle;letter-spacing:2px}
.foot{font-size:15px;fill:#6b7699}
</style>
<rect width="1200" height="630" fill="url(#bg)"/>
<text x="60" y="70" class="brand">%(brand)s</text>
<text x="1140" y="70" class="ver" text-anchor="end">v%(version)s</text>
<circle cx="300" cy="330" r="%(radius)d" fill="none" stroke="#ffffff" stroke-opacity="0.08" stroke-width="28"/>
<circle cx="300" cy="330" r="%(radius)d" fill="none" stroke="%(col)s" stroke-width="28" stroke-linecap="round" stroke-dasharray="%(dash).1f %(circ).1f" transform="rotate(-90 300 330)"/>
<text x="300" y="352" class="big" style="fill:%(col)s">%(score)d</text>
<text x="300" y="396" class="small">out of 100</text>
<rect x="225" y="500" width="150" height="48" rx="24" fill="%(col)s" fill-opacity="0.16" stroke="%(col)s" stroke-width="2"/>
<text x="300" y="534" class="pill" style="fill:%(col)s">GRADE %(grade)s</text>
<text x="560" y="150" class="name">%(name)s</text>
<text x="560" y="196" class="verdict" style="fill:%(col)s">%(verdict)s</text>
%(rows)s
<text x="560" y="500" class="head">TOP FIXES</text>
%(issues)s
<text x="60" y="605" class="foot">%(stats)s</text>
%(plugin_note)s</svg>
""" % {
        "name": esc(trunc(r.name, 24)), "score": r.score, "grade": esc(r.grade), "verdict": esc(r.verdict),
        "version": esc(__version__), "radius": radius, "col": col, "dash": dash, "circ": circ,
        "rows": "\n".join(rows), "issues": "\n".join(issue_lines),
        "stats": esc(r.stats.get("footer") or "%d lines, ~%d body tokens, ~%d tokens always loaded, %d file%s" % (
            r.stats["lines"], r.stats["body_tokens_est"], r.stats["menu_tokens_est"], r.stats["files"], "" if r.stats["files"] == 1 else "s")),
        "brand": esc(r.stats.get("brand") or "SKILL VERDICT SCORE"),
        "plugin_note": ('<text x="1140" y="605" class="foot" text-anchor="end">%s</text>\n' % esc(
            "PLUGIN %d/100 %s  |  %d finding%s, %d strength%s" % (plugin.score, plugin.grade, len(plugin.findings), "" if len(plugin.findings) == 1 else "s",
                                                               len(plugin.strengths), "" if len(plugin.strengths) == 1 else "s"))) if plugin is not None else "",
    }


def svg_badge(r: SkillReport, plugin=None) -> str:
    label = r.stats.get("badge_label") or "skill health"
    value = "%d %s" % (r.score, r.grade)
    lw = int(len(label) * 6.4 + 20)
    rw = int(len(value) * 7.0 + 20)
    w = lw + rw
    col = "#e05d44" if r.cap_reason == "critical" else {"#34d399": "#3fb68b", "#a3e635": "#97ca00", "#fbbf24": "#dfb317",
                                       "#fb923c": "#fe7d37", "#f87171": "#e05d44"}[score_color(r.score)]
    return ("""<svg xmlns="http://www.w3.org/2000/svg" width="%(w)d" height="20" role="img" aria-label="%(label)s: %(value)s">
<title>%(label)s: %(value)s</title>
<clipPath id="r"><rect width="%(w)d" height="20" rx="3" fill="#fff"/></clipPath>
<g clip-path="url(#r)"><rect width="%(lw)d" height="20" fill="#555"/><rect x="%(lw)d" width="%(rw)d" height="20" fill="%(col)s"/></g>
<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
<text x="%(lx)s" y="14">%(label)s</text><text x="%(rx)s" y="14" font-weight="bold">%(value)s</text></g>
</svg>
""" % {"w": w, "lw": lw, "rw": rw, "col": col, "label": esc(label), "value": esc(value),
       "lx": lw / 2.0, "rx": lw + rw / 2.0})


def safe_name(n: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", n).strip("-") or "skill"


def write_images(reports, target: str, kind: str, plugin=None):
    maker = svg_card if kind == "card" else svg_badge
    written = []
    tp = Path(target)
    pr = plugin_card_report(plugin) if plugin is not None else None
    if len(reports) <= 1 and tp.suffix.lower() == ".svg":
        tp.parent.mkdir(parents=True, exist_ok=True)
        if reports:
            tp.write_text(maker(reports[0], plugin), encoding="utf-8")
            written.append(str(tp))
        if pr is not None:
            f = tp if not reports else tp.with_name(tp.stem + "-plugin.svg")
            f.write_text(maker(pr), encoding="utf-8")
            written.append(str(f))
        return written
    tp.mkdir(parents=True, exist_ok=True)
    for r in reports:
        f = tp / (safe_name(r.name) + ("-scorecard.svg" if kind == "card" else "-badge.svg"))
        f.write_text(maker(r, plugin), encoding="utf-8")
        written.append(str(f))
    if pr is not None:
        f = tp / (safe_name(plugin.name) + ("-plugin-scorecard.svg" if kind == "card" else "-plugin-badge.svg"))
        f.write_text(maker(pr), encoding="utf-8")
        written.append(str(f))
    return written


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="skill-verdict-score",
        description="Audit Agent Skills (folders with a SKILL.md): validity, triggering, weight, security, hygiene. "
                    "Read-only: the audited code is never executed.",
        epilog="Exit codes: 0 ok, 1 a threshold was not met, 2 usage error or no skills found.")
    p.add_argument("paths", nargs="*", help="a skill folder, a folder of skills, or a SKILL.md file")
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text", help="report format (default: text)")
    p.add_argument("--output", "-o", metavar="FILE", help="write the report to FILE instead of the screen")
    p.add_argument("--svg", metavar="PATH", help="write a shareable scorecard image (a .svg file, or a folder for many skills)")
    p.add_argument("--badge", metavar="PATH", help="write a small README badge (a .svg file, or a folder)")
    p.add_argument("--fail-under", type=int, metavar="N", help="exit 1 if any skill scores below N")
    p.add_argument("--fail-on", choices=["critical", "error", "warn"], help="exit 1 if any finding is at least this severe")
    p.add_argument("--ignore", metavar="CODES", help="comma-separated rule codes to skip, for example S011,T002")
    p.add_argument("--only", metavar="CATEGORIES", help="comma-separated categories to score: " + ",".join(CATEGORIES) +
                   ",plugin (only the plugin block; implies --plugin)")
    p.add_argument("--plugin", nargs="?", const="auto", metavar="ROOT",
                   help="also audit what the plugin would install (agents, hooks, scripts, installers, CI, dependencies) in its own "
                        "score block. ROOT is the plugin folder; without it the root is found by climbing up to %d folders from the "
                        "target. Put the paths before --plugin when you give no ROOT" % PLUGIN_ROOT_CLIMB)
    p.add_argument("--plugin-affects-skills", action="store_true",
                   help="with --plugin, also add the findings of the scripts a skill calls to that skill's own score (off by default)")
    p.add_argument("--online", action="store_true",
                   help="reserved for checks that need the network (for example a tag signature). This version makes no network "
                        "request and the flag changes nothing")
    p.add_argument("--min-severity", choices=["info", "warn", "error", "critical"], default="info", help="hide findings below this level")
    p.add_argument("--max-depth", type=int, default=5, help="how deep to look for skills in a folder (default 5)")
    p.add_argument("--no-color", action="store_true", help="plain output")
    p.add_argument("--ascii", action="store_true", help="ASCII-only bars and marks")
    p.add_argument("--list-rules", action="store_true", help="print every rule (use --format markdown or json)")
    p.add_argument("--explain", metavar="CODE", help="explain one rule, for example S003")
    p.add_argument("--version", action="store_true", help="print the version")
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print("skill-verdict-score " + __version__)
        return 0
    if args.list_rules:
        print(render_rules(args.format))
        return 0
    if args.explain:
        code = args.explain.upper()
        r = RULES.get(code)
        if not r:
            print("Unknown rule: " + code, file=sys.stderr)
            return 2
        print("%s  %s\nCategory: %s, default severity: %s\n\nWhy it matters: %s\nHow to fix: %s" % (
            r.code, r.title, category_label(r.category), r.severity, r.why, r.fix))
        return 0
    paths = list(args.paths)
    only_raw = set(c.strip().lower() for c in (args.only or "").split(",") if c.strip())
    want_plugin = args.plugin is not None or "plugin" in only_raw
    plugin_root = None
    if args.plugin not in (None, "auto"):
        cand = Path(args.plugin)
        if is_plugin_root(cand):
            plugin_root = cand.resolve()
            if not paths:
                paths = [str(plugin_root / "skills") if (plugin_root / "skills").is_dir() else str(plugin_root)]
        else:
            paths.append(args.plugin)       # "--plugin PATH" where PATH is a skills folder, not a plugin root
    if not paths and want_plugin:
        paths = ["."]
    if not paths:
        parser.print_usage(sys.stderr)
        print("skill-verdict-score: give at least one path, or use --list-rules", file=sys.stderr)
        return 2
    ignore = set(c.strip().upper() for c in (args.ignore or "").split(",") if c.strip())
    unknown = [c for c in ignore if c not in RULES]
    if unknown:
        print("skill-verdict-score: unknown rule code(s): " + ", ".join(unknown), file=sys.stderr)
        return 2
    only = None
    plugin_only = False
    if only_raw:
        bad = [c for c in only_raw if c not in CATEGORIES and c != "plugin"]
        if bad:
            print("skill-verdict-score: unknown category: " + ", ".join(bad), file=sys.stderr)
            return 2
        plugin_only = only_raw == {"plugin"}
        only = (only_raw - {"plugin"}) or None
    if args.online:
        print("skill-verdict-score: --online is reserved: this version makes no network request, so nothing was sent.", file=sys.stderr)
    found = discover(paths, args.max_depth)
    if not found:
        print("skill-verdict-score: no SKILL.md found under: " + ", ".join(paths), file=sys.stderr)
        return 2
    reports = [audit_skill(d, md, ignore, only) for d, md in found]
    collection = collection_checks(reports, ignore)
    if only:
        collection = [f for f in collection if f.category in only]
    if plugin_root is None:
        for pth in paths:
            plugin_root = find_plugin_root(Path(pth))
            if plugin_root:
                break
    plugin = None
    note = None
    if want_plugin:
        if plugin_root is None:
            print("skill-verdict-score: --plugin: no .claude-plugin/plugin.json found in the target or up to %d folders above it" % PLUGIN_ROOT_CLIMB,
                  file=sys.stderr)
            return 2
        plugin = audit_plugin(plugin_root, ignore, reports)
        if args.plugin_affects_skills:
            merge_plugin_into_skills(reports, plugin, only)
    elif plugin_root is not None:
        note = PLUGIN_NOTE % plugin_root

    enc = (getattr(sys.stdout, "encoding", None) or "").lower()
    unicode_ok = enc.startswith("utf") and not args.ascii
    color = (not args.no_color and not args.output and sys.stdout.isatty() and not os.environ.get("NO_COLOR")
             and args.format == "text")
    st = Style(color, unicode_ok)
    show_skills = not plugin_only
    if args.format == "json":
        text = render_json(reports, collection, plugin, note, show_skills)
    elif args.format == "markdown":
        text = render_markdown(reports, collection, args.min_severity, plugin, note, show_skills)
    else:
        text = render_text(reports, collection, st, args.min_severity, min(110, max(70, _term_width())), plugin, note, show_skills)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
        print("wrote " + args.output, file=sys.stderr)
    else:
        try:
            print(text)
        except UnicodeEncodeError:
            print(text.encode("ascii", "replace").decode("ascii"))
    img_reports = [] if plugin_only else reports
    if args.svg:
        for w in write_images(img_reports, args.svg, "card", plugin):
            print("wrote " + w, file=sys.stderr)
    if args.badge:
        for w in write_images(img_reports, args.badge, "badge", plugin):
            print("wrote " + w, file=sys.stderr)

    code = 0
    scores = ([] if plugin_only else [r.score for r in reports]) + ([plugin.score] if plugin is not None else [])
    if args.fail_under is not None and any(sc < args.fail_under for sc in scores):
        code = 1
    if args.fail_on:
        lvl = SEVERITY_ORDER[args.fail_on]
        allf = ([] if plugin_only else [f for r in reports for f in r.findings] + collection) + (list(plugin.findings) if plugin is not None else [])
        if any(SEVERITY_ORDER[f.severity] >= lvl for f in allf):
            code = 1
    return code


def _term_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 100


if __name__ == "__main__":
    sys.exit(main())
