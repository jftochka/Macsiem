"""LOOBins ``code`` -> structured argv patterns.

Build-time only.  Nothing in ``macsiem/`` imports this module, and its output
deliberately contains **no executable command strings** -- only token
constraints, hashes and prose.  See docs/SAFETY.md ("corpus firewall").

The corpus is adversary tradecraft written for humans: heredocs, pipelines,
``while true`` loops, ``<TARGET_IP>`` placeholders, narration comments, and
several examples where only the first of four chained commands is the actual
technique.  A substring matcher over these strings would false-positive on
every Mac in the world.  This pipeline is the alternative.
"""

from __future__ import annotations

import hashlib
import re
import shlex

# Shell grammar that must never be mistaken for a binary.  Without this the
# naive extractor emits rules whose "binary" is `while`, `do`, `done` or `let`.
SHELL_KEYWORDS = {
    "while", "for", "do", "done", "if", "then", "elif", "else", "fi", "case",
    "esac", "function", "select", "until", "in", "[[", "]]", "[", "]", "{", "}",
    "let", "local", "declare", "typeset", "readonly", "return", "break",
    "continue", "shift", "trap", "wait", "set", "unset", "alias", "unalias",
    "echo", "printf", "cd", "pwd", "export", "read", "eval", "source", ".",
    "true", "false", ":", "exit", "history", "jobs", "fg", "bg", "umask",
}

# Peelable prefixes: they modify how the *next* command runs, they are not the
# technique themselves.  `sudo` additionally flags the rule as privileged.
PREFIX_COMMANDS = {"sudo", "doas", "nohup", "command", "builtin", "time", "exec", "env", "stdbuf"}

# Ordered placeholder substitutions.  Applied before tokenizing so that a
# multi-word `$(...)` does not explode into several bogus tokens.
WILD = "MACSIEMWILDCARD"
_PLACEHOLDER_SUBS = [
    (re.compile(r"\$\([^)]*\)"), WILD),           # $(command substitution)
    (re.compile(r"`[^`]*`"), WILD),               # `backticks`
    (re.compile(r"\$\{[^}]*\}"), WILD),           # ${VAR}
    (re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*"), WILD),  # $VAR
    (re.compile(r"\$\d+"), WILD),                 # $1
    (re.compile(r"<[A-Za-z0-9_. -]{0,40}>"), WILD),   # <TARGET_IP>, <>
]

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_URL = re.compile(r"^[a-z][a-z0-9+.-]*://", re.I)
_NUMBER = re.compile(r"^\d+$")
_B64ISH = re.compile(r"^[A-Za-z0-9+/=]{20,}$")
_HEXISH = re.compile(r"^[0-9a-fA-F]{16,}$")

# Sample/attacker-controlled names that appear in the corpus.  These are
# illustrative, never literal indicators.
_SAMPLE_WORDS = re.compile(
    r"(?i)\b(evil|malicious|payload|attacker|badcert|bad_cert|mypayload|loot|"
    r"clipdata|gain_persistence|backdoor|implant|example|foo|bar|test|"
    r"username|user_name|hostname|filename|yourfile|somefile|targetfile|"
    r"newpassword|oldpassword|mypassword)\b")
_VOLATILE_PREFIXES = ("/tmp/", "/private/tmp/", "/var/folders/", "~/", "/Users/")


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# ---------------------------------------------------------------------------
# S1-S3: clean, excise heredocs, split into statements
# ---------------------------------------------------------------------------
def clean_lines(code):
    """Join line continuations, drop comment-only lines and narration."""
    text = code.replace("\r\n", "\n").replace("\\\n", " ")
    out = []
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(stripped)
    return out


_HEREDOC_START = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def excise_heredocs(lines):
    """Remove ``<<EOF`` redirections and their bodies; return (lines, bodies).

    Bodies are re-processed separately at a confidence penalty -- an
    ``osascript <<EOF`` payload is a real technique, but its body is not a
    continuation of the outer command line.
    """
    result, bodies = [], []
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _HEREDOC_START.search(line)
        if not match:
            result.append(line)
            index += 1
            continue
        terminator = match.group(2)
        result.append(line[:match.start()].rstrip() + line[match.end():])
        index += 1
        body = []
        while index < len(lines) and lines[index].strip() != terminator:
            body.append(lines[index])
            index += 1
        index += 1  # skip the terminator line itself
        if body:
            bodies.append("\n".join(body))
    return result, bodies


_SPLIT_TOKENS = (";;", "&&", "||", ";", "|", "&")


def split_statements(line):
    """Quote-aware split on ``;`` ``&&`` ``||`` ``|`` ``&``.

    Hand-rolled rather than ``re.split`` because the corpus contains separators
    inside quoted AppleScript and inside ``log show --predicate`` strings.
    """
    statements, current = [], []
    quote = None
    depth = 0
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            current.append(char)
            if char == quote and (index == 0 or line[index - 1] != "\\"):
                quote = None
            index += 1
            continue
        if char in "'\"":
            quote = char
            current.append(char)
            index += 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        if depth == 0:
            matched = next((tok for tok in _SPLIT_TOKENS if line.startswith(tok, index)), None)
            if matched:
                statements.append("".join(current).strip())
                current = []
                index += len(matched)
                continue
        current.append(char)
        index += 1
    statements.append("".join(current).strip())
    return [s for s in statements if s]


# ---------------------------------------------------------------------------
# S4-S5: normalize placeholders, tokenize
# ---------------------------------------------------------------------------
def extract_substitutions(statement):
    """Pull out ``$(...)``/backtick bodies so their commands are not lost.

    ``while true; do echo $(osascript -e 'return (the clipboard)'); done`` is a
    real clipboard-collection technique whose only interesting command lives
    inside the substitution.  Flattening it to a wildcard would drop the rule.
    """
    inner = []
    index = 0
    while index < len(statement) - 1:
        if statement[index] == "$" and statement[index + 1] == "(":
            depth, start = 1, index + 2
            cursor = start
            while cursor < len(statement) and depth:
                if statement[cursor] == "(":
                    depth += 1
                elif statement[cursor] == ")":
                    depth -= 1
                cursor += 1
            body = statement[start:cursor - 1]
            if body.strip():
                inner.append(body)
            index = cursor
            continue
        if statement[index] == "`":
            end = statement.find("`", index + 1)
            if end == -1:
                break
            if statement[index + 1:end].strip():
                inner.append(statement[index + 1:end])
            index = end + 1
            continue
        index += 1
    return inner


def normalize_placeholders(statement):
    for pattern, replacement in _PLACEHOLDER_SUBS:
        statement = pattern.sub(replacement, statement)
    return statement


def tokenize(statement):
    """Tokenize, falling back to a permissive scanner on unbalanced quotes.

    15 of the 183 corpus examples do not survive ``shlex`` once heredocs are
    excised.  Dropping them loses real techniques, so they are kept with
    ``tokenization="lenient"`` and a confidence penalty.
    """
    try:
        return shlex.split(statement, posix=True), "strict"
    except ValueError:
        try:
            lexer = shlex.shlex(statement, posix=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = []
            while True:
                try:
                    token = lexer.get_token()
                except ValueError:
                    break
                if token is None or token == lexer.eof:
                    break
                tokens.append(token)
            return tokens, "lenient"
        except ValueError:
            return statement.split(), "lenient"


#: Keywords that can *precede* a real command on the same statement.  Peeled,
#: not rejected -- `do screencapture -x ...` inside a loop is still a technique.
LEADING_KEYWORDS = {"do", "then", "else", "!", "while", "until", "if", "elif"}


def peel_prefixes(tokens):
    """Strip loop/conditional keywords, sudo/env wrappers and VAR=value pairs."""
    privileged = False
    index = 0
    while index < len(tokens) and tokens[index] in LEADING_KEYWORDS:
        index += 1
    while index < len(tokens):
        token = tokens[index]
        base = token.rsplit("/", 1)[-1]
        if base in PREFIX_COMMANDS:
            if base in ("sudo", "doas"):
                privileged = True
            index += 1
            # Skip the wrapper's own flags and, for `env`, its assignments.
            while index < len(tokens) and (
                    tokens[index].startswith("-") or re.match(r"^\w+=", tokens[index])):
                index += 1
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
            index += 1
            continue
        break
    return tokens[index:], privileged


# ---------------------------------------------------------------------------
# S6-S8: classify tokens and synthesize a pattern
# ---------------------------------------------------------------------------
_GLOB = re.compile(r"[*?]|\[[^\]]+\]")


def classify_token(token, index):
    """Map one token to a match constraint plus the specificity it earns."""
    if WILD in token:
        return None, 0.0, True
    if _GLOB.search(token) and " " not in token:
        # A shell glob is expanded by the shell before exec: the observed argv
        # holds whatever it matched, so the pattern must not require the star.
        return None, 0.0, True
    if token.startswith("-"):
        # A flag whose *value* is glued on (`-u<user>`) keeps only its shape.
        return {"idx": index, "eq": token}, (1.5 if token.startswith("--") else 1.0), False
    alternatives = _alternation_anchor(token)
    if alternatives:
        return {"idx": index, "contains_any": alternatives}, 2.0, False
    if " " in token or "\t" in token:
        # A script/predicate/SQL argument.  Anchor on its leading keywords --
        # `do shell script "id"` and `do shell script "whoami"` are the same
        # technique and must both match.
        anchor = _script_anchor(token)
        if anchor:
            return {"idx": index, "contains": anchor}, 2.0, False
        return None, 0.0, True
    if _URL.match(token) or _IPV4.match(token):
        return None, 0.0, True
    if _NUMBER.match(token) or _B64ISH.match(token) or _HEXISH.match(token):
        return None, 0.0, True
    if _SAMPLE_WORDS.search(token):
        return None, 0.0, True
    if token.startswith(_VOLATILE_PREFIXES):
        # Location is the signal, not the filename: `/tmp/anything`.
        prefix = next(p for p in _VOLATILE_PREFIXES if token.startswith(p))
        return {"idx": index, "startswith": prefix}, 1.0, False
    if token.startswith("/"):
        return {"idx": index, "eq": token}, 2.0, False
    return {"idx": index, "eq": token}, 2.0, False


def _alternation_anchor(token):
    """Pull the alternatives out of a regex-ish argument.

    ``pkill -f "Little Snitch|ESET|osqueryd|Falcon"`` is one of the most
    important signals in the whole corpus -- an adversary killing the endpoint
    agent -- and its entire value lives in that pipe-separated list.  The plain
    word-run anchor throws it away, so alternations get their own handling.
    """
    if "|" not in token:
        return None
    parts = [part.strip().strip("()^$'\"") for part in token.split("|")]
    parts = [p for p in parts if len(p) >= 3 and re.match(r"^[A-Za-z][\w .-]*$", p)
             and WILD not in p]
    return sorted(set(parts)) if len(parts) >= 2 else None


def _script_anchor(token):
    """Longest leading run of plain words from a multi-word argument."""
    words = []
    for word in re.split(r"\s+", token.strip("'\" ")):
        if not word or WILD in word or not re.match(r"^[A-Za-z][A-Za-z0-9_.-]*$", word):
            break
        words.append(word)
        if len(words) >= 4:
            break
    anchor = " ".join(words)
    return anchor if len(anchor) >= 4 and len(words) >= 2 else None


def build_pattern(tokens, binary_names):
    """Turn a token list into an argv pattern, or return ``None`` to reject."""
    tokens, privileged = peel_prefixes(tokens)
    if not tokens:
        return None
    head = tokens[0]
    base = head.rsplit("/", 1)[-1]
    if base in SHELL_KEYWORDS or WILD in base or not base:
        return None
    if base not in binary_names:
        return None  # caller records it as a context token instead

    positional, flags_required, specificity, wildcards = [], [], 0.0, 0
    subcommand = None
    for index, token in enumerate(tokens[1:], start=1):
        constraint, score, is_wild = classify_token(token, index)
        if is_wild:
            wildcards += 1
            continue
        specificity += score
        if constraint and "eq" in constraint and constraint["eq"].startswith("-"):
            flags_required.append(constraint["eq"])
        elif subcommand is None and constraint and "eq" in constraint:
            subcommand = constraint["eq"]
        if constraint:
            positional.append(constraint)

    return {
        "binary": base,
        "exec_path_hint": head if head.startswith("/") else None,
        "subcommand": subcommand,
        "positional": positional,
        "flags_required": sorted(set(flags_required)),
        "min_argc": len(tokens),
        "wildcards": wildcards,
        "specificity": round(specificity, 2),
        "privileged": privileged,
    }


def extract(code, binary_names, depth=0):
    """Full pipeline.  Returns ``(patterns, context_tokens, tokenization)``."""
    lines, bodies = excise_heredocs(clean_lines(code))
    patterns, context = [], []
    tokenization = "strict"
    for line in lines:
        for statement in split_statements(line):
            for inner in extract_substitutions(statement):
                if depth < 2:
                    sub_patterns, sub_context, _ = extract(inner, binary_names, depth + 1)
                    patterns.extend(sub_patterns)
                    context.extend(sub_context)
            tokens, mode = tokenize(normalize_placeholders(statement))
            if mode == "lenient":
                tokenization = "lenient"
            if not tokens:
                continue
            pattern = build_pattern(tokens, binary_names)
            if pattern:
                pattern["nested"] = depth > 0
                patterns.append(pattern)
            else:
                peeled, _ = peel_prefixes(tokens)
                if peeled:
                    head = peeled[0].rsplit("/", 1)[-1]
                    if head and head not in SHELL_KEYWORDS and WILD not in head:
                        context.append(head)
    if depth < 2:
        for body in bodies:
            sub_patterns, sub_context, sub_mode = extract(body, binary_names, depth + 1)
            patterns.extend(sub_patterns)
            context.extend(sub_context)
            if sub_mode == "lenient":
                tokenization = "lenient"
    return patterns, sorted(set(context)), tokenization
