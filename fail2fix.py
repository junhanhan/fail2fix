#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import re
import json
from dataclasses import dataclass
from typing import List, Optional


MAX_SNIPPET_LINES = 40
PRE_CONTEXT = 10
POST_CONTEXT = 30


@dataclass
class Candidate:
    score: int
    confidence: str  # "high" | "medium" | "low"
    signature: str
    snippet_lines: List[str]
    reason: str


def _clamp_window(lines: List[str], center_idx: int, pre: int, post: int, max_lines: int) -> List[str]:
    start = max(0, center_idx - pre)
    end = min(len(lines), center_idx + post + 1)
    window = lines[start:end]
    if len(window) <= max_lines:
        return window
    # Prefer tail where errors typically appear
    return window[-max_lines:]


def _sanitize(lines: List[str]) -> List[str]:
    # Best-effort secret redaction
    redacted = []
    secret_patterns = [
        (re.compile(r'(?i)(token|secret|password|passwd|api[_-]?key)\s*[:=]\s*([^\s]+)'), r'\1=<REDACTED>'),
        (re.compile(r'(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-_\.=]+'), 'Authorization: Bearer <REDACTED>'),
    ]
    for line in lines:
        s = line
        for pat, rep in secret_patterns:
            s = pat.sub(rep, s)
        redacted.append(s)
    return redacted


def _make_signature(prefix: str, core: str) -> str:
    core = core.strip()
    core = re.sub(r'\s+', ' ', core)
    core = core[:120]
    return f"{prefix}:{core}" if core else f"{prefix}:unknown"


def _truncate_after_pytest_summary(snippet: List[str]) -> List[str]:
    """
    If snippet contains pytest summary markers, truncate soon after that.
    Purpose: keep snippet "causally closed" and avoid unrelated tail noise.
    """
    stop_markers = [
        "=========================== short test summary info",
        "FAILED ",
        "========================= 1 failed",
        "========================= 2 failed",
        "========================= 3 failed",
        "========================= 4 failed",
        "========================= 5 failed",
    ]
    last_idx = None
    for i, line in enumerate(snippet):
        if any(m in line for m in stop_markers):
            last_idx = i

    if last_idx is None:
        return snippet

    # Keep at most 1 extra line after the last marker
    end = min(len(snippet), last_idx + 2)
    return snippet[:end]


def extract_metadata_from_snippet(snippet_lines: List[str]) -> dict:
    """
    Extract minimal metadata for later context collection:
      - pytest test_id: tests/x.py::test_name
      - file path + line number: tests/x.py:42: ...
    """
    meta = {}

    # 1) pytest failing test id: "FAILED path::test_name - ..."
    for line in snippet_lines:
        if line.startswith("FAILED "):
            rest = line[len("FAILED "):].strip()
            test_id = rest.split(" - ", 1)[0].strip()
            meta["test_id"] = test_id
            if "::" in test_id:
                meta["file"] = test_id.split("::", 1)[0]
            else:
                meta["file"] = test_id
            break

    # 2) file:line: ... pattern
    file_line_pat = re.compile(r'^(.+):(\d+):\s+')
    for line in snippet_lines:
        m = file_line_pat.match(line.strip())
        if m:
            meta["file"] = meta.get("file") or m.group(1)
            meta["line"] = int(m.group(2))
            break

    return meta


def _python_traceback_candidate(lines: List[str]) -> Optional[Candidate]:
    # Anchor: "Traceback (most recent call last):"
    try:
        start = next(i for i, l in enumerate(lines) if "Traceback (most recent call last):" in l)
    except StopIteration:
        return None

    # Find exception line within next ~120 lines
    end_search = lines[start:start + 120]
    exc_idx = None
    exc_line = ""

    exc_pat = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(Error|Exception)\s*:\s*.+')
    modnot_pat = re.compile(r'^ModuleNotFoundError\s*:\s*No module named\s+[\'"].+[\'"]')
    import_pat = re.compile(r'^(ImportError)\s*:\s*.+')

    for j, l in enumerate(end_search):
        s = l.strip()
        if exc_pat.match(s) or modnot_pat.match(s) or import_pat.match(s):
            exc_idx = start + j
            exc_line = s

    if exc_idx is None:
        snippet = lines[start:start + MAX_SNIPPET_LINES]
        sig = _make_signature("py:Traceback", "no-exception-line-found")
        return Candidate(score=10, confidence="medium", signature=sig, snippet_lines=snippet, reason="python_traceback_no_exception")

    # Determine subtype + signature
    if "ModuleNotFoundError" in exc_line:
        prefix = "py:ModuleNotFoundError"
        m = re.search(r"No module named\s+[\'\"]([^\'\"]+)[\'\"]", exc_line)
        core = m.group(1) if m else exc_line
        sig = _make_signature(prefix, core)
        score = 18
        conf = "high"
    elif exc_line.startswith("ImportError"):
        sig = _make_signature("py:ImportError", exc_line)
        score = 16
        conf = "high"
    else:
        err_cls = exc_line.split(":", 1)[0]
        msg = exc_line.split(":", 1)[1] if ":" in exc_line else exc_line
        sig = _make_signature(f"py:{err_cls}", msg)
        score = 15
        conf = "high"

    snippet = _clamp_window(lines, exc_idx, PRE_CONTEXT, POST_CONTEXT, MAX_SNIPPET_LINES)
    return Candidate(score=score, confidence=conf, signature=sig, snippet_lines=snippet, reason="python_traceback")


def _assertion_candidate(lines: List[str]) -> Optional[Candidate]:
    # Works for pytest/jest/etc. Look for assertion keywords (tail-first)
    keywords = ["AssertionError", "assertion failed", "Expected:", "Received:", "toBe(", "toEqual(", "assert "]

    idx = None
    hit = ""

    for i in range(len(lines) - 1, -1, -1):
        s = lines[i]
        ls = s.lower()
        if any(k.lower() in ls for k in keywords):
            idx = i
            hit = s.strip()
            break

    if idx is None:
        return None

    sig = _make_signature("assert", hit if hit else "assertion")
    snippet = _clamp_window(lines, idx, PRE_CONTEXT, POST_CONTEXT, MAX_SNIPPET_LINES)
    snippet = _truncate_after_pytest_summary(snippet)

    return Candidate(score=12, confidence="medium", signature=sig, snippet_lines=snippet, reason="assertion_like")


def _npm_err_candidate(lines: List[str]) -> Optional[Candidate]:
    anchors = ["npm ERR!", "ERR_PNPM", "yarn error", "pnpm:"]
    idx = None
    hit = ""
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i]
        ls = s.lower()
        if any(a.lower() in ls for a in anchors):
            idx = i
            hit = s.strip()
            break
    if idx is None:
        return None

    core = hit
    m = re.search(r'\b(E[A-Z0-9_]+)\b', hit)
    if m:
        core = m.group(1)

    sig = _make_signature("node:npm", core)
    snippet = _clamp_window(lines, idx, PRE_CONTEXT, POST_CONTEXT, MAX_SNIPPET_LINES)
    return Candidate(score=14, confidence="high", signature=sig, snippet_lines=snippet, reason="npm_err")


def _compiler_error_candidate(lines: List[str]) -> Optional[Candidate]:
    patterns = [
        re.compile(r'.+:\d+:\d+:\s*error:\s+.+', re.IGNORECASE),
        re.compile(r'error\s+TS\d{3,5}\s*:\s+.+', re.IGNORECASE),
        re.compile(r'.+:\d+:\s*error:\s+.+', re.IGNORECASE),
    ]
    idx = None
    hit = ""
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i].strip()
        if any(pat.search(s) for pat in patterns):
            idx = i
            hit = s
            break
    if idx is None:
        return None

    m = re.search(r'(TS\d{3,5})', hit)
    if m:
        sig = _make_signature("ts", m.group(1))
    else:
        core = hit.split("error:", 1)[0].strip() if "error:" in hit else hit[:80]
        sig = _make_signature("build:error", core)

    snippet = _clamp_window(lines, idx, PRE_CONTEXT, POST_CONTEXT, MAX_SNIPPET_LINES)
    return Candidate(score=14, confidence="high", signature=sig, snippet_lines=snippet, reason="compiler_error")


def _timeout_oom_candidate(lines: List[str]) -> Optional[Candidate]:
    keys = ["timed out", "timeout", "killed", "oom", "out of memory", "signal: killed", "exit code 137"]
    idx = None
    hit = ""
    for i in range(len(lines) - 1, -1, -1):
        s = lines[i]
        ls = s.lower()
        if any(k in ls for k in keys):
            idx = i
            hit = s.strip()
            break
    if idx is None:
        return None

    sig = _make_signature("infra:timeout_oom", hit)
    snippet = _clamp_window(lines, idx, PRE_CONTEXT, POST_CONTEXT, MAX_SNIPPET_LINES)
    return Candidate(score=11, confidence="medium", signature=sig, snippet_lines=snippet, reason="timeout_oom_like")


def _fallback_candidate(lines: List[str]) -> Candidate:
    idx = None
    for i in range(len(lines) - 1, -1, -1):
        ls = lines[i].lower()
        if "error" in ls or "failed" in ls or "exception" in ls:
            idx = i
            break

    if idx is None:
        snippet = lines[-MAX_SNIPPET_LINES:] if len(lines) > MAX_SNIPPET_LINES else lines[:]
        sig = _make_signature("unknown", "no_anchor_found")
        return Candidate(score=1, confidence="low", signature=sig, snippet_lines=snippet, reason="fallback_tail")

    snippet = _clamp_window(lines, idx, PRE_CONTEXT, POST_CONTEXT, MAX_SNIPPET_LINES)
    sig = _make_signature("unknown", lines[idx].strip())
    return Candidate(score=2, confidence="low", signature=sig, snippet_lines=snippet, reason="fallback_keyword")


def extract_fatal(text: str) -> dict:
    lines = text.splitlines()
    if not lines:
        return {
            "ok": False,
            "error": "empty_input",
            "fatal_snippet": [],
            "error_signature": "empty",
            "confidence": "low",
            "reason": "no_lines",
            "metadata": {},
        }

    candidates: List[Candidate] = []

    for fn in [
        _python_traceback_candidate,
        _compiler_error_candidate,
        _npm_err_candidate,
        _assertion_candidate,
        _timeout_oom_candidate,
    ]:
        c = fn(lines)
        if c is not None:
            candidates.append(c)

    best = max(candidates, key=lambda x: x.score) if candidates else _fallback_candidate(lines)

    snippet = _sanitize(best.snippet_lines)
    metadata = extract_metadata_from_snippet(snippet)

    return {
        "ok": True,
        "fatal_snippet": snippet,
        "error_signature": best.signature,
        "confidence": best.confidence,
        "reason": best.reason,
        "metadata": metadata,
        "lines_in_input": len(lines),
        "lines_in_snippet": len(snippet),
    }


def main():
    # Read from stdin until EOF
    raw = sys.stdin.read()
    result = extract_fatal(raw)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
