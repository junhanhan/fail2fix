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
      - repro_cmd: 复现命令
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
            # 生成复现命令
            meta["repro_cmd"] = f"pytest -xvs {test_id}"
            break

    # 2) file:line: ... pattern
    file_line_pat = re.compile(r'^(.+):(\d+):\s+')
    for line in snippet_lines:
        m = file_line_pat.match(line.strip())
        if m:
            meta["file"] = meta.get("file") or m.group(1)
            meta["line"] = int(m.group(2))
            break

    # 3) 如果没有 test_id，生成默认复现命令
    if "repro_cmd" not in meta:
        if meta.get("file"):
            meta["repro_cmd"] = f"pytest -xvs {meta['file']}"
        else:
            meta["repro_cmd"] = "pytest -xvs"

    return meta


def generate_suspects(signature: str, snippet_lines: List[str], metadata: dict) -> List[str]:
    """
    生成怀疑点 Top3（规则版，不用 AI）
    """
    suspects = []
    sig_lower = signature.lower()
    
    # AssertionError：类型/比较逻辑
    if "assert" in sig_lower or "assertion" in sig_lower:
        suspects.append("🔍 类型不匹配或比较逻辑错误（检查 assert 语句两侧的类型）")
        suspects.append("🔍 预期值与实际值不一致（检查测试数据或业务逻辑）")
        suspects.append("🔍 边界条件未覆盖（检查空值、零值、极端值处理）")
    
    # ModuleNotFoundError：依赖/requirements
    elif "modulenotfound" in sig_lower or "importerror" in sig_lower:
        suspects.append("🔍 缺少依赖包（检查 requirements.txt 或 package.json）")
        suspects.append("🔍 Python 路径问题（检查 PYTHONPATH 或相对导入）")
        suspects.append("🔍 虚拟环境未激活或依赖未安装（运行 pip install -r requirements.txt）")
    
    # Timeout：外部依赖/网络/并发
    elif "timeout" in sig_lower or "oom" in sig_lower or "killed" in sig_lower:
        suspects.append("🔍 外部服务响应慢或不可达（检查网络连接、API 端点）")
        suspects.append("🔍 资源限制（内存不足、CPU 超载、并发过高）")
        suspects.append("🔍 死锁或无限循环（检查异步代码、锁机制）")
    
    # TypeScript/编译错误
    elif "ts" in sig_lower or "build:error" in sig_lower:
        suspects.append("🔍 类型定义错误（检查 TypeScript 类型声明）")
        suspects.append("🔍 语法错误或 API 变更（检查最近的代码改动）")
        suspects.append("🔍 依赖版本不兼容（检查 package.json 版本锁定）")
    
    # npm/yarn 错误
    elif "npm" in sig_lower or "yarn" in sig_lower or "pnpm" in sig_lower:
        suspects.append("🔍 依赖安装失败（检查 package.json 和 lock 文件）")
        suspects.append("🔍 版本冲突或 registry 问题（尝试清除缓存重新安装）")
        suspects.append("🔍 权限或网络问题（检查 npm registry 可达性）")
    
    # Python traceback
    elif "py:" in sig_lower and "error" in sig_lower:
        suspects.append("🔍 运行时异常（检查堆栈跟踪中的具体错误行）")
        suspects.append("🔍 数据验证失败（检查输入数据格式和边界条件）")
        suspects.append("🔍 环境配置问题（检查环境变量、配置文件）")
    
    # 默认通用建议
    else:
        suspects.append("🔍 检查最近的代码变更（git diff）")
        suspects.append("🔍 本地复现问题（使用下方复现命令）")
        suspects.append("🔍 查看完整日志（下载 Artifacts 中的 ci.log）")
    
    return suspects[:3]  # 最多返回 3 条


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
            "suspects": [],
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
    suspects = generate_suspects(best.signature, snippet, metadata)

    return {
        "ok": True,
        "fatal_snippet": snippet,
        "error_signature": best.signature,
        "confidence": best.confidence,
        "reason": best.reason,
        "metadata": metadata,
        "suspects": suspects,
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
