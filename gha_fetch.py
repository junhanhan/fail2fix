#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
升级版：只抓失败 job 的日志，减少噪声
"""

import os
import io
import sys
import zipfile
import requests
from pathlib import Path


def get_failed_jobs(owner, name, run_id, headers):
    """获取失败的 job 列表"""
    url = f"https://api.github.com/repos/{owner}/{name}/actions/runs/{run_id}/jobs"
    r = requests.get(url, headers=headers, timeout=60)
    if r.status_code != 200:
        print(f"Failed to fetch jobs: {r.status_code}", file=sys.stderr)
        return []
    
    jobs = r.json().get("jobs", [])
    failed = [j for j in jobs if j.get("conclusion") == "failure"]
    return [j["name"] for j in failed]


def main():
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    token = os.environ.get("GITHUB_TOKEN")

    if not repo or not run_id or not token:
        print("Missing env: GITHUB_REPOSITORY / GITHUB_RUN_ID / GITHUB_TOKEN", file=sys.stderr)
        sys.exit(2)

    owner, name = repo.split("/", 1)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # 1. 获取失败的 job 名称
    failed_jobs = get_failed_jobs(owner, name, run_id, headers)
    print(f"Failed jobs: {failed_jobs}", file=sys.stderr)

    # 2. 下载 logs zip
    url = f"https://api.github.com/repos/{owner}/{name}/actions/runs/{run_id}/logs"
    r = requests.get(url, headers=headers, timeout=60)
    if r.status_code != 200:
        print(f"Failed to download logs zip: {r.status_code} {r.text[:200]}", file=sys.stderr)
        sys.exit(3)

    z = zipfile.ZipFile(io.BytesIO(r.content))
    out_dir = Path("run_logs")
    out_dir.mkdir(exist_ok=True)
    z.extractall(out_dir)

    # 3. 只合并失败 job 的日志
    txt_files = sorted(out_dir.rglob("*.txt"))
    if not txt_files:
        print("No .txt logs found in logs zip", file=sys.stderr)
        sys.exit(4)

    # 如果有失败 job，只选相关的；否则全量合并
    if failed_jobs:
        # 简单匹配：文件名包含 job 名的任意部分
        selected = []
        for p in txt_files:
            path_str = p.as_posix().lower()
            if any(job.lower().replace(" ", "-") in path_str for job in failed_jobs):
                selected.append(p)
        
        if selected:
            txt_files = selected
            print(f"Filtered to {len(txt_files)} files from failed jobs", file=sys.stderr)

    with open("ci.log", "w", encoding="utf-8", errors="replace") as w:
        for p in txt_files:
            w.write(f"\n\n===== {p.as_posix()} =====\n")
            w.write(p.read_text(encoding="utf-8", errors="replace"))

    print(f"Merged {len(txt_files)} log files into ci.log")


if __name__ == "__main__":
    main()
