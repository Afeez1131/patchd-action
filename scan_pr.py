#!/usr/bin/env python3
"""Patchd GitHub Action — AI-powered security scanning for every PR."""

import base64
import json
import os
import sys
from pathlib import Path

import requests

# Configuration

_REQUIRED = ["PATCHD_API_KEY", "GITHUB_TOKEN", "GITHUB_REPOSITORY", "GITHUB_EVENT_PATH"]
_missing = [v for v in _REQUIRED if not os.environ.get(v)]
if _missing:
    print(f"❌ Missing required environment variables: {', '.join(_missing)}")
    print("   Make sure PATCHD_API_KEY is set in your GitHub Actions secrets.")
    sys.exit(1)

PATCHD_API_URL = os.environ.get("PATCHD_API_URL", "https://api.patchd.dev").rstrip("/")
PATCHD_API_KEY = os.environ["PATCHD_API_KEY"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPOSITORY = os.environ["GITHUB_REPOSITORY"]  # "owner/repo"
GITHUB_EVENT_PATH = os.environ["GITHUB_EVENT_PATH"]
FAIL_ON_CRITICAL = os.environ.get("FAIL_ON_CRITICAL", "true").lower() == "true"
MAX_FILES = int(os.environ.get("MAX_FILES", "15"))
FILE_EXTENSIONS = set(
    os.environ.get(
        "FILE_EXTENSIONS", ".py,.js,.ts,.go,.java,.php,.rb,.rs,.jsx,.tsx,.sh,.sql"
    ).split(",")
)

GH_API = "https://api.github.com"

EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".sh": "bash",
    ".sql": "sql",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
}

# HTTP sessions


def gh_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    return s


def patchd_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "X-API-Key": PATCHD_API_KEY,
            "Content-Type": "application/json",
        }
    )
    return s


# GitHub helpers


def load_event() -> dict:
    with open(GITHUB_EVENT_PATH) as f:
        return json.load(f)


def get_pr_number(event: dict) -> int:
    return event["pull_request"]["number"]


def get_pr_head_sha(event: dict) -> str:
    return event["pull_request"]["head"]["sha"]


def get_pr_title(event: dict) -> str:
    return event["pull_request"].get("title", "")


def get_pr_files(gh: requests.Session, owner: str, repo: str, pr: int) -> list[dict]:
    url = f"{GH_API}/repos/{owner}/{repo}/pulls/{pr}/files"
    resp = gh.get(url, params={"per_page": 100}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_file_content(gh: requests.Session, contents_url: str) -> str | None:
    # Use the GitHub Contents API (base64-encoded) — works for both public and private repos
    resp = gh.get(contents_url, timeout=30)
    if resp.status_code != 200:
        print(f"    ⚠️  contents_url returned {resp.status_code}")
        return None
    data = resp.json()
    if data.get("encoding") != "base64" or not data.get("content"):
        return None
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def post_pr_comment(
    gh: requests.Session, owner: str, repo: str, pr: int, body: str
) -> None:
    url = f"{GH_API}/repos/{owner}/{repo}/issues/{pr}/comments"
    resp = gh.post(url, json={"body": body}, timeout=30)
    resp.raise_for_status()


def create_check_run(
    gh: requests.Session,
    owner: str,
    repo: str,
    sha: str,
    conclusion: str,
    title: str,
    summary: str,
    annotations: list[dict],
) -> None:
    """Create a GitHub Check Run. Handles the 50-annotation-per-request limit."""
    url = f"{GH_API}/repos/{owner}/{repo}/check-runs"
    payload = {
        "name": "Patchd Security Scan",
        "head_sha": sha,
        "status": "completed",
        "conclusion": conclusion,
        "output": {
            "title": title,
            "summary": summary,
            "annotations": annotations[:50],
        },
    }
    resp = gh.post(url, json=payload, timeout=30)
    resp.raise_for_status()

    if len(annotations) > 50:
        check_id = resp.json()["id"]
        for i in range(50, len(annotations), 50):
            batch = annotations[i : i + 50]
            gh.patch(
                f"{GH_API}/repos/{owner}/{repo}/check-runs/{check_id}",
                json={
                    "output": {"title": title, "summary": summary, "annotations": batch}
                },
                timeout=30,
            )


def set_action_outputs(critical_count: int, warnings_count: int) -> None:
    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"critical_count={critical_count}\n")
            f.write(f"warnings_count={warnings_count}\n")


# Patchd scanning


def scan_file(
    patchd: requests.Session, filename: str, code: str, pr_title: str
) -> dict | None:
    ext = Path(filename).suffix.lower()
    language = EXTENSION_TO_LANGUAGE.get(ext)

    payload: dict = {
        "code": code[:50000],
        "context": f"PR: {pr_title} — file: {filename}",
    }
    if language:
        payload["language"] = language

    try:
        resp = patchd.post(f"{PATCHD_API_URL}/api/analyze", json=payload, timeout=120)
    except requests.Timeout:
        print(f"    ⚠️  Scan timed out for {filename}")
        return None

    if resp.status_code != 200:
        print(
            f"    ⚠️  Scan failed for {filename}: HTTP {resp.status_code} — {resp.text[:200]}"
        )
        return None

    return resp.json()


# Formatting


def _format_issue(issue: dict) -> str:
    lines = [f"**{issue['title']}**"]
    if issue.get("what"):
        lines.append(f"> **What:** {issue['what']}")
    if issue.get("how"):
        lines.append(f"> **How:** {issue['how']}")
    if issue.get("impact"):
        lines.append(f"> **Impact:** {issue['impact']}")
    if issue.get("fix"):
        lines.append(f"> **Fix:** `{issue['fix']}`")
    return "\n".join(lines)


def build_file_comment(filename: str, result: dict) -> str:
    critical = result.get("critical", [])
    warnings = result.get("warnings", [])
    best_practices = result.get("best_practices", [])

    if not (critical or warnings or best_practices):
        return f"## ✅ Patchd — `{filename}`\n\nNo issues found."

    lines = [f"## 🔍 Patchd Security Scan — `{filename}`\n"]

    if critical:
        lines.append(f"### 🚨 Critical Issues ({len(critical)})\n")
        for issue in critical:
            lines.append(_format_issue(issue))
            lines.append("\n---\n")

    if warnings:
        lines.append(f"### ⚠️ Warnings ({len(warnings)})\n")
        for issue in warnings:
            lines.append(_format_issue(issue))
            lines.append("\n---\n")

    if best_practices:
        lines.append(f"### 💡 Best Practices ({len(best_practices)})\n")
        for issue in best_practices:
            lines.append(_format_issue(issue))
            lines.append("\n---\n")

    return "\n".join(lines)


def build_summary_comment(file_results: list[dict]) -> str:
    total_critical = sum(len(r["result"].get("critical", [])) for r in file_results)
    total_warnings = sum(len(r["result"].get("warnings", [])) for r in file_results)

    lines = ["## 🔐 Patchd Security Scan Results\n"]
    lines.append("| File | Critical | Warnings | Best Practices |")
    lines.append("|------|----------|----------|----------------|")

    for fr in file_results:
        res = fr["result"]
        crit = len(res.get("critical", []))
        warn = len(res.get("warnings", []))
        bp = len(res.get("best_practices", []))
        crit_cell = f"🚨 {crit}" if crit else "✅ 0"
        warn_cell = f"⚠️ {warn}" if warn else "0"
        bp_cell = f"💡 {bp}" if bp else "0"
        lines.append(f"| `{fr['filename']}` | {crit_cell} | {warn_cell} | {bp_cell} |")

    lines.append("")
    if total_critical:
        lines.append(
            f"**Total: {total_critical} critical issue{'s' if total_critical != 1 else ''} "
            f"and {total_warnings} warning{'s' if total_warnings != 1 else ''} found.**"
        )
    else:
        lines.append("**No critical issues found. ✅**")

    lines.append("")
    lines.append(
        "> Powered by [Patchd](https://patchd.dev) — AI security scanning for founders"
    )
    return "\n".join(lines)


def build_annotations(file_results: list[dict]) -> list[dict]:
    annotations = []
    for fr in file_results:
        filename = fr["filename"]
        result = fr["result"]

        for issue in result.get("critical", []):
            annotations.append(
                {
                    "path": filename,
                    "start_line": 1,
                    "end_line": 1,
                    "annotation_level": "failure",
                    "title": issue["title"],
                    "message": (
                        f"{issue.get('what', '')}\n\n"
                        f"Impact: {issue.get('impact', '')}\n\n"
                        f"Fix: {issue.get('fix', '')}"
                    ),
                }
            )

        for issue in result.get("warnings", []):
            annotations.append(
                {
                    "path": filename,
                    "start_line": 1,
                    "end_line": 1,
                    "annotation_level": "warning",
                    "title": issue["title"],
                    "message": (
                        f"{issue.get('what', '')}\n\n" f"Fix: {issue.get('fix', '')}"
                    ),
                }
            )

        for issue in result.get("best_practices", []):
            annotations.append(
                {
                    "path": filename,
                    "start_line": 1,
                    "end_line": 1,
                    "annotation_level": "notice",
                    "title": issue["title"],
                    "message": issue.get("what", ""),
                }
            )

    return annotations


# Main


def main() -> int:
    owner, repo = GITHUB_REPOSITORY.split("/", 1)

    gh = gh_session()
    patchd = patchd_session()

    event = load_event()
    pr_number = get_pr_number(event)
    pr_head_sha = get_pr_head_sha(event)
    pr_title = get_pr_title(event)

    print(f"🔍 Patchd Security Scan — {owner}/{repo} PR #{pr_number}")

    # Fetch and filter changed files
    pr_files = get_pr_files(gh, owner, repo, pr_number)
    scannable = [
        f
        for f in pr_files
        if f["status"] != "removed"
        and Path(f["filename"]).suffix.lower() in FILE_EXTENSIONS
    ][:MAX_FILES]

    if not scannable:
        print("ℹ️  No scannable code files changed in this PR.")
        set_action_outputs(0, 0)
        return 0

    skipped = len(pr_files) - len(scannable)
    if skipped:
        print(
            f"📁 Scanning {len(scannable)} file(s) ({skipped} skipped — not code or limit reached)"
        )
    else:
        print(f"📁 Scanning {len(scannable)} file(s)")

    file_results = []
    for pr_file in scannable:
        filename = pr_file["filename"]
        print(f"  → {filename}")

        code = get_file_content(gh, pr_file["contents_url"])
        if not code:
            print(f"    ⚠️  Could not fetch content, skipping.")
            continue

        result = scan_file(patchd, filename, code, pr_title)
        if result is None:
            continue

        crit_count = len(result.get("critical", []))
        warn_count = len(result.get("warnings", []))
        print(f"    🚨 {crit_count} critical  ⚠️  {warn_count} warnings")
        file_results.append({"filename": filename, "result": result})

    if not file_results:
        print("ℹ️  No results to report.")
        set_action_outputs(0, 0)
        return 0

    total_critical = sum(len(r["result"].get("critical", [])) for r in file_results)
    total_warnings = sum(len(r["result"].get("warnings", [])) for r in file_results)

    print(f"\n📝 Posting results to PR #{pr_number}...")

    # Per-file comments (only files with issues)
    for fr in file_results:
        if fr["result"].get("critical") or fr["result"].get("warnings"):
            body = build_file_comment(fr["filename"], fr["result"])
            post_pr_comment(gh, owner, repo, pr_number, body)

    # Summary comment
    summary_body = build_summary_comment(file_results)
    post_pr_comment(gh, owner, repo, pr_number, summary_body)

    # Check Run with inline annotations
    annotations = build_annotations(file_results)
    conclusion = "failure" if (total_critical > 0 and FAIL_ON_CRITICAL) else "success"
    check_title = (
        f"Found {total_critical} critical issue{'s' if total_critical != 1 else ''}"
        if total_critical
        else "No critical issues found"
    )
    create_check_run(
        gh, owner, repo, pr_head_sha, conclusion, check_title, summary_body, annotations
    )

    # Set outputs for downstream steps
    set_action_outputs(total_critical, total_warnings)

    status_icon = "❌" if total_critical else "✅"
    print(
        f"\n{status_icon} Done — {total_critical} critical, {total_warnings} warnings across {len(file_results)} file(s)."
    )

    return 1 if (total_critical > 0 and FAIL_ON_CRITICAL) else 0


if __name__ == "__main__":
    sys.exit(main())
