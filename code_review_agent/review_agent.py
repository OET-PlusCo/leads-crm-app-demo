#!/usr/bin/env python3
"""
AI Code Security and Quality Review Agent.
Uses Gemini to review PR diffs and writes findings to code_review.md.
"""

import os
import subprocess
import sys
import textwrap


def get_git_diff(repo_path: str) -> str:
    """Get the diff of the current PR against the base branch."""
    try:
        # Try to get diff against origin/main
        result = subprocess.run(
            ["git", "diff", "origin/main...HEAD", "--", ".", ":(exclude)*.lock", ":(exclude)package-lock.json"],
            capture_output=True,
            text=True,
            cwd=repo_path,
        )
        diff = result.stdout.strip()
        if diff:
            return diff

        # Fallback: diff of the last commit
        result = subprocess.run(
            ["git", "diff", "HEAD~1", "HEAD", "--", ".", ":(exclude)*.lock", ":(exclude)package-lock.json"],
            capture_output=True,
            text=True,
            cwd=repo_path,
        )
        return result.stdout.strip()
    except Exception as e:
        return f"Error getting git diff: {e}"


def get_changed_files(repo_path: str) -> list[str]:
    """Get list of changed files in the PR."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            capture_output=True,
            text=True,
            cwd=repo_path,
        )
        files = result.stdout.strip().splitlines()
        if files:
            return files

        result = subprocess.run(
            ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
            capture_output=True,
            text=True,
            cwd=repo_path,
        )
        return result.stdout.strip().splitlines()
    except Exception:
        return []


def review_with_gemini(diff: str, changed_files: list[str]) -> str:
    """Send the diff to Gemini for code review."""
    from google import genai

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "⚠️ **GEMINI_API_KEY not set** – skipping AI review."

    client = genai.Client(api_key=api_key)

    if not diff:
        return "ℹ️ No code changes detected in this PR."

    # Truncate diff if too large (Gemini has token limits)
    max_diff_chars = 30_000
    truncated = False
    if len(diff) > max_diff_chars:
        diff = diff[:max_diff_chars]
        truncated = True

    files_list = "\n".join(f"- {f}" for f in changed_files) if changed_files else "- (unknown)"

    prompt = textwrap.dedent(f"""
        You are an expert code reviewer specializing in security and code quality.
        Review the following git diff from a pull request and provide a concise, actionable report.

        **Changed files:**
        {files_list}

        **Git Diff:**
        ```diff
        {diff}
        ```
        {"*(Note: diff was truncated due to size)*" if truncated else ""}

        Provide your review in **Markdown** with the following sections:

        ## 🔒 Security Findings
        List any security issues (injection risks, secrets exposure, insecure dependencies, auth issues, etc.).
        Use severity labels: 🔴 Critical, 🟠 High, 🟡 Medium, 🟢 Low.
        If none found, write "No security issues detected."

        ## 🧹 Code Quality
        List code quality issues (error handling, code duplication, naming, complexity, missing tests, etc.).
        If none found, write "Code quality looks good."

        ## ✅ Summary
        A 2-3 sentence overall assessment of the changes.

        Be specific and reference file names and line numbers when possible.
        Keep the tone constructive and professional.
    """).strip()

    response = client.models.generate_content(
        model="gemini-3.8-flash",
        contents=prompt,
    )
    return response.text


def write_report(findings: str, repo_path: str) -> None:
    """Write the review findings to code_review.md in the repo root."""
    pr_number = os.environ.get("GITHUB_REF", "").replace("refs/pull/", "").replace("/merge", "")
    sha = os.environ.get("GITHUB_SHA", "")[:7] if os.environ.get("GITHUB_SHA") else ""

    header = "## 🤖 AI Code Security & Quality Review\n\n"
    if pr_number or sha:
        meta = []
        if pr_number:
            meta.append(f"**PR:** #{pr_number}")
        if sha:
            meta.append(f"**Commit:** `{sha}`")
        header += " · ".join(meta) + "\n\n"

    output_path = os.path.join(repo_path, "code_review.md")
    with open(output_path, "w") as f:
        f.write(header + findings + "\n")

    print(f"✅ Review written to {output_path}")


def main() -> None:
    repo_path = sys.argv[1] if len(sys.argv) > 1 else "."
    repo_path = os.path.abspath(repo_path)

    print(f"🔍 Reviewing changes in: {repo_path}")

    diff = get_git_diff(repo_path)
    changed_files = get_changed_files(repo_path)

    print(f"📄 Changed files: {', '.join(changed_files) if changed_files else 'none detected'}")
    print(f"📏 Diff size: {len(diff)} chars")

    findings = review_with_gemini(diff, changed_files)
    write_report(findings, repo_path)


if __name__ == "__main__":
    main()
