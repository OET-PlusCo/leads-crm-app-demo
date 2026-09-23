#!/usr/bin/env python3
"""
AI Code Security and Quality Review Agent — powered by Antigravity SDK.

Uses deny-by-default policies, agent skills (code-review-and-quality),
structured Pydantic output, and audit hooks. Writes findings to code_review.md.

Designed for GitHub Actions but also runnable locally:
    uv run --project code_review_agent code_review_agent/review_agent.py .
"""

import asyncio
import json
import os
import sys

import pydantic

from google.antigravity import Agent, LocalAgentConfig
from google.antigravity.hooks import hooks, policy
from google.antigravity import types


# ---------------------------------------------------------------------------
# Output schema
# ---------------------------------------------------------------------------

class Finding(pydantic.BaseModel):
    file: str
    line: int
    severity: str   # critical | high | medium | low
    category: str
    description: str
    proposed_fix: str = ""


class ReviewResult(pydantic.BaseModel):
    findings: list[Finding]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = "code_review.md"

SKILLS_PATHS = [
    os.path.join(SCRIPT_DIR, "skills", "code-review-and-quality"),
]

# Deny-by-default: only allow read + git commands
review_policies = [
    policy.deny_all(),
    policy.allow("view_file"),
    policy.allow("list_directory"),
    policy.allow("search_directory"),
    policy.allow("find_file"),
    policy.allow("run_command"),
    policy.allow("finish"),
]


# ---------------------------------------------------------------------------
# Hooks — audit logging + second-layer git-only enforcement
# ---------------------------------------------------------------------------

@hooks.post_tool_call
async def log_tool_results(data: types.ToolResult):
    result_str = str(data.result) if data.result else ""
    preview = result_str[:200] + "..." if len(result_str) > 200 else result_str
    print(
        f"[audit] tool={data.name} result_len={len(result_str)} "
        f"error={data.error} preview={preview}",
        flush=True,
    )


@hooks.pre_tool_call_decide
async def enforce_safe_tools(data: types.ToolCall) -> types.HookResult:
    print(f"[audit] calling tool={data.name} args_keys={list(data.args.keys())}", flush=True)
    if data.name == "run_command":
        cmd = str(data.args.get("CommandLine", ""))
        if not cmd.startswith("git "):
            return types.HookResult(
                allow=False,
                message=f"Only git commands are allowed. Blocked: {cmd}",
            )
    return types.HookResult(allow=True)


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

async def review_code(target_dir: str) -> dict:
    prompt = (
        f"Run `git diff main...HEAD -- ':!.github' ':!code_review_agent'` "
        f"in {target_dir} to get the changes on this branch. "
        "Review ONLY the changed code for security vulnerabilities and code quality issues."
    )

    config_kwargs = dict(
        system_instructions=(
            "You are a code review agent. "
            "You review code diffs for vulnerabilities and quality issues using the loaded skills. "
            "You can run git commands to inspect the diff. "
            "You NEVER modify files."
        ),
        response_schema=ReviewResult,
        skills_paths=SKILLS_PATHS,
        policies=review_policies,
        hooks=[log_tool_results, enforce_safe_tools],
    )

    if os.environ.get("GEMINI_API_KEY"):
        config_kwargs["api_key"] = os.environ["GEMINI_API_KEY"]
    else:
        # Fallback to Vertex AI / Application Default Credentials
        config_kwargs["vertex"] = True
        config_kwargs["project"] = os.environ.get("GOOGLE_CLOUD_PROJECT")
        config_kwargs["location"] = os.environ.get("GOOGLE_CLOUD_LOCATION", "global")

    config = LocalAgentConfig(**config_kwargs)

    async with Agent(config) as agent:
        response = await agent.chat(prompt)

        # Collect final text (reset on each new tool call)
        last_step = -1
        final_text_chunks: list[str] = []
        async for chunk in response.chunks:
            if isinstance(chunk, types.ToolCall):
                final_text_chunks.clear()
            if hasattr(chunk, "text") and hasattr(chunk, "step_index"):
                if chunk.step_index != last_step:
                    final_text_chunks.clear()
                    last_step = chunk.step_index
                final_text_chunks.append(chunk.text)

        final_text = "".join(final_text_chunks)
        if final_text:
            print(final_text)

        # Primary: structured output via SDK finish tool
        data = await response.structured_output()
        if data and "findings" in data:
            return {"findings": data["findings"]}

        # Fallback: parse final text as JSON
        try:
            parsed = json.loads(final_text)
            if isinstance(parsed, list):
                return {"findings": parsed}
            if isinstance(parsed, dict) and "findings" in parsed:
                return {"findings": parsed["findings"]}
        except json.JSONDecodeError:
            pass

    return {"findings": final_text}


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
}


def format_markdown(result: dict) -> str:
    findings = result.get("findings", [])

    if isinstance(findings, str):
        return f"## 🤖 AI Code Security & Quality Review\n\n{findings}\n"

    if not findings:
        return "## 🤖 AI Code Security & Quality Review\n\n✅ No security issues found.\n"

    lines = ["## 🤖 AI Code Security & Quality Review\n"]
    for f in findings:
        emoji = SEVERITY_EMOJI.get(f.get("severity", "").lower(), "⚪")
        severity = f.get("severity", "unknown").upper()
        category = f.get("category", "")
        lines.append(f"### {emoji} [{severity}] {category}\n")
        lines.append(f"**`{f.get('file', '')}` line {f.get('line', '')}**\n")
        lines.append(f"{f.get('description', '')}\n")
        if fix := f.get("proposed_fix", ""):
            lines.append(f"**Proposed fix:** {fix}\n")

    lines.append("\n---\n*Powered by [Antigravity SDK](https://antigravity.dev)*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    target = os.path.abspath(target)

    print(f"🔍 Reviewing changes in: {target}", flush=True)

    result = asyncio.run(review_code(target))
    markdown = format_markdown(result)

    with open(OUTPUT_FILE, "w") as f:
        f.write(markdown)

    print(f"✅ Review written to {OUTPUT_FILE}")
    print(json.dumps(result, indent=2))
