#!/usr/bin/env python3
"""
Generate a triage prompt from security scan results.

Reads JSON scan results from:
- resultados/scan-before/bandit-results.json
- resultados/scan-before/semgrep-results.json
- resultados/scan-before/pip-audit-results.json
- resultados/scan-before/gitleaks-results.json

Generates a markdown triage prompt at:
- resultados/prompts/triage-prompt.md
"""

import json
import sys
from pathlib import Path

SCAN_DIR = Path("resultados/scan-before")
PROMPT_DIR = Path("resultados/prompts")
PROMPT_FILE = PROMPT_DIR / "triage-prompt.md"

BANDIT_FILE = SCAN_DIR / "bandit-results.json"
SEMGREP_FILE = SCAN_DIR / "semgrep-results.json"
PIP_AUDIT_FILE = SCAN_DIR / "pip-audit-results.json"
GITLEAKS_FILE = SCAN_DIR / "gitleaks-results.json"

SEVERITY_ORDER = {"HIGH": 0, "ERROR": 0, "MEDIUM": 1, "WARNING": 1, "LOW": 2, "INFO": 2}


def load_json(filepath):
    """Load JSON file, return None if missing or empty."""
    if not filepath.exists():
        print(f"Warning: {filepath} does not exist, skipping", file=sys.stderr)
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                print(f"Warning: {filepath} is empty, skipping", file=sys.stderr)
                return None
            return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Warning: Failed to parse {filepath}: {e}, skipping", file=sys.stderr)
        return None


def get_source_snippet(filepath, line_number, context=3):
    """
    Extract code snippet from source file with context lines.
    Returns (snippet, language) or (None, None) if file not found or line out of bounds.
    """
    if not filepath.exists():
        return None, None

    # Determine language from extension
    ext = filepath.suffix.lower()
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
        ".cs": "csharp",
        ".cpp": "cpp",
        ".c": "c",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".html": "html",
        ".css": "css",
        ".sql": "sql",
        ".sh": "bash",
    }
    language = lang_map.get(ext, "text")

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            lines = f.readlines()

        total_lines = len(lines)
        start = max(0, line_number - 1 - context)
        end = min(total_lines, line_number + context)

        if line_number > total_lines:
            return None, None

        snippet_lines = lines[start:end]
        snippet = "".join(snippet_lines)

        # Add line numbers for reference
        numbered_lines = []
        for i, line in enumerate(snippet_lines, start=start + 1):
            marker = ">>> " if i == line_number else "    "
            numbered_lines.append(f"{marker}{i:4d} | {line.rstrip()}")

        return "\n".join(numbered_lines), language
    except (IOError, UnicodeDecodeError) as e:
        print(f"Warning: Could not read {filepath}: {e}", file=sys.stderr)
        return None, None


def parse_bandit(data):
    """Parse bandit results and return list of findings."""
    findings = []
    results = data.get("results", []) if data else []

    for result in results:
        filename = result.get("filename", "")
        # Strip .// prefix if present
        if filename.startswith("./"):
            filename = filename[2:]

        line_number = result.get("line_number", 0)
        severity = result.get("issue_severity", "LOW")
        description = result.get("issue_text", "No description")
        test_id = result.get("test_id", "")
        more_info = result.get("more_info", "")

        filepath = Path(filename)
        snippet, language = get_source_snippet(filepath, line_number)

        findings.append(
            {
                "tool": "bandit",
                "severity": severity,
                "filename": filename,
                "line_number": line_number,
                "description": description,
                "test_id": test_id,
                "more_info": more_info,
                "snippet": snippet,
                "language": language,
            }
        )

    return findings


def parse_semgrep(data):
    """Parse semgrep results and return list of findings."""
    findings = []
    results = data.get("results", []) if data else []

    for result in results:
        path = result.get("path", "")
        start = result.get("start", {})
        line_number = start.get("line", 0)
        extra = result.get("extra", {})
        severity = extra.get("severity", "INFO")
        message = extra.get("message", "No description")
        check_id = result.get("check_id", "")

        filepath = Path(path)
        snippet, language = get_source_snippet(filepath, line_number)

        findings.append(
            {
                "tool": "semgrep",
                "severity": severity,
                "filename": path,
                "line_number": line_number,
                "description": message,
                "test_id": check_id,
                "more_info": "",
                "snippet": snippet,
                "language": language,
            }
        )

    return findings


def parse_pip_audit(data):
    """Parse pip-audit results and return list of findings."""
    findings = []
    dependencies = data.get("dependencies", []) if data else []

    for dep in dependencies:
        name = dep.get("name", "")
        version = dep.get("version", "")
        vulns = dep.get("vulns", [])

        for vuln in vulns:
            vuln_id = vuln.get("id", "")
            fix_versions = vuln.get("fix_versions", [])
            aliases = vuln.get("aliases", [])
            description = vuln.get("description", "No description")

            # Extract CVE IDs from aliases
            cve_ids = [a for a in aliases if a.startswith("CVE-")]

            findings.append(
                {
                    "tool": "pip-audit",
                    "severity": "HIGH" if cve_ids else "MEDIUM",
                    "package": name,
                    "version": version,
                    "vuln_id": vuln_id,
                    "cve_ids": cve_ids,
                    "fix_versions": fix_versions,
                    "description": description,
                }
            )

    return findings


def parse_gitleaks(data):
    """Parse gitleaks results and return list of findings."""
    findings = []
    if not isinstance(data, list):
        return findings

    for result in data:
        description = result.get("Description", "No description")
        file_path = result.get("File", "")
        start_line = result.get("StartLine", 0)
        match = result.get("Match", "")

        findings.append(
            {
                "tool": "gitleaks",
                "severity": "HIGH",
                "filename": file_path,
                "line_number": start_line,
                "description": description,
                "match": match,
            }
        )

    return findings


def sort_findings(findings):
    """Sort findings by severity (HIGH > MEDIUM > LOW/INFO)."""

    def severity_key(f):
        sev = f.get("severity", "INFO").upper()
        return SEVERITY_ORDER.get(sev, 3)

    return sorted(findings, key=severity_key)


def count_by_severity(findings):
    """Count findings by severity level."""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1
        elif sev == "ERROR":
            counts["HIGH"] += 1
    return counts


def format_severity(severity):
    """Format severity with emoji indicator."""
    sev = severity.upper()
    if sev in ("HIGH", "ERROR"):
        return "🔴 HIGH"
    elif sev == "MEDIUM":
        return "🟡 MEDIUM"
    elif sev in ("LOW", "INFO"):
        return "🟢 LOW"
    return severity


def generate_prompt(
    bandit_findings, semgrep_findings, pip_audit_findings, gitleaks_findings
):
    """Generate the triage prompt markdown."""

    all_findings = sort_findings(bandit_findings + semgrep_findings + gitleaks_findings)
    severity_counts = count_by_severity(all_findings)

    # Count pip-audit separately (it doesn't have source file references)
    pip_high = sum(1 for f in pip_audit_findings if f.get("severity") == "HIGH")
    pip_med = sum(1 for f in pip_audit_findings if f.get("severity") == "MEDIUM")

    lines = []
    lines.append("# Security Triage Prompt")
    lines.append("")
    lines.append("## System Instructions")
    lines.append("")
    lines.append(
        "You are an expert security engineer reviewing the results of automated security scans."
    )
    lines.append(
        "Your task is to analyze the findings below, prioritize them by severity, and provide"
    )
    lines.append(
        "actionable remediation steps. Focus on findings that pose the greatest risk to the"
    )
    lines.append("application's security posture.")
    lines.append("")
    lines.append("For each finding:")
    lines.append(
        "1. Verify the vulnerability exists by examining the code snippet provided"
    )
    lines.append("2. Assess the actual risk considering exploitability and context")
    lines.append("3. Provide specific remediation guidance")
    lines.append("4. Flag any findings that are false positives (with justification)")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")

    total = len(all_findings)
    total_pip = len(pip_audit_findings)
    total_all = total + total_pip

    lines.append("| Tool | Findings |")
    lines.append("|------|----------|")
    lines.append(f"| Bandit | {len(bandit_findings)} |")
    lines.append(f"| Semgrep | {len(semgrep_findings)} |")
    lines.append(f"| pip-audit | {total_pip} |")
    lines.append(f"| gitleaks | {len(gitleaks_findings)} |")
    lines.append(f"| **Total** | **{total_all}** |")
    lines.append("")

    total_high = severity_counts["HIGH"] + pip_high
    total_med = severity_counts["MEDIUM"] + pip_med

    lines.append(f"**Critical/High Severity:** {total_high}")
    lines.append(f"**Medium Severity:** {total_med}")
    lines.append(
        f"**Low/Info Severity:** {severity_counts['LOW'] + severity_counts['INFO']}"
    )
    lines.append("")

    # Bandit Findings
    if bandit_findings:
        lines.append("---")
        lines.append("")
        lines.append("## Bandit Findings")
        lines.append("")
        lines.append(
            "Bandit is a Python-focused static analysis tool that detects common security issues."
        )
        lines.append("")

        for finding in sort_findings(bandit_findings):
            lines.append(
                f"### {format_severity(finding['severity'])} - {finding['filename']}:{finding['line_number']}"
            )
            lines.append("")
            lines.append(f"**Test ID:** `{finding['test_id']}`")
            lines.append("")
            lines.append(f"**Description:** {finding['description']}")
            lines.append("")

            if finding["snippet"]:
                lines.append(f"**Code Snippet ({finding['language']}):**")
                lines.append("```" + finding["language"])
                lines.append(finding["snippet"])
                lines.append("```")
            else:
                lines.append("*Source code snippet not available*")
            lines.append("")

            if finding["more_info"]:
                lines.append(f"**More Info:** {finding['more_info']}")
                lines.append("")
            lines.append("")

    # Semgrep Findings
    if semgrep_findings:
        lines.append("---")
        lines.append("")
        lines.append("## Semgrep Findings")
        lines.append("")
        lines.append(
            "Semgrep is a fast, open-source static analysis tool that finds vulnerabilities via pattern matching."
        )
        lines.append("")

        for finding in sort_findings(semgrep_findings):
            lines.append(
                f"### {format_severity(finding['severity'])} - {finding['filename']}:{finding['line_number']}"
            )
            lines.append("")
            lines.append(f"**Rule ID:** `{finding['test_id']}`")
            lines.append("")
            lines.append(f"**Description:** {finding['description']}")
            lines.append("")

            if finding["snippet"]:
                lines.append(f"**Code Snippet ({finding['language']}):**")
                lines.append("```" + finding["language"])
                lines.append(finding["snippet"])
                lines.append("```")
            else:
                lines.append("*Source code snippet not available*")
            lines.append("")

    # pip-audit Findings
    if pip_audit_findings:
        lines.append("---")
        lines.append("")
        lines.append("## pip-audit Findings")
        lines.append("")
        lines.append("pip-audit checks Python dependencies for known vulnerabilities.")
        lines.append("")

        for finding in sort_findings(pip_audit_findings):
            lines.append(
                f"### {format_severity(finding['severity'])} - {finding['package']} ({finding['version']})"
            )
            lines.append("")
            lines.append(f"**Vulnerability ID:** `{finding['vuln_id']}`")
            lines.append("")

            if finding["cve_ids"]:
                lines.append(f"**CVE IDs:** {', '.join(finding['cve_ids'])}")
                lines.append("")

            if finding["fix_versions"]:
                lines.append(
                    f"**Fixed Versions:** {', '.join(finding['fix_versions'])}"
                )
                lines.append("")

            # Truncate very long descriptions
            desc = finding["description"]
            if len(desc) > 500:
                desc = desc[:500] + "..."
            lines.append(f"**Description:** {desc}")
            lines.append("")

    # Gitleaks Findings
    if gitleaks_findings:
        lines.append("---")
        lines.append("")
        lines.append("## Gitleaks Findings")
        lines.append("")
        lines.append(
            "Gitleaks scans git repositories for secrets, credentials, and other sensitive data."
        )
        lines.append("")

        for finding in sort_findings(gitleaks_findings):
            lines.append(
                f"### {format_severity(finding['severity'])} - {finding['filename']}:{finding['line_number']}"
            )
            lines.append("")
            lines.append(f"**Description:** {finding['description']}")
            lines.append("")
            lines.append(
                f"**Match:** `{finding['match'][:100]}...`"
                if len(finding.get("match", "")) > 100
                else f"**Match:** `{finding.get('match', 'N/A')}`"
            )
            lines.append("")

    # Prioritized Action Items
    lines.append("---")
    lines.append("")
    lines.append("## Prioritized Action Items")
    lines.append("")
    lines.append(
        "Based on severity and exploitability, address these findings in order:"
    )
    lines.append("")

    action_items = []

    # High severity from all sources
    for f in all_findings:
        if f.get("severity", "").upper() in ("HIGH", "ERROR"):
            if f["tool"] == "bandit":
                action_items.append(
                    f"- **[HIGH] {f['filename']}:{f['line_number']}** - {f['description'][:100]}"
                )
            elif f["tool"] == "semgrep":
                action_items.append(
                    f"- **[HIGH] {f['filename']}:{f['line_number']}** - {f['description'][:100]}"
                )
            elif f["tool"] == "gitleaks":
                action_items.append(
                    f"- **[HIGH] Secret Exposure** - {f['filename']}:{f['line_number']} - {f['description'][:80]}"
                )

    # pip-audit high severity
    for f in pip_audit_findings:
        if f.get("severity") == "HIGH":
            cves = ", ".join(f["cve_ids"][:3]) if f["cve_ids"] else f["vuln_id"]
            action_items.append(
                f"- **[HIGH] {f['package']}** - Upgrade to {' or '.join(f['fix_versions'][:2]) if f['fix_versions'] else 'latest'}: {cves}"
            )

    # Medium severity
    for f in all_findings:
        if f.get("severity", "").upper() == "MEDIUM":
            if f["tool"] == "bandit":
                action_items.append(
                    f"- **[MEDIUM] {f['filename']}:{f['line_number']}** - {f['description'][:100]}"
                )
            elif f["tool"] == "semgrep":
                action_items.append(
                    f"- **[MEDIUM] {f['filename']}:{f['line_number']}** - {f['description'][:100]}"
                )

    for f in pip_audit_findings:
        if f.get("severity") == "MEDIUM":
            cves = ", ".join(f["cve_ids"][:3]) if f["cve_ids"] else f["vuln_id"]
            action_items.append(
                f"- **[MEDIUM] {f['package']}** - Upgrade to {' or '.join(f['fix_versions'][:2]) if f['fix_versions'] else 'latest'}: {cves}"
            )

    # Remove duplicates and limit
    seen = set()
    unique_items = []
    for item in action_items:
        if item not in seen:
            seen.add(item)
            unique_items.append(item)

    if unique_items:
        lines.extend(unique_items[:30])  # Limit to 30 action items
    else:
        lines.append("- No critical or medium severity findings detected.")

    lines.append("")

    # Remediation Checklist
    lines.append("---")
    lines.append("")
    lines.append("## Remediation Checklist")
    lines.append("")
    lines.append("Use this checklist to track remediation progress:")
    lines.append("")

    if bandit_findings:
        lines.append("### Bandit")
        for f in sort_findings(bandit_findings):
            checked = "[ ]"
            lines.append(
                f"{checked} **{f['filename']}:{f['line_number']}** - {f['test_id']}: {f['description'][:60]}..."
            )
        lines.append("")

    if semgrep_findings:
        lines.append("### Semgrep")
        for f in sort_findings(semgrep_findings):
            checked = "[ ]"
            lines.append(
                f"{checked} **{f['filename']}:{f['line_number']}** - {f['test_id']}: {f['description'][:60]}..."
            )
        lines.append("")

    if pip_audit_findings:
        lines.append("### Dependencies")
        for f in sort_findings(pip_audit_findings):
            checked = "[ ]"
            fix_ver = f["fix_versions"][0] if f["fix_versions"] else "latest"
            lines.append(
                f"{checked} **{f['package']}=={f['version']}** -> **{f['package']}>={fix_ver}** ({f['vuln_id']})"
            )
        lines.append("")

    if gitleaks_findings:
        lines.append("### Secrets")
        for f in sort_findings(gitleaks_findings):
            checked = "[ ]"
            lines.append(
                f"{checked} **{f['filename']}:{f['line_number']}** - {f['description'][:60]}..."
            )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*This triage prompt was automatically generated by the security scan workflow.*"
    )

    return "\n".join(lines)


def main():
    """Main entry point."""
    # Ensure output directory exists
    PROMPT_DIR.mkdir(parents=True, exist_ok=True)

    # Load all scan results
    print("Loading scan results...")
    bandit_data = load_json(BANDIT_FILE)
    semgrep_data = load_json(SEMGREP_FILE)
    pip_audit_data = load_json(PIP_AUDIT_FILE)
    gitleaks_data = load_json(GITLEAKS_FILE)

    # Parse findings
    print("Parsing findings...")
    bandit_findings = parse_bandit(bandit_data) if bandit_data else []
    semgrep_findings = parse_semgrep(semgrep_data) if semgrep_data else []
    pip_audit_findings = parse_pip_audit(pip_audit_data) if pip_audit_data else []
    gitleaks_findings = parse_gitleaks(gitleaks_data) if gitleaks_data else []

    # Generate prompt
    print("Generating triage prompt...")
    prompt = generate_prompt(
        bandit_findings, semgrep_findings, pip_audit_findings, gitleaks_findings
    )

    # Write output
    with open(PROMPT_FILE, "w", encoding="utf-8") as f:
        f.write(prompt)

    print(f"Triage prompt written to: {PROMPT_FILE}")
    print(
        f"Summary: {len(bandit_findings)} bandit, {len(semgrep_findings)} semgrep, "
        f"{len(pip_audit_findings)} pip-audit, {len(gitleaks_findings)} gitleaks findings"
    )


if __name__ == "__main__":
    main()
