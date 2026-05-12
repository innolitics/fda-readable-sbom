#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.13"
# ///
import json
import argparse
import subprocess
import sys
from datetime import datetime
from collections import defaultdict


def check_grype():
    """Exits with an error message if grype is not installed."""
    result = subprocess.run(["which", "grype"], capture_output=True)
    if result.returncode != 0:
        print("Error: grype is not installed or not on PATH.", file=sys.stderr)
        print("Install it with: brew install grype", file=sys.stderr)
        print("Then update the DB with: grype db update", file=sys.stderr)
        sys.exit(1)


def scan_with_grype(sbom_path: str) -> dict:
    """Runs grype against an SBOM file and returns the parsed JSON output."""
    result = subprocess.run(
        ["grype", f"sbom:{sbom_path}", "-o", "json", "--quiet"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"grype error:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def generate_markdown_report(grype_output: dict, sbom_file_name: str) -> str:
    """Generates a Markdown report from grype's JSON output."""
    db_status = grype_output.get("descriptor", {}).get("db", {}).get("status", {})
    db_built = db_status.get("built", "unknown")
    db_schema = db_status.get("schemaVersion", "unknown")

    report_lines = [
        f"# Vulnerability Report for {sbom_file_name}",
        f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Vulnerability DB built: {db_built}  ",
        f"Vulnerability DB schema: `{db_schema}`",
        "\n---",
    ]

    matches = grype_output.get("matches", [])

    if not matches:
        report_lines.append("\n**No vulnerabilities found for the components in this SBOM.**")
        return "\n".join(report_lines)

    # Group matches by artifact name+version, deduplicating by CVE ID
    by_artifact: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)
    for match in matches:
        artifact = match.get("artifact", {})
        key = (artifact.get("name", "N/A"), artifact.get("version", "N/A"))
        cve_id = match["vulnerability"]["id"]
        if cve_id not in by_artifact[key]:
            by_artifact[key][cve_id] = match

    for (name, version), cve_map in sorted(by_artifact.items()):
        report_lines.append(f"\n## 📦 Package: {name} ({version})")

        first_match = next(iter(cve_map.values()))
        cpes = first_match.get("artifact", {}).get("cpes", [])
        if cpes:
            report_lines.append(f"**CPE:** `{cpes[0]}`")

        report_lines.append("\n### Found Vulnerabilities:")
        for match in sorted(cve_map.values(), key=lambda m: m["vulnerability"]["id"]):
            vuln = match["vulnerability"]
            cve_id = vuln.get("id", "N/A")
            data_source = vuln.get("dataSource", f"https://nvd.nist.gov/vuln/detail/{cve_id}")
            report_lines.append(f"\n#### 🚨 [{cve_id}]({data_source})")

            # Pick the highest CVSS version available
            severity_label = vuln.get("severity", "N/A")
            cvss_list = vuln.get("cvss", [])
            base_score = None
            for cvss in sorted(cvss_list, key=lambda c: c.get("version", ""), reverse=True):
                score = cvss.get("metrics", {}).get("baseScore")
                if score is not None:
                    base_score = score
                    break

            if base_score is not None:
                report_lines.append(f"- **Severity:** {base_score} ({severity_label})")
            else:
                report_lines.append(f"- **Severity:** {severity_label}")

            description = vuln.get("description") or "No description available."
            report_lines.append(f"- **Description:** {description}")

            fix = vuln.get("fix", {})
            fix_versions = fix.get("versions", [])
            if fix_versions:
                report_lines.append(f"- **Fix:** {', '.join(fix_versions)}")

    return "\n".join(report_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a vulnerability report from an SBOM file using grype."
    )
    parser.add_argument("sbom_file", help="Path to the SBOM file (SPDX JSON or CycloneDX).")
    parser.add_argument(
        "-o",
        "--output",
        help="Path to the output Markdown file. If not provided, prints to console.",
    )
    parser.add_argument(
        "--db-update",
        action="store_true",
        help="Update the grype vulnerability database before scanning.",
    )

    args = parser.parse_args()

    check_grype()

    if args.db_update:
        print("Updating grype vulnerability database...")
        subprocess.run(["grype", "db", "update"], check=True)

    print(f"Scanning {args.sbom_file} with grype...")
    grype_output = scan_with_grype(args.sbom_file)

    match_count = len(grype_output.get("matches", []))
    print(f"Found {match_count} vulnerability matches.")

    markdown_report = generate_markdown_report(grype_output, args.sbom_file)

    if args.output:
        with open(args.output, "w") as f:
            f.write(markdown_report)
        print(f"Report successfully generated at {args.output}")
    else:
        print("\n" + "=" * 20 + " REPORT " + "=" * 20 + "\n")
        print(markdown_report)


if __name__ == "__main__":
    main()
