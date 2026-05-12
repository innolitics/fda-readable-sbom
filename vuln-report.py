#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.13"
# dependencies = ["nvdlib~=0.8.3"]
# ///
import json
import argparse
import time
import nvdlib  # type: ignore
from datetime import datetime
from requests.exceptions import HTTPError


def parse_spdx(file_path):
    """Parses the SPDX JSON file to extract package information."""
    with open(file_path, "r") as f:
        spdx_data = json.load(f)
    return spdx_data.get("packages", [])


def get_cpe_from_package(package):
    """Extracts the CPE string from a package's external references."""
    for ref in package.get("externalRefs", []):
        if ref.get("referenceType") == "SECURITY" and ref.get(
            "referenceLocator", ""
        ).startswith("cpe:"):
            return ref["referenceLocator"]
    return None


def find_vulnerabilities(cpe_string, api_key=None):
    """Finds vulnerabilities for a given CPE string using nvdlib."""
    if not cpe_string:
        return []

    print(f"Searching for vulnerabilities for: {cpe_string}")

    for attempt in range(5):
        try:
            return nvdlib.searchCVE(cpeName=cpe_string, limit=2000, key=api_key)
        except HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                wait = 2 ** attempt * 10
                print(f"Rate limited; retrying in {wait}s (attempt {attempt + 1}/5)...")
                time.sleep(wait)
            else:
                print(f"Could not fetch vulnerabilities for {cpe_string}. Error: {e}")
                return []
        except Exception as e:
            print(f"Could not fetch vulnerabilities for {cpe_string}. Error: {e}")
            return []

    print(f"Giving up on {cpe_string} after 5 rate-limit retries.")
    return []


def generate_markdown_report(packages_with_vulns, spdx_file_name):
    """Generates a Markdown report from the vulnerability data."""
    report_lines = [
        f"# Vulnerability Report for {spdx_file_name}",
        f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "\n---",
    ]

    if not packages_with_vulns:
        report_lines.append(
            "\n**No vulnerabilities found for the components in this SBOM.**"
        )
        return "\n".join(report_lines)

    for package_info in packages_with_vulns:
        report_lines.append(
            f"\n## 📦 Package: {package_info['name']} ({package_info['version']})"
        )
        report_lines.append(f"**CPE:** `{package_info['cpe']}`")

        vulns = package_info["vulnerabilities"]
        if not vulns:
            report_lines.append("\n*No vulnerabilities found for this package.*")
            continue

        report_lines.append("\n### Found Vulnerabilities:")
        for cve in vulns:
            report_lines.append(
                f"\n#### 🚨 [{cve.id}](https://nvd.nist.gov/vuln/detail/{cve.id})"
            )

            # Get CVSS V3 score if available, otherwise V2
            severity = "N/A"
            if hasattr(cve.metrics, "cvssMetricV31") and cve.metrics.cvssMetricV31:
                severity = f"{cve.metrics.cvssMetricV31[0].cvssData.baseScore} ({cve.metrics.cvssMetricV31[0].cvssData.baseSeverity})"
            elif hasattr(cve.metrics, "cvssMetricV2") and cve.metrics.cvssMetricV2:
                severity = f"{cve.metrics.cvssMetricV2[0].cvssData.baseScore} ({cve.metrics.cvssMetricV2[0].baseSeverity})"

            report_lines.append(f"- **Severity:** {severity}")

            description = "No description available."
            if cve.descriptions:
                description = cve.descriptions[0].value

            report_lines.append(f"- **Description:** {description}")

    return "\n".join(report_lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate a vulnerability report from an SPDX JSON file."
    )
    parser.add_argument("spdx_file", help="Path to the SPDX JSON file.")
    parser.add_argument(
        "-o",
        "--output",
        help="Path to the output Markdown file. If not provided, prints to console.",
    )
    parser.add_argument(
        "--api-key",
        help="NVD API key (allows 50 req/30s instead of 5 req/30s).",
    )

    args = parser.parse_args()

    packages = parse_spdx(args.spdx_file)
    packages_with_vulns = []

    for package in packages:
        name = package.get("name", "N/A")
        version = package.get("versionInfo", "N/A")
        cpe = get_cpe_from_package(package)

        if not cpe:
            continue

        vulnerabilities = find_vulnerabilities(cpe, api_key=args.api_key)

        # We only add packages with vulnerabilities to the report
        if vulnerabilities:
            packages_with_vulns.append(
                {
                    "name": name,
                    "version": version,
                    "cpe": cpe,
                    "vulnerabilities": vulnerabilities,
                }
            )

    markdown_report = generate_markdown_report(packages_with_vulns, args.spdx_file)

    if args.output:
        with open(args.output, "w") as f:
            f.write(markdown_report)
        print(f"Report successfully generated at {args.output}")
    else:
        print("\n" + "=" * 20 + " REPORT " + "=" * 20 + "\n")
        print(markdown_report)


if __name__ == "__main__":
    print("This is a last resort tool to map SPDX SBOM with CPE string to vulnerabilities in NVD.")
    print("Consider using Trivy or Syft/Grype for better results.")
    main()
