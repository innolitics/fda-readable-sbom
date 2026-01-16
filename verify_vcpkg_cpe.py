#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.13"
# dependencies = ["nvdlib~=0.8.3", "pyyaml~=6.0.3"]
# ///
import sys
import time

import nvdlib
import yaml


def verify_cpes(filepath="vcpkg.yml"):
    """
    Parses a YAML file, extracts CPE strings, and verifies them against the NVD.
    """
    try:
        with open(filepath, "r") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: File not found at '{filepath}'")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML file: {e}")
        sys.exit(1)

    if not isinstance(data, dict):
        print("Error: YAML file is not a dictionary of packages.")
        sys.exit(1)

    print(f"Verifying CPEs from '{filepath}' against NVD...\n")

    not_found = []
    found_count = 0

    packages_to_check = []
    for package_name, details in data.items():
        if isinstance(details, dict) and "cpe" in details:
            packages_to_check.append((package_name, details["cpe"]))

    total_count = len(packages_to_check)
    print(f"Found {total_count} packages with CPEs to verify.")

    for i, (package_name, cpe_string) in enumerate(packages_to_check):
        try:
            # Use cpeMatchString for an exact search.
            # The NVD API may return multiple minor versions for a base CPE string,
            # so we check if we get at least one result.
            results = nvdlib.searchCPE(cpeMatchString=cpe_string, limit=1)
            if results:
                print(f"✅ Found: {package_name} ({cpe_string})")
                found_count += 1
            else:
                print(f"❌ Not Found: {package_name} ({cpe_string})")
                not_found.append((package_name, cpe_string))
        except Exception as e:
            print(f"ERROR searching for {package_name} ({cpe_string}): {e}")
            not_found.append((package_name, cpe_string))

        # The public NVD API has a rate limit. A delay prevents hitting it.
        # 5 requests per 30 seconds without an API key.
        if (i + 1) % 5 == 0 and i < total_count - 1:
            print("\n--- Pausing for 30 seconds to respect NVD API rate limit ---\n")
            time.sleep(30)

    print("\n--- Verification Summary ---")
    print(f"Total Packages with CPEs: {total_count}")
    print(f"Found in NVD: {found_count}")
    print(f"Not Found in NVD: {len(not_found)}")

    if not_found:
        print("\nPackages not found in NVD:")
        for package, cpe in not_found:
            print(f"  - {package}: {cpe}")


if __name__ == "__main__":
    # Assumes vcpkg.yml is in the same directory as the script.
    # You can pass a different path as an argument.
    file_to_check = sys.argv[1] if len(sys.argv) > 1 else "vcpkg.yml"
    verify_cpes(file_to_check)
