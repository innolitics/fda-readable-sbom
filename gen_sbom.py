import os
import json
import argparse

import openpyxl


def newer(p1, p2):
    return p1 if p1["versionInfo"] > p2["versionInfo"] else p2


def create_sbom_packages_dict(sbom):
    packages = {}
    for p in sbom["packages"]:
        name = p["name"]
        packages[name] = newer(p, packages[name]) if name in packages else p
    return packages


def merge_sboms(sbom1, sbom2):
    packages1 = create_sbom_packages_dict(sbom1)
    packages2 = create_sbom_packages_dict(sbom2)
    merged_packages = []
    for name, p in packages1.items():
        merged_packages.append(newer(p, packages2[name]) if name in packages2 else p)
    for name, p in packages2.items():
        merged_packages.extend([] if name in packages1 else [p])
    sbom1["packages"] = merged_packages

    sbom1["creationInfo"]["created"] = max(
        sbom1["creationInfo"]["created"], sbom2["creationInfo"]["created"]
    )
    return sbom1


excel_header = [
    "Author Name",
    "Timestamp",
    "Supplier Name",
    "Component Name",
    "Version String",
    "Unique Identifier",
    "Relationship",
]


def save_as_xlsx(sbom, output_file_path, author_name=None):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(excel_header)
    for p in sbom["packages"]:
        row = [
            author_name if author_name else ", ".join(sbom["creationInfo"]["creators"]),
            sbom["creationInfo"]["created"],
            p.get("supplier", "Open-source software"),
            p["name"],
            p["versionInfo"],
            p["SPDXID"],
            "Is contained by",
        ]
        ws.append(row)
    wb.save(output_file_path)


def gen_sbom(input_directory_path, output_file_path, author_name=None):
    master_sbom = {}
    for file_name in os.listdir(input_directory_path):
        input_file_path = os.path.join(input_directory_path, file_name)
        with open(input_file_path, "r") as f:
            sbom = json.load(f)
            master_sbom = merge_sboms(master_sbom, sbom) if master_sbom != {} else sbom
    save_as_xlsx(master_sbom, output_file_path, author_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input_directory", help="Github SPDX SBOM json files directory.")
    parser.add_argument("output_file", help="Output combined SBOM excel file path.")
    parser.add_argument("--author", help="Override the Author Name.")
    args = parser.parse_args()

    gen_sbom(args.input_directory, args.output_file, args.author)
