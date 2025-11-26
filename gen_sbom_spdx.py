import csv
import argparse
import logging
import re

logger = logging.getLogger(__name__)


def parse_spdx_file(file_path):
    doc_metadata = {
        "creators": [],
        "created": None
    }
    packages = []
    current_package = None
    main_package = None
    
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()
            
            if not line:
                continue
            
            if line.startswith("#####"):
                if current_package is not None:
                    if main_package is None:
                        main_package = current_package
                    else:
                        packages.append(current_package)
                current_package = {}
                continue
            
            if line.startswith("Creator:"):
                creator_match = re.match(r"Creator:\s*(.+)", line)
                if creator_match:
                    creator = creator_match.group(1).strip()
                    doc_metadata["creators"].append(creator)
            elif line.startswith("Created:"):
                created_match = re.match(r"Created:\s*(.+)", line)
                if created_match:
                    doc_metadata["created"] = created_match.group(1).strip()
            
            if current_package is not None:
                if line.startswith("PackageName:"):
                    current_package["name"] = line.split(":", 1)[1].strip()
                elif line.startswith("PackageVersion:"):
                    current_package["version"] = line.split(":", 1)[1].strip()
                elif line.startswith("PackageSupplier:"):
                    current_package["supplier"] = line.split(":", 1)[1].strip()
                elif line.startswith("SPDXID:"):
                    current_package["SPDXID"] = line.split(":", 1)[1].strip()
                elif line.startswith("ExternalRef:"):
                    if "externalRefs" not in current_package:
                        current_package["externalRefs"] = []
                    parts = line.split(":", 1)[1].strip().split()
                    if len(parts) >= 3 and parts[0] == "PACKAGE-MANAGER" and parts[1] == "purl":
                        current_package["externalRefs"].append({
                            "referenceType": "purl",
                            "referenceLocator": " ".join(parts[2:])
                        })
        
        if current_package is not None:
            if main_package is None:
                main_package = current_package
            else:
                packages.append(current_package)
    
    return doc_metadata, packages, main_package


def extract_purl(package):
    if "externalRefs" in package:
        for ref in package["externalRefs"]:
            if ref.get("referenceType") == "purl":
                return ref.get("referenceLocator")
    return None


def normalize_supplier(supplier_str):
    if not supplier_str or supplier_str == "NOASSERTION":
        return None
    
    parts = supplier_str.split(":", 1)
    if len(parts) == 2:
        return parts[1].strip()
    
    return supplier_str.strip()


def save_as_csv(packages, doc_metadata, output_file_path, author_name=None, main_package=None):
    csv_header = [
        "Author Name",
        "Timestamp",
        "Supplier Name",
        "Component Name",
        "Version String",
        "Unique Identifier",
        "Relationship",
        "Software Level of Support",
        "End of Support Date",
    ]
    
    with open(output_file_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(csv_header)
        
        if author_name:
            author = author_name
        else:
            author = ", ".join(doc_metadata["creators"]) if doc_metadata["creators"] else ""
        
        timestamp = doc_metadata["created"] if doc_metadata["created"] else ""
        
        if main_package:
            purl = extract_purl(main_package)
            unique_id = purl if purl else main_package.get("SPDXID", "")
            
            version = main_package.get("version", "")
            if not version:
                version = "MANUAL: Please include version manually"
            
            main_row = [
                author,
                timestamp,
                "Open-source software",
                main_package.get("name", ""),
                version,
                unique_id,
                "Is contained by",
                "Open-source software",
                "None",
            ]
            writer.writerow(main_row)
        
        for p in packages:
            version = p.get("version", "")
            if not version:
                logger.warning("Skipping '%s' due to no PackageVersion field", p.get("name", "unknown"))
                continue
            
            purl = extract_purl(p)
            unique_id = purl if purl else p.get("SPDXID", "")
            
            row = [
                author,
                timestamp,
                "Open-source software",
                p.get("name", ""),
                version,
                unique_id,
                "Is contained by",
                "Open-source software",
                "None",
            ]
            writer.writerow(row)


def gen_sbom_spdx(input_file_path, output_file_path, author_name=None):
    doc_metadata, packages, main_package = parse_spdx_file(input_file_path)
    save_as_csv(packages, doc_metadata, output_file_path, author_name, main_package)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Parse SPDX tag-value format SBOM and output human-readable CSV."
    )
    parser.add_argument(
        "spdx_sbom",
        help="Input SPDX tag-value format SBOM file path."
    )
    parser.add_argument(
        "output_csv_file",
        help="Output CSV file path."
    )
    parser.add_argument(
        "--author",
        help="Override the Author Name."
    )
    args = parser.parse_args()
    
    gen_sbom_spdx(args.spdx_sbom, args.output_csv_file, args.author)
