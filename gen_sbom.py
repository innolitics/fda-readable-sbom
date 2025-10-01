#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.10"
# dependencies = ["openpyxl", "pydantic", "packaging"]
# ///

import argparse
import logging
from functools import reduce
from pathlib import Path
from typing import Generator, Literal

import openpyxl
from packaging import version
from pydantic import AliasPath, BaseModel, Field, computed_field

logger = logging.getLogger(__name__)


class BaseSBOM(BaseModel):
    def to_fda_records(self, author: str | None) -> Generator["FDARecord"]:
        raise NotImplementedError


class SPDXRef(BaseModel):
    # referenceCategory: str
    referenceType: str
    referenceLocator: str


class SPDXPackage(BaseModel):
    SPDXID: str
    name: str

    # The versionInfo field is optional (https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field).
    # I haven't yet seen a case where it is missing and it should be included in the human-readable SBOM
    versionInfo: str
    supplier: str = "Open-source software"
    externalRefs: list[SPDXRef] = Field(default_factory=list)

    @computed_field
    def purl(self) -> str | None:
        for ref in self.externalRefs:
            if ref.referenceType == "purl":
                return ref.referenceLocator
        return None


class SPDX2_3(BaseSBOM):
    spdxVersion: Literal["SPDX-2.3"]
    SPDXID: str
    name: str
    creationInfo: dict
    packages: list[SPDXPackage]

    def to_fda_records(self, author: str | None) -> Generator["FDARecord"]:
        """Convert SPDX packages to FDARecords."""
        for p in self.packages:
            yield FDARecord(
                author=author if author else ", ".join(self.creationInfo["creators"]),  # type: ignore[arg-type]
                timestamp=self.creationInfo["created"],
                supplier=p.supplier if p.supplier else "Open-source software",
                component=p.name,
                version=p.versionInfo,
                unique_identifier=p.purl if p.purl else p.SPDXID,  # type: ignore[arg-type]
            )


class CycloneComponent(BaseModel):
    name: str
    version: str
    purl: str | None = None
    supplier: str = Field(
        validation_alias=AliasPath("supplier", "name"), default="Open-source software"
    )
    bom_ref: str = Field(alias="bom-ref")


class CycloneMetadata(BaseModel):
    timestamp: str
    tools: list[dict] = Field(validation_alias=AliasPath("tools", "components"))

    @computed_field
    def author(self) -> str:
        return ", ".join(
            f"{tool['type']}: {tool['name']}-{tool['version']}" for tool in self.tools
        )


class Cyclone1_6(BaseSBOM):
    bomFormat: Literal["CycloneDX"]
    specVersion: Literal["1.6"]
    version: int
    metadata: CycloneMetadata
    components: list[CycloneComponent] | None = None

    def to_fda_records(self, author: str | None) -> Generator["FDARecord"]:
        """Convert CycloneDX components to FDARecords."""
        if self.components:
            for c in self.components:
                yield FDARecord(
                    author=author if author else self.metadata.author,  # type: ignore[arg-type]
                    timestamp=self.metadata.timestamp,
                    supplier=c.supplier,
                    component=c.name,
                    version=c.version,
                    unique_identifier=c.purl if c.purl else c.bom_ref,
                )


class FDARecord(BaseModel):
    """FDA required fields."""

    author: str
    timestamp: str
    supplier: str = "Open-source software"
    component: str
    version: str
    unique_identifier: str
    relationship: Literal["Is contained by"] = "Is contained by"


def newer(p1: FDARecord, p2: FDARecord) -> FDARecord:
    """Return the package with the newer version using semantic version comparison."""
    if p1.version == p2.version:
        return p2  # Arbitrary choice if versions are equal
    try:
        v1 = version.parse(p1.version)
        v2 = version.parse(p2.version)
        return p1 if v1 > v2 else p2
    except Exception as e:
        # Fallback to string comparison if version parsing fails
        logger.warning(
            f"Failed to parse versions '{p1.version}' or '{p2.version}': {e}"
        )
        return p1 if p1.version > p2.version else p2


def merge_sboms(sbom1: list[FDARecord], sbom2: list[FDARecord]) -> list[FDARecord]:
    """Merge two SBOMs, keeping the newest version of each package."""
    records = {(r.component, r.supplier): r for r in sbom1}
    for r in sbom2:
        key = (r.component, r.supplier)
        if key in records:
            records[key] = newer(records[key], r)
        else:
            records[key] = r
    return list(records.values())


def deduplicate(records: list[FDARecord]) -> list[FDARecord]:
    """Deduplicate records by unique_identifier, keeping the first occurrence."""
    seen = set()
    deduped = []
    for r in records:
        key = r.unique_identifier
        if key not in seen:
            deduped.append(r)
            seen.add(key)
        else:
            logger.warning(f"Duplicate record found for unique_identifier: {key}")
    return deduped


def gen_sbom(
    input_directory_path: Path, output_file_path: Path, author_name: str | None = None
):
    """Generate a combined SBOM from multiple SPDX and CycloneDX SBOMs in the input directory."""
    bom_parsers: list[type[BaseSBOM]] = [SPDX2_3, Cyclone1_6]
    boms: list[list[FDARecord]] = []

    for bom_file in input_directory_path.glob("*.json"):
        for bom_parser in bom_parsers:
            try:
                bom = bom_parser.model_validate_json(bom_file.read_text())
                logger.info(f"Parsed {bom_file} as {bom_parser.__name__}")
                boms.append(list(bom.to_fda_records(author_name)))
                break
            except Exception as e:
                logger.debug(
                    f"Failed to parse {bom_file} as {bom_parser.__name__}: {e}"
                )
        else:
            logger.error(f"Failed to parse {bom_file} with all known parsers")
            raise ValueError(f"Unknown BOM format in {bom_file}")

    merged_bom: list[FDARecord] = reduce(merge_sboms, boms, [])
    save_as_xlsx(merged_bom, output_file_path)
    # Check for duplicates (side effect: log warnings)
    deduplicate(merged_bom)


def save_as_xlsx(bom: list[FDARecord], output_file_path: Path | str):
    """Save the BOM as an excel file."""
    excel_header = [
        "Author Name",
        "Timestamp",
        "Supplier Name",
        "Component Name",
        "Version String",
        "Unique Identifier",
        "Relationship",
    ]
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(excel_header)
    for r in bom:
        ws.append(
            [
                r.author,
                r.timestamp,
                r.supplier,
                r.component,
                r.version,
                r.unique_identifier,
                r.relationship,
            ]
        )
    wb.save(output_file_path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "input_directory", help="Github SPDX SBOM json files directory."
    )
    parser.add_argument("output_file", help="Output combined SBOM excel file path.")
    parser.add_argument("--author", help="Override the Author Name.")
    args = parser.parse_args()

    gen_sbom(Path(args.input_directory), Path(args.output_file), args.author)
