#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.13"
# dependencies = [
#   "click~=8.1.8",
#   "openpyxl~=3.1.5",
#   "packaging~=25.0",
#   "pydantic~=2.11.9",
#   "pyyaml~=6.0.3",
#   "types-PyYAML",
# ]
# ///

import logging
from collections.abc import Generator, Sequence
from datetime import datetime
from functools import reduce
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol

import click
import openpyxl
import yaml
from packaging import version
from pydantic import (
    AliasPath,
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_serializer,
)

logger = logging.getLogger(__name__)


class BaseSBOM(BaseModel):
    def to_fda_records(self, author: str | None) -> Generator["FDARecord"]:
        raise NotImplementedError


class SPDXRef(BaseModel):
    # referenceCategory: str
    referenceType: str
    referenceLocator: str


class SPDXPackage(BaseModel):
    _default_supplier = "Open-source software"
    model_config = ConfigDict(populate_by_name=True)
    SPDXID: str
    name: str

    # The versionInfo field is optional (https://spdx.github.io/spdx-spec/v2.3/package-information/#73-package-version-field).
    # VCPKG generated SBOMs sometimes have versionInfo missing
    # versionInfo: str | None = None
    version: Annotated[str, Field(alias="versionInfo")] = ""
    supplier: str = Field(default=_default_supplier)
    externalRefs: list[SPDXRef] = Field(default_factory=list)

    @field_serializer("supplier")
    def supplier_serializer(self, supplier: str) -> str:
        if supplier.startswith("Organization: ") or supplier.startswith("Person: "):
            return supplier
        return "NOASSERTION"

    @computed_field
    def purl(self) -> str | None:
        for ref in self.externalRefs:
            if ref.referenceType == "purl":
                return ref.referenceLocator
        return None


class SPDXCreationInfo(BaseModel):
    creators: list[str]
    created: str


class SPDX2_3(BaseSBOM):
    spdxVersion: Literal["SPDX-2.3", "SPDX-2.2"]
    SPDXID: str
    name: str
    creationInfo: SPDXCreationInfo
    packages: list[SPDXPackage]

    _is_vcpkg: bool = False

    def model_post_init(self, __context: Any):
        self._is_vcpkg = any(
            "tool: vcpkg" in creator.lower() for creator in self.creationInfo.creators
        )

    def to_fda_records(self, author: str | None) -> Generator["FDARecord"]:
        """Convert SPDX packages to FDARecords."""
        for p in self.packages:
            if not p.version:
                logger.warning(
                    f"Package {p.name} ({p.SPDXID}) is missing versionInfo, skipping"
                )
                continue
            # Skip binary package provided in vcpkg
            if self._is_vcpkg:
                if p.SPDXID == "SPDXRef-binary":
                    continue

            unique_id = p.SPDXID  # fallback, prefer purl, then cpe
            for ref in p.externalRefs:
                if ref.referenceType == "purl":
                    unique_id = ref.referenceLocator
                    break
                elif (
                    ref.referenceType == "SECURITY"
                    and ref.referenceLocator.startswith("cpe:2.3:")
                ):
                    unique_id = ref.referenceLocator

            yield FDARecord(
                author=author if author else ", ".join(self.creationInfo.creators),
                timestamp=self.creationInfo.created,
                supplier=p.supplier,
                name=p.name,
                version=p.version,
                unique_identifier=unique_id,
            )


def enrich_vcpkg(sbom: SPDX2_3):
    """Enrich VCPKG SPDX SBOM with cpe and supplier info from vcpkg.yml."""
    vcpkg_yaml_path = Path(__file__).parent / "vcpkg.yml"
    if not vcpkg_yaml_path.is_file():
        logger.error(f"vcpkg.yml not found at {vcpkg_yaml_path}, cannot enrich SBOM")
        return

    with vcpkg_yaml_path.open() as f:
        vcpkg_data = yaml.safe_load(f)

    def follow_link(pkg_name: str) -> str | None:
        """Follow links in vcpkg.yml to get the actual package name. (recursive)"""
        pkg = vcpkg_data.get(pkg_name)
        if not pkg:
            return None
        if "aka" in pkg:
            return follow_link(pkg["aka"])
        return pkg_name

    for p in sbom.packages:
        name = follow_link(p.name)
        if name != p.name:
            logger.info(f"Using {name} for {p.name}")
        if not name:
            logger.error(f"Package {p.name} not found in vcpkg.yml, cannot enrich")
            continue

        p.SPDXID = f"SPDXRef-{name}"
        p.supplier = "vcpkg"

        if "cpe" in vcpkg_data[name]:
            version = p.version.split("#")[0]  # Remove vcpkg revision number
            cpe = vcpkg_data[name]["cpe"]
            vendor = cpe.split(":")[3:4][0]  # Extract vendor from cpe
            p.supplier += f", {vendor}"
            p.externalRefs.append(
                SPDXRef(
                    referenceType="SECURITY",
                    referenceLocator=f"{cpe}:{version}",
                )
            )
            logger.info(f"Added CPE {cpe} to package {p.name}")

    # deduplicate by SPDXID
    unique_packages = {}
    for p in sbom.packages:
        if p.SPDXID not in unique_packages:
            unique_packages[p.SPDXID] = p
        else:
            logger.warning(
                f"Duplicate package {p.SPDXID} found, keeping the first occurrence"
            )
    sbom.packages = list(unique_packages.values())


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
                    name=c.name,
                    version=c.version,
                    unique_identifier=c.purl if c.purl else c.bom_ref,
                )


class FDARecord(BaseModel):
    """FDA required fields."""

    author: str
    timestamp: str
    supplier: str = "Open-source software"
    name: str
    version: str
    unique_identifier: str
    relationship: Literal["Is contained by"] = "Is contained by"


class CommonRecordProtocol(Protocol):
    version: str
    name: str
    supplier: str


def newer[T: CommonRecordProtocol](p1: T, p2: T) -> T:
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


def merge_sboms[T: CommonRecordProtocol](
    sbom1: Sequence[T], sbom2: Sequence[T]
) -> list[T]:
    """Merge two SBOMs, keeping the newest version of each package."""
    records = {(r.name, r.supplier): r for r in sbom1}
    for r in sbom2:
        key = (r.name, r.supplier)
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
                r.name,
                r.version,
                r.unique_identifier,
                r.relationship,
            ]
        )
    wb.save(output_file_path)


@click.command()
@click.argument(
    "input_directory_path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.argument("output_file_path", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--verbose", is_flag=True, help="Enable verbose logging.")
@click.option("--author-name", type=str, default=None, help="Override the Author Name.")
@click.option("--vcpkg", is_flag=True, help="Combine VCPKG SBOMs.")
@click.option(
    "--spdx-output-file",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Output combined SPDX SBOM file path (for VCPKG only).",
)
def main(
    input_directory_path: Path,
    output_file_path: Path,
    author_name: str | None = None,
    vcpkg: bool = False,
    spdx_output_file: Path | None = None,
    verbose: bool = False,
):
    """Generate a combined SBOM from multiple SPDX and CycloneDX SBOMs in the input directory."""
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if vcpkg:
        return gen_sbom_vcpkg(
            input_directory_path, output_file_path, author_name, spdx_output_file
        )
    else:
        gen_sbom(input_directory_path, output_file_path, author_name)


def gen_sbom(
    input_directory_path: Path, output_file_path: Path, author_name: str | None = None
):
    """Generate a combined SBOM from multiple SPDX and CycloneDX SBOMs in the input directory."""
    bom_parsers: list[type[BaseSBOM]] = [SPDX2_3]  # , Cyclone1_6]
    boms: list[list[FDARecord]] = []

    for bom_file in input_directory_path.glob("**/*.json"):
        if not bom_file.is_file():
            continue
        logger.info(f"Processing {bom_file}")
        for bom_parser in bom_parsers:
            try:
                bom = bom_parser.model_validate_json(bom_file.read_text())
                logger.info(f"Parsed {bom_file} as {bom_parser.__name__}")
                boms.append(list(bom.to_fda_records(author_name)))
                break
            except Exception as e:
                logger.exception(f"Failed to parse {bom_file} as {bom_parser.__name__}")
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


def gen_sbom_vcpkg(
    input_directory_path: Path,
    output_file_path: Path,
    author_name: str | None = None,
    spdx_output_file: Path | None = None,
):
    boms: list[SPDXPackage] = []
    for bom_file in input_directory_path.glob("**/*.json"):
        if not bom_file.is_file():
            continue
        logger.info(f"Processing {bom_file}")
        try:
            bom = SPDX2_3.model_validate_json(bom_file.read_text())
            if bom._is_vcpkg:
                boms = merge_sboms(
                    boms, [p for p in bom.packages if p.SPDXID == "SPDXRef-port"]
                )
            else:
                logger.warning(f"Skipping non-vcpkg SBOM: {bom_file}")
        except Exception as e:
            logger.exception(f"Failed to parse {bom_file} as SPDX2_3")
            logger.debug(f"Failed to parse {bom_file} as SPDX2_3: {e}")
            raise ValueError(f"Unknown BOM format in {bom_file}")

    final_bom = SPDX2_3(
        spdxVersion="SPDX-2.3",
        SPDXID="SPDXRef-DOCUMENT",
        name="Combined VCPKG",
        creationInfo=SPDXCreationInfo.model_validate(
            {
                "creators": [author_name]
                if author_name
                else [
                    "Tool: github.com/innolitics/fda-readable-sbom",
                    "Tool: https://github.com/microsoft/vcpkg",
                ],
                "created": datetime.now().isoformat() + "Z",
            }
        ),
        packages=boms,
    )

    enrich_vcpkg(final_bom)
    if spdx_output_file:
        spdx_output_file.write_text(
            final_bom.model_dump_json(indent=2, by_alias=True, exclude_none=True)
        )
    save_as_xlsx(list(final_bom.to_fda_records(author=author_name)), output_file_path)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
    main()
