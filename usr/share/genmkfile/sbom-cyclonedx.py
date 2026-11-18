#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-assisted.

## Generates an SBOM for a package in CycloneDX format, and outputs it to
## stdout.

import json
import os
import subprocess
from datetime import datetime, timezone

from cyclonedx.factory.license import LicenseFactory
from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.license import LicenseAcknowledgement, LicenseExpression
from cyclonedx.output.json import JsonV1Dot6
from packageurl import PackageURL


def deb_component(name, version=None):
    ## Every Debian package is a 'library' -- uniform for the root component and
    ## its dependencies, so one package is never typed two ways across SBOMs.
    purl = PackageURL(type="deb", namespace="debian", name=name, version=version)
    return Component(
        name=name,
        version=version,
        type=ComponentType.LIBRARY,
        bom_ref=purl.to_string(),
        purl=purl,
    )


def reuse_used_licenses():
    ## SPDX license ids declared in the source tree, via 'reuse --root . lint --json'
    ## .summary.used_licenses -- the set of ids actually referenced by a file, so it does
    ## not drift. '--root .' confines the scan to THIS package dir, so a parent VCS root's
    ## sibling files cannot leak their licenses in. genmkfile make_require's 'reuse' when
    ## REUSE metadata is present, so a missing tool fails loud there, not here.
    if not (os.path.exists("REUSE.toml") or os.path.exists(".reuse/dep5")):
        return []
    result = subprocess.run(
        ["reuse", "--root", ".", "lint", "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise SystemExit(
            "sbom-cyclonedx.py: 'reuse lint --json' produced no parseable output "
            f"(exit {result.returncode}): {result.stderr.strip()}"
        )
    return sorted(set(report["summary"]["used_licenses"]))


def declared_license(used_licenses):
    ## used_licenses is a flat SET of ids -- it does NOT carry the per-file boolean
    ## structure, so a file's 'A OR B' arrives as {'A', 'B'}. The ids are joined with AND:
    ## the DECLARED aggregate of licenses present in the source (debsbom's convention).
    ## Exact for the common single-license package.
    ## Limitation: a dual-licensed ('OR') file is widened to AND, and a multi-binary source
    ## gets the whole-source set per binary -- the per-.deb SBOM (debsbom, from
    ## debian/copyright) is the authoritative per-package expression source.
    if len(used_licenses) == 1:
        return LicenseFactory().make_from_string(
            used_licenses[0], license_acknowledgement=LicenseAcknowledgement.DECLARED
        )
    ## A LicenseExpression is built directly for the compound case so the output is always a
    ## valid CycloneDX 'expression' -- make_from_string mis-emits a compound that contains a
    ## 'LicenseRef-*' id as a single malformed license 'name'.
    return LicenseExpression(
        value=" AND ".join(used_licenses),
        acknowledgement=LicenseAcknowledgement.DECLARED,
    )


def main():
    binpkg = os.environ["BINPKG"]
    version = os.environ["VERSION"]
    deps = [dep for dep in os.environ["DEPS"].split("\n") if dep]
    section = os.environ.get("SECTION", "")
    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH", "")

    bom = Bom()
    ## No serial number: not required for CycloneDX, and a random one would
    ## break reproducibility.
    bom.serial_number = None
    ## Timestamp = SOURCE_DATE_EPOCH (the changelog release date): required by
    ## SPDX and by NTIA/BSI SBOM guidance, and reproducible because it is the
    ## source date, not wall-clock build time.
    if source_date_epoch:
        bom.metadata.timestamp = datetime.fromtimestamp(
            int(source_date_epoch), tz=timezone.utc
        )
    else:
        bom.metadata.timestamp = None

    root = deb_component(binpkg, version)
    bom.metadata.component = root

    used_licenses = reuse_used_licenses()
    if used_licenses:
        root.licenses.add(declared_license(used_licenses))
    if section:
        root.properties.add(Property(name="section", value=section))

    bom.metadata.properties.add(
        Property(
            name="genmkfile:sbom:source",
            value="debian/control top-level dependencies (Pre-Depends, Depends)",
        )
    )

    ## Dependencies are emitted by name only -- a source-release SBOM carries no
    ## dependency version numbers, by design.
    dep_components = [deb_component(dep) for dep in deps]
    for dep_component in dep_components:
        bom.components.add(dep_component)
    bom.register_dependency(root, dep_components)

    ## Generate SBOM json and normalize it.
    document = json.loads(JsonV1Dot6(bom).output_as_string(indent=2))
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
