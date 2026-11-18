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
from cyclonedx.model.license import LicenseAcknowledgement
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


def reuse_license_expression():
    ## SPDX license from REUSE metadata (REUSE.toml / .reuse/dep5), via
    ## 'reuse lint --json' .summary.used_licenses -- the set of ids actually
    ## referenced by a file, so it does not drift. Joined into one SPDX 'AND'
    ## expression, emitted DECLARED. genmkfile make_require's 'reuse' when this
    ## metadata is present, so a missing tool fails loud there, not here.
    if not (os.path.exists("REUSE.toml") or os.path.exists(".reuse/dep5")):
        return None
    result = subprocess.run(
        ["reuse", "lint", "--json"],
        stdout=subprocess.PIPE,
        text=True,
        check=False,
    )
    used_licenses = sorted(set(json.loads(result.stdout)["summary"]["used_licenses"]))
    if not used_licenses:
        return None
    return " AND ".join(used_licenses)


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

    license_expr = reuse_license_expression()
    if license_expr:
        root.licenses.add(
            LicenseFactory().make_from_string(
                license_expr, license_acknowledgement=LicenseAcknowledgement.DECLARED
            )
        )
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
