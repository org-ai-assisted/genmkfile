#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Emit a declared-floor CycloneDX SBOM for one Debian binary package to stdout,
## using the official OWASP CycloneDX library (python3-cyclonedx-lib) and the
## reference purl library (python3-packageurl) so the document and its purls are
## canonical and schema-valid. Run directly as a script: sys.path[0] is this
## trusted install directory, not the scanned package's working directory, so a
## planted module in a package tree cannot shadow the stdlib or these imports.
## Output is deterministic (no serial number, no timestamp, purl-based
## bom-refs) so a committed, regenerated SBOM does not churn. Inputs via
## environment, set by genmkfile make_sbom:
##   BINPKG  - binary package name
##   VERSION - package version (from debian/changelog)
##   DEPS    - newline-separated top-level dependency names (may be empty)

import json
import os

from cyclonedx.model import Property
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.output.json import JsonV1Dot6
from packageurl import PackageURL


def deb_component(name, component_type, version=None):
    purl = PackageURL(type="deb", namespace="debian", name=name, version=version)
    return Component(
        name=name,
        version=version,
        type=component_type,
        bom_ref=purl.to_string(),
        purl=purl,
    )


def main():
    binpkg = os.environ["BINPKG"]
    version = os.environ["VERSION"]
    deps = [dep for dep in os.environ["DEPS"].split("\n") if dep]

    bom = Bom()
    bom.serial_number = None
    bom.metadata.timestamp = None
    root = deb_component(binpkg, ComponentType.APPLICATION, version)
    bom.metadata.component = root
    bom.metadata.properties.add(
        Property(name="kicksecure:sbom:tier", value="declared-floor")
    )
    bom.metadata.properties.add(
        Property(
            name="kicksecure:sbom:source",
            value="debian/control top-level dependencies (Pre-Depends, Depends)",
        )
    )

    dep_components = [deb_component(dep, ComponentType.LIBRARY) for dep in deps]
    for dep_component in dep_components:
        bom.components.add(dep_component)
    ## Link the root component to its declared top-level dependencies so the
    ## CycloneDX dependency graph is complete (also silences the library's
    ## incomplete-graph warning).
    bom.register_dependency(root, dep_components)

    ## Re-serialize the library output to the repo's canonical JSON form (sorted
    ## keys, 2-space indent, trailing newline from print) so the committed file
    ## passes the pretty-format-json gate and stays byte-stable. Key order is not
    ## significant in JSON, so sorting keeps the document valid CycloneDX.
    document = json.loads(JsonV1Dot6(bom).output_as_string(indent=2))
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
