#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-assisted.

## Generates an SBOM for a package in CycloneDX format, and outputs it to
## stdout.

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
        Property(
            name="genmkfile:sbom:source",
            value="debian/control top-level dependencies (Pre-Depends, Depends)",
        )
    )

    ## FIXME: This will generate contradictory information across SBOMs.
    ## helper-scripts for instance will declare itself as an application but
    ## anything depending on it will call it a library.
    ##
    ## FIXME: No version information is included for dependencies.
    dep_components = [deb_component(dep, ComponentType.LIBRARY) for dep in deps]
    for dep_component in dep_components:
        bom.components.add(dep_component)
    bom.register_dependency(root, dep_components)

    ## Generate SBOM json and normalize it.
    document = json.loads(JsonV1Dot6(bom).output_as_string(indent=2))
    print(json.dumps(document, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
