#!/usr/bin/python3 -Bsu

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## Emit a declared-floor CycloneDX SBOM for one Debian binary package to stdout.
## Run directly as a script: sys.path[0] is this trusted install directory, not
## the scanned package's working directory, so a planted json.py in a package
## tree cannot shadow the stdlib. Inputs via environment, set by genmkfile
## make_sbom:
##   BINPKG  - binary package name
##   VERSION - package version (from debian/changelog)
##   DEPS    - newline-separated top-level dependency names (may be empty)

import json
import os


def main():
    binpkg = os.environ["BINPKG"]
    version = os.environ["VERSION"]
    deps = [dep for dep in os.environ["DEPS"].split("\n") if dep]

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "component": {
                "type": "application",
                "name": binpkg,
                "version": version,
                "purl": "pkg:deb/debian/%s@%s" % (binpkg, version),
            },
            "properties": [
                {"name": "kicksecure:sbom:tier", "value": "declared-floor"},
                {
                    "name": "kicksecure:sbom:source",
                    "value": "debian/control top-level dependencies (Pre-Depends, Depends)",
                },
            ],
        },
        "components": [
            {
                "type": "library",
                "name": dep,
                "scope": "required",
                "purl": "pkg:deb/debian/%s" % dep,
            }
            for dep in deps
        ],
    }
    print(json.dumps(bom, indent=2))


if __name__ == "__main__":
    main()
