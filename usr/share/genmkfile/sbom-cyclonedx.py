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
import urllib.parse


def purl_encode(component):
    ## Percent-encode a purl component per the purl spec: everything outside the
    ## RFC-3986 unreserved set (A-Z a-z 0-9 - . _ ~), so an epoch ':' becomes
    ## '%3A' and a '+' (e.g. in 'libstdc++6') becomes '%2B'.
    return urllib.parse.quote(component, safe="")


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
                "purl": "pkg:deb/debian/%s@%s" % (purl_encode(binpkg), purl_encode(version)),
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
                "purl": "pkg:deb/debian/%s" % purl_encode(dep),
            }
            for dep in deps
        ],
    }
    print(json.dumps(bom, indent=2))


if __name__ == "__main__":
    main()
