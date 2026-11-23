#!/usr/bin/env python3
"""Build the RC4 payload from the exact reviewed RC2 input."""

import argparse
import gzip
import hashlib
from io import BytesIO
from pathlib import Path
import tarfile


INPUT_DIGEST = "832452bfe1e36e91e89a478f866d93e972a80a9d9306aa40f8b509f0eb8b8a9b"


def repack(source, output):
    with source.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != INPUT_DIGEST:
            raise ValueError("Unexpected reviewed RC2 input SHA-256")
    with tarfile.open(source, "r:gz") as original, output.open("xb") as raw, \
            gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=0) as zipped, \
            tarfile.open(fileobj=zipped, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        for member in original:
            archive.addfile(member, original.extractfile(member) if member.isfile() else None)
        prefix = "x-ui/nginx-openssl"
        directory = tarfile.TarInfo(prefix)
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        manifest = ""
        for name in ("libcrypto.so.3", "libssl.so.3"):
            with original.extractfile("x-ui/certbot/" + name) as stream:
                contents = stream.read()
            member = tarfile.TarInfo(prefix + "/" + name)
            member.size = len(contents)
            archive.addfile(member, BytesIO(contents))
            manifest += f"{hashlib.sha256(contents).hexdigest()}  {name}\n"
        member = tarfile.TarInfo(prefix + "/SHA256SUMS")
        member.size = len(manifest)
        archive.addfile(member, BytesIO(manifest.encode("ascii")))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    repack(arguments.source, arguments.output)
