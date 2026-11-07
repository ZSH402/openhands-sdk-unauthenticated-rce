#!/usr/bin/env python3
"""Evidence sealing: content-addressed blobs + a manifest anyone can re-verify.

Usage:
    seal_evidence.py <evidence-dir>            # seal (idempotent)
    seal_evidence.py --verify <evidence-dir>   # re-verify every blob and source

Sealing writes:
    <dir>/blobs/<aa>/<sha256>.bin   verbatim copy, addressed by content
    <dir>/MANIFEST.json             path, size, mtime, sha256 per source file
    <dir>/MANIFEST.json.sha256      digest of MANIFEST.json itself
and prints the sha256 of MANIFEST.json.

Re-sealing an unchanged directory reuses the existing manifest verbatim, so the
digest stays stable; that is what makes the recorded digest meaningful.

Verification recomputes every hash and exits non-zero on any mismatch, including
files that appeared after sealing and a manifest that no longer covers the
directory. The point is that a third party can run this and get an answer
without trusting the report.

Residual limit, stated rather than papered over: someone who rewrites the
sources, the blobs and the manifest together produces a self-consistent
directory. What breaks that is the digest printed at seal time and recorded in
the report — recomputing it here yields a different value.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone

MANIFEST = "MANIFEST.json"
MANIFEST_DIGEST = "MANIFEST.json.sha256"
BLOBS = "blobs"
CHUNK = 1 << 20


def sha256_file(path: str) -> tuple[str, int]:
    h = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            h.update(chunk)
            total += len(chunk)
    return h.hexdigest(), total


def blob_path(root: str, digest: str) -> str:
    return os.path.join(root, BLOBS, digest[:2], digest + ".bin")


def reserved(root: str) -> set[str]:
    return {
        os.path.join(root, MANIFEST),
        os.path.join(root, MANIFEST_DIGEST),
    }


def iter_sources(root: str):
    skip = reserved(root)
    blobs_dir = os.path.join(root, BLOBS)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if os.path.join(dirpath, d) != blobs_dir)
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            if path in skip:
                continue
            yield path


def build_entries(root: str) -> list[dict]:
    entries = []
    for path in iter_sources(root):
        digest, size = sha256_file(path)
        dest = blob_path(root, digest)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if not os.path.exists(dest):
            shutil.copyfile(path, dest)
        entries.append({
            "path": os.path.relpath(path, root),
            "size": size,
            "mtime": datetime.fromtimestamp(os.path.getmtime(path), timezone.utc).isoformat(),
            "sha256": digest,
            "blob": os.path.relpath(dest, root),
        })
    return entries


def seal(root: str) -> int:
    entries = build_entries(root)
    manifest_path = os.path.join(root, MANIFEST)
    digest_path = os.path.join(root, MANIFEST_DIGEST)

    # Idempotence: an unchanged file set keeps the previous manifest byte for
    # byte, so the digest a report quotes stays reproducible.
    reuse = False
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, encoding="utf-8") as fh:
                previous = json.load(fh)
            reuse = previous.get("files") == entries and previous.get("count") == len(entries)
        except (json.JSONDecodeError, OSError):
            reuse = False

    if reuse:
        print(f"unchanged: {len(entries)} file(s), manifest kept as-is")
    else:
        manifest = {
            "sealed_at": datetime.now(timezone.utc).isoformat(),
            "root": os.path.abspath(root),
            "count": len(entries),
            "total_bytes": sum(e["size"] for e in entries),
            "files": entries,
        }
        with open(manifest_path, "w", encoding="utf-8") as fh:
            json.dump(manifest, fh, indent=2, ensure_ascii=False, sort_keys=False)
            fh.write("\n")
        print(f"sealed {len(entries)} file(s), {manifest['total_bytes']} bytes")

    digest, size = sha256_file(manifest_path)
    with open(digest_path, "w", encoding="utf-8") as fh:
        fh.write(f"{digest}  {MANIFEST}\n")

    print(f"{MANIFEST} sha256 = {digest}  ({size} bytes)")
    print("record that digest in the report; a verifier can re-run this script with --verify")
    return 0


def verify(root: str) -> int:
    manifest_path = os.path.join(root, MANIFEST)
    digest_path = os.path.join(root, MANIFEST_DIGEST)
    if not os.path.exists(manifest_path):
        print(f"NO MANIFEST: {MANIFEST} is missing from {root}", file=sys.stderr)
        return 2

    with open(manifest_path, encoding="utf-8") as fh:
        raw = fh.read()
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"BROKEN MANIFEST: {exc}", file=sys.stderr)
        return 1

    # A manifest stripped down to {} must fail loudly, not verify zero files and
    # print OK. Destroying the seal is not the same as satisfying it.
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        print(f"BROKEN MANIFEST: no 'files' list in {MANIFEST}", file=sys.stderr)
        return 1
    if manifest.get("count") != len(manifest["files"]):
        print(
            f"BROKEN MANIFEST: count={manifest.get('count')!r} but {len(manifest['files'])} entries",
            file=sys.stderr,
        )
        return 1

    failures = 0
    manifest_paths = {entry.get("path") for entry in manifest["files"]}

    actual_paths = {os.path.relpath(p, root) for p in iter_sources(root)}
    for extra in sorted(actual_paths - manifest_paths):
        print(f"UNSEALED {extra}  (appeared after sealing)", file=sys.stderr)
        failures += 1

    for entry in manifest["files"]:
        src = os.path.join(root, entry["path"])
        blob = os.path.join(root, entry["blob"])
        expected = entry["sha256"]

        if not os.path.exists(src):
            print(f"MISSING source {entry['path']}", file=sys.stderr)
            failures += 1
        else:
            got, size = sha256_file(src)
            if got != expected or size != entry["size"]:
                print(f"CHANGED {entry['path']}  expected={expected[:16]} got={got[:16]}", file=sys.stderr)
                failures += 1

        if not os.path.exists(blob):
            print(f"MISSING blob {entry['blob']}", file=sys.stderr)
            failures += 1
        else:
            got_blob, _ = sha256_file(blob)
            if got_blob != expected:
                print(f"CORRUPT blob {entry['blob']}", file=sys.stderr)
                failures += 1

    digest, _ = sha256_file(manifest_path)
    if os.path.exists(digest_path):
        with open(digest_path, encoding="utf-8") as fh:
            parts = fh.read().split()
        recorded = parts[0] if parts else ""
        if recorded and recorded != digest:
            print(
                f"MANIFEST REWRITTEN  expected={recorded[:16]} got={digest[:16]}",
                file=sys.stderr,
            )
            failures += 1

    print(f"{MANIFEST} sha256 = {digest}")
    if failures:
        print(f"FAILED: {failures} problem(s)", file=sys.stderr)
        return 1
    print(f"OK: {len(manifest['files'])} file(s) verified, nothing changed")
    return 0


def main() -> int:
    args = [a for a in sys.argv[1:] if a]
    if not args:
        print(__doc__, file=sys.stderr)
        return 2
    if args[0] == "--verify":
        if len(args) < 2:
            print("--verify needs a directory", file=sys.stderr)
            return 2
        return verify(args[1])
    if not os.path.isdir(args[0]):
        print(f"not a directory: {args[0]}", file=sys.stderr)
        return 2
    return seal(args[0])


if __name__ == "__main__":
    sys.exit(main())
