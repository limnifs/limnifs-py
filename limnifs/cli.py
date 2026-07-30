"""``limni-py`` -- read-only CLI for the Python reference reader.

Mirrors a subset of the Rust ``limni`` CLI's ``verify`` subcommand so
differential testing can compare both binaries' output for the same
image.
"""

from __future__ import annotations

import json
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from limnifs.cursor import Cursor
from limnifs.error import ParseError
from limnifs.feature_flags import parse_feature_flags_section
from limnifs.header import parse_manifest_header
from limnifs.history import parse_history_section
from limnifs.inode import ContentHandleKind
from limnifs.merkle import (
    SectionHashes,
    compute_merkle_root,
    hash_empty_section,
    hash_section,
)
from limnifs.metadata import parse_metadata_blob
from limnifs.metadata_reference import parse_metadata_reference_section
from limnifs.slab_index import parse_slab_index_section


def _read_file(path: Path) -> bytes:
    with path.open("rb") as fp:
        return fp.read()


def _content_handle_kind_tag(kind: ContentHandleKind) -> int:
    return {
        ContentHandleKind.INLINE_DATA: 1,
        ContentHandleKind.SLICE_MAP: 2,
        ContentHandleKind.DIRECTORY: 3,
        ContentHandleKind.SYMLINK: 4,
        ContentHandleKind.DEVICE: 5,
        ContentHandleKind.PIPE: 6,
    }[kind]


def _metadata_summary(blob_bytes: bytes) -> dict[str, object]:
    blob = parse_metadata_blob(Cursor(blob_bytes))
    inodes = sorted(
        (
            {
                "number": i.number,
                "mode": i.mode,
                "kind": _content_handle_kind_tag(i.content_handle.kind),
            }
            for i in blob.inodes
        ),
        key=lambda d: d["number"],
    )
    dir_nodes = sorted(
        (
            {
                "entries": len(n.entries),
                "first": n.entries[0].name if n.entries else "",
            }
            for n in blob.dir_nodes
        ),
        key=lambda d: (d["entries"], d["first"]),
    )
    root = blob.root_inode_number()
    return {
        "metadata_inode_count": len(blob.inodes),
        "metadata_dir_node_count": len(blob.dir_nodes),
        "metadata_root_inode": root,
        "metadata_inodes": inodes,
        "metadata_dir_nodes": dir_nodes,
    }


def _verify_bytes(buf: bytes) -> dict[str, object]:
    cursor = Cursor(buf)

    header_start = cursor.position
    header = parse_manifest_header(cursor)
    header_end = cursor.position

    flags_start = cursor.position
    flags = parse_feature_flags_section(cursor)
    flags_end = cursor.position

    meta_ref_start = cursor.position
    metadata_reference = parse_metadata_reference_section(cursor)
    meta_ref_end = cursor.position

    slab_index_start = cursor.position
    slab_index = parse_slab_index_section(cursor)
    slab_index_end = cursor.position

    # Optional sections based on feature flags.
    ec_params_start = cursor.position
    has_ec = flags.get(0x0001) is not None
    if has_ec:
        from limnifs.ec_params import parse_ec_params_section
        parse_ec_params_section(cursor)
    ec_params_end = cursor.position

    dms_policy_start = cursor.position
    has_dms = flags.get(0x0002) is not None
    if has_dms:
        from limnifs.dms_policy import parse_dms_policy_section
        parse_dms_policy_section(cursor)
    dms_policy_end = cursor.position

    history_start = cursor.position
    history = parse_history_section(cursor)
    history_end = cursor.position

    extra_bytes_after_history = cursor.remaining_len

    section_hashes = SectionHashes(
        metadata=metadata_reference.metadata_hash,
        format_header=hash_section(buf[header_start:header_end]),
        feature_flags=hash_section(buf[flags_start:flags_end]),
        metadata_reference=hash_section(buf[meta_ref_start:meta_ref_end]),
        slab_index=hash_section(buf[slab_index_start:slab_index_end]),
        crypto_params=hash_empty_section(),
        ec_params=(
            hash_section(buf[ec_params_start:ec_params_end])
            if has_ec
            else hash_empty_section()
        ),
        dms_policy=(
            hash_section(buf[dms_policy_start:dms_policy_end])
            if has_dms
            else hash_empty_section()
        ),
        delta_linkage=hash_empty_section(),
        history=hash_section(buf[history_start:history_end]),
    )
    merkle_root = compute_merkle_root(section_hashes)

    report: dict[str, object] = {
        "magic": "LMFS",
        "drop_store_version": header.drop_store_version,
        "metadata_version": header.metadata_version,
        "manifest_version": header.manifest_version,
        "feature_flags": [
            {"flag_id": e.flag_id, "required": e.required} for e in flags.entries
        ],
        "metadata_inlined": metadata_reference.is_inlined,
        "slab_index_entries": len(slab_index),
        "history_entries": len(history),
        "extra_bytes_after_history": extra_bytes_after_history,
        "merkle_root": str(merkle_root),
    }

    if metadata_reference.is_inlined and metadata_reference.inline_metadata:
        try:
            report.update(_metadata_summary(metadata_reference.inline_metadata))
        except ParseError:
            pass

    return report


def _print_human(path: Path, report: dict[str, object]) -> None:
    print(f"{path}: valid LimniFS manifest")
    print("  magic:               LMFS")
    print(f"  drop store version:  {report['drop_store_version']}")
    print(f"  metadata version:    {report['metadata_version']}")
    print(f"  manifest version:    {report['manifest_version']}")
    flags = report["feature_flags"]
    flag_list: list[dict[str, object]] = list(flags) if isinstance(flags, list) else []
    if not flag_list:
        print("  feature flags:       0 entries")
    else:
        print(f"  feature flags:       {len(flag_list)} entries")
        for entry in flag_list:
            kind = "required" if entry["required"] else "optional"
            print(f"    0x{entry['flag_id']:04X}            {kind}")
    metadata_kind = "inlined" if report["metadata_inlined"] else "external"
    print(f"  metadata:            {metadata_kind}")
    print(f"  slab index:          {report['slab_index_entries']} entries")
    print(f"  history:             {report['history_entries']} entries")
    if int(report["extra_bytes_after_history"]) > 0:
        print(
            f"  warning:             {report['extra_bytes_after_history']} extra bytes "
            f"after history (optional sections present, not parsed)"
        )
    print(f"  merkle root:         {report['merkle_root']}")


def _print_json(path: Path, report: dict[str, object]) -> None:
    payload = {"path": str(path), **report}
    print(json.dumps(payload))


def _cmd_verify(args: Namespace) -> int:
    path = Path(args.image)
    try:
        buf = _read_file(path)
        report = _verify_bytes(buf)
    except ParseError as e:
        print(f"limni-py: {path}: {e}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"limni-py: cannot read {path}: {e}", file=sys.stderr)
        return 1

    if args.json:
        _print_json(path, report)
    else:
        _print_human(path, report)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(
        prog="limni-py",
        description="Python reference reader for the LimniFS format",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser(
        "verify", help="Validate a manifest and compute its ManifestRoot"
    )
    verify.add_argument("image", help="Path to the .lim image to inspect")
    verify.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )
    verify.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
