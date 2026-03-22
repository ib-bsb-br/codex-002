#!/usr/bin/env python3
"""Filesystem harvesting utility built around ``ugrep``.

This module exposes a command line utility that enumerates every readable file
in the supplied root locations (including hidden paths and following symbolic
links) and captures any human-readable data it can extract.  By default the
script stores a text file per inspected path inside a timestamped directory in
the user's home folder.  Each generated text file embeds the original absolute
path along with either the decoded text payload or the printable sequences that
``ugrep`` could recover from binary content.  A manifest file and an execution
log are produced to simplify auditing.

The behaviour matches the user's requirements gathered in the brainstorming
step:
* include hidden files and follow symbolic links;
* attempt direct decoding first, falling back to ``ugrep`` extraction;
* create one text artefact per visited filesystem object;
* provide a dry-run mode for validation before the real harvest.

The module also exposes helper functions that are exercised via ``pytest`` to
guard core behaviours such as path sanitisation.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import hashlib
import logging
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterator, List, Optional, Sequence, Tuple

LOGGER = logging.getLogger("ugrep_harvest")

def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    """Parse command line arguments.

    Parameters
    ----------
    argv:
        Optional list of arguments (defaults to ``sys.argv[1:]``).
    """

    parser = argparse.ArgumentParser(
        description="Harvest human readable data from all files reachable from the"
        " supplied paths."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        default=[Path(".")],
        help="One or more root paths to inspect. Defaults to the current directory.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=None,
        help=(
            "Directory where harvested artefacts are stored. The script creates a "
            "timestamped sub-directory inside this path. Defaults to "
            "~/ugrep_harvest_runs."
        ),
    )
    parser.add_argument(
        "--ugrep-bin",
        default="ugrep",
        help="Executable name or path for the ugrep binary.",
    )
    parser.add_argument(
        "--ugrep-args",
        nargs=argparse.REMAINDER,
        default=None,
        help="Additional arguments passed verbatim to ugrep after the printable "
        "pattern.",
    )
    parser.add_argument(
        "--min-printable-length",
        type=int,
        default=4,
        help="Minimum length for printable sequences extracted via ugrep.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Reserved for future concurrency control (currently must be 1).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List the files that would be processed without extracting data.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level for console output.",
    )

    args = parser.parse_args(argv)
    if args.workers != 1:
        parser.error("Parallel workers are not yet supported; use --workers 1.")
    if args.min_printable_length < 1:
        parser.error("--min-printable-length must be >= 1")
    return args


def build_output_root(base: Optional[Path]) -> Path:
    """Determine and create the output directory for this run."""

    timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    if base is None:
        base = Path.home() / "ugrep_harvest_runs"
    run_dir = base.expanduser().resolve() / f"harvest_{timestamp}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def sanitise_path_for_filename(path: Path) -> str:
    """Produce a filesystem-safe representation of ``path``.

    The function preserves all components by replacing path separators with
    ``__`` markers before applying a conservative character whitelist. When the
    resulting name grows beyond 200 characters, a SHA-1 digest is appended to
    guarantee uniqueness without discarding the leading portion that remains
    human readable.
    """

    path_str = path.resolve().as_posix()
    if path_str.startswith("/"):
        path_str = path_str[1:]
    markerised = path_str.replace("/", "__") or "root"
    safe = re.sub(r"[^A-Za-z0-9_.=+\-]", "_", markerised)
    if len(safe) > 200:
        digest = hashlib.sha1(path_str.encode("utf-8", "ignore")).hexdigest()
        safe = f"{safe[:160]}__{digest}"
    return safe


def iter_files(paths: Sequence[Path]) -> Iterator[Path]:
    """Yield every file reachable from ``paths`` while avoiding symlink loops."""

    seen_dirs: set[Tuple[int, int]] = set()
    for root in paths:
        root = root.expanduser().resolve()
        if not root.exists():
            LOGGER.warning("Path does not exist: %s", root)
            continue
        if root.is_file():
            yield root
            continue
        for current, dirnames, filenames in os.walk(root, followlinks=True):
            try:
                stat_info = os.stat(current, follow_symlinks=True)
            except OSError as exc:
                LOGGER.warning("Cannot stat %s: %s", current, exc)
                continue
            key = (stat_info.st_dev, stat_info.st_ino)
            if key in seen_dirs:
                continue
            seen_dirs.add(key)
            # Filter directories already visited to break cycles proactively.
            pruned_dirs: List[str] = []
            for dname in dirnames:
                dpath = Path(current) / dname
                try:
                    dstat = os.stat(dpath, follow_symlinks=True)
                except OSError:
                    continue
                dkey = (dstat.st_dev, dstat.st_ino)
                if dkey in seen_dirs:
                    continue
                pruned_dirs.append(dname)
            dirnames[:] = pruned_dirs
            for fname in filenames:
                yield Path(current) / fname


def attempt_text_read(path: Path) -> Tuple[Optional[str], Optional[str]]:
    """Try decoding ``path`` as text with a series of encodings."""

    encodings = ["utf-8", "utf-16", "utf-16-le", "utf-16-be", "latin-1"]
    for encoding in encodings:
        try:
            with path.open("r", encoding=encoding) as handle:
                data = handle.read()
            if "\x00" in data:
                # Likely binary; try next strategy.
                continue
            return data, encoding
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            LOGGER.warning("Failed to read %s: %s", path, exc)
            return None, None
    return None, None


def extract_with_ugrep(
    path: Path,
    ugrep_bin: str,
    min_printable_length: int,
    extra_args: Optional[Sequence[str]] = None,
) -> str:
    """Run ``ugrep`` to extract printable sequences from ``path``."""

    pattern = f"[[:print:]]{{{min_printable_length},}}"
    command: List[str] = [ugrep_bin, "-a", "-o", "--color=never", pattern, str(path)]
    if extra_args:
        command = [ugrep_bin, "-a", "-o", "--color=never"] + list(extra_args) + [pattern, str(path)]
    try:
        proc = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Could not find ugrep executable '{ugrep_bin}'."
        ) from exc
    if proc.returncode not in (0, 1):
        LOGGER.warning("ugrep failed for %s with code %s: %s", path, proc.returncode, proc.stderr.strip())
    return proc.stdout.strip()


def write_output_file(
    output_file: Path,
    source_path: Path,
    content: str,
    provenance: str,
) -> None:
    """Write captured content together with metadata into ``output_file``."""

    output_file.parent.mkdir(parents=True, exist_ok=True)
    header = [
        f"Source path: {source_path}",
        f"Captured via: {provenance}",
        "--",
    ]
    with output_file.open("w", encoding="utf-8") as handle:
        for line in header:
            handle.write(line + "\n")
        if content:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
        handle.write("--\n")


def process_single_file(
    path: Path,
    output_dir: Path,
    ugrep_bin: str,
    min_printable_length: int,
    extra_ugrep_args: Optional[Sequence[str]] = None,
    dry_run: bool = False,
) -> Tuple[str, str, str]:
    """Inspect ``path`` and persist harvested data.

    Returns a tuple ``(status, output_path, note)`` suitable for manifest logging.
    """

    output_name = sanitise_path_for_filename(path)
    output_file = output_dir / f"{output_name}.txt"
    if dry_run:
        return "dry-run", str(output_file), "Skipped (dry-run)"

    decoded, encoding = attempt_text_read(path)
    if decoded is not None and encoding is not None:
        write_output_file(output_file, path, decoded, f"decoded as {encoding}")
        return "decoded", str(output_file), f"encoding={encoding}"

    extracted = extract_with_ugrep(path, ugrep_bin, min_printable_length, extra_ugrep_args)
    provenance = "ugrep printable sequences"
    if not extracted:
        provenance = "no readable data found"
    write_output_file(output_file, path, extracted, provenance)
    return "ugrep" if extracted else "empty", str(output_file), provenance


def configure_logging(level: str, log_file: Path) -> None:
    """Configure logging for console and file output."""

    log_level = getattr(logging, level.upper(), logging.INFO)
    LOGGER.setLevel(log_level)
    formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(formatter)
    LOGGER.addHandler(console_handler)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    LOGGER.addHandler(file_handler)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_arguments(argv)
    run_dir = build_output_root(args.output_root)
    log_path = run_dir / "harvest.log"
    configure_logging(args.log_level, log_path)

    LOGGER.info("Starting harvest run. Output directory: %s", run_dir)

    file_list = list(iter_files(args.paths))
    if args.dry_run:
        LOGGER.info("Dry-run mode enabled. %d files would be processed.", len(file_list))
        for sample in file_list[:10]:
            LOGGER.info("Would create: %s", run_dir / f"{sanitise_path_for_filename(sample)}.txt")
        return 0

    manifest_path = run_dir / "manifest.csv"
    with manifest_path.open("w", encoding="utf-8", newline="") as manifest:
        writer = csv.writer(manifest)
        writer.writerow(["source_path", "output_file", "status", "note"])
        processed = 0
        for file_path in file_list:
            status, output_path, note = process_single_file(
                file_path,
                run_dir,
                args.ugrep_bin,
                args.min_printable_length,
                args.ugrep_args,
                dry_run=False,
            )
            writer.writerow([str(file_path), output_path, status, note])
            processed += 1
            if processed % 50 == 0:
                LOGGER.info("Processed %d/%d files", processed, len(file_list))

    LOGGER.info("Harvest completed. %d files processed. Manifest: %s", len(file_list), manifest_path)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    sys.exit(main())
