# ugrep Harvest Toolkit

This repository contains a Python utility that orchestrates [`ugrep`](https://ugrep.com)
to crawl every accessible file within a CageFS-style environment, extract all
human-readable data, and persist the findings in a structured directory tree.
Each filesystem object produces a dedicated text artefact that records the
absolute source path, how the data was obtained (decoded or recovered via
`ugrep`), and the captured payload.

## Project Layout

- `scripts/ugrep_harvest.py` – command line interface that performs the harvest
  run.
- `tests/` – unit tests covering core helper routines.

## Prerequisites

- Python 3.10+
- `ugrep` (or compatible wrapper such as `ug+`) available on the `PATH`

## Usage

1. **Dry-run** to validate the scope without touching files:

   ```bash
   python scripts/ugrep_harvest.py --dry-run /
   ```

   The script lists how many files would be inspected and previews the output
   paths that will be created beneath `~/ugrep_harvest_runs/harvest_<timestamp>/`.

2. **Full harvest** (follows symlinks and includes hidden files):

   ```bash
   python scripts/ugrep_harvest.py --ugrep-bin ug+ /
   ```

   Useful command line flags:

   - `--output-root /path/to/dir` – choose a different parent directory for the
     timestamped run folder.
   - `--min-printable-length 6` – adjust the shortest printable sequence that
     `ugrep` keeps when falling back to binary extraction.
   - `--ugrep-args --binary-files=text` – append any additional arguments for
     `ugrep` after the printable pattern.

### Output Structure

Each execution creates a folder such as
`~/ugrep_harvest_runs/harvest_20240101_120000/` containing:

- `manifest.csv` – mapping between source files, generated artefacts, and
  capture method.
- `harvest.log` – verbose log of the run.
- `*.txt` artefacts – one per visited file.  Names encode the full source path
  (path separators become `__`) and the file body stores:

  ```text
  Source path: /path/to/file
  Captured via: decoded as utf-8
  --
  <extracted content>
  --
  ```

## Running Tests

```bash
pytest
```

The tests focus on the sanitisation helper that converts absolute paths into
filesystem-safe artefact names.
