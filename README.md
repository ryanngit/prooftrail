# prooftrail

Bundle command results, git diffs, and screenshots into a local proof folder.

Prooftrail is a small file-first CLI for collecting review evidence from local code work. It runs any command as opaque evidence, copies selected artifacts, records opportunistic git status and diffs, and writes a portable folder with Markdown and JSON indexes.

It is local-only: no account, service, telemetry, browser control, or network connection is required.

## Install From Source

Requirements:

- Python 3.11 or newer.
- Git is optional. When Git is unavailable or the current folder is not a worktree, prooftrail still writes command evidence.

Clone or copy this folder, then run prooftrail directly:

```powershell
python prooftrail.py --help
```

On Windows, the included wrapper can be used from this folder:

```powershell
.\prooftrail.cmd --help
```

## Quick Start

```powershell
prooftrail run --out proof --project notes-cli -- python tests.py
```

The command above creates `proof\SUMMARY.md`, `proof\commands.jsonl`, `proof\manifest.json`, `proof\REDACTION.md`, `proof\prooftrail.log`, and redacted stdout/stderr artifacts.

## Import Existing Artifacts

```powershell
prooftrail import --out proof --project notes-cli --command "python tests.py" --stdout stdout.txt --stderr stderr.txt --screenshot screen.png
```

Screenshots are copied as binary files. The MVP does not inspect or visually redact image contents.

## Proof Folder Contents

| Path | Purpose |
| --- | --- |
| `SUMMARY.md` | Human-readable entry point for the captured evidence. |
| `commands.jsonl` | One machine-readable command record per captured command. |
| `manifest.json` | Machine-readable index of proof files and hashes. |
| `REDACTION.md` | Privacy and secret-check report. |
| `prooftrail.log` | Tool event log. It does not include raw command output. |
| `artifacts/commands/` | Redacted stdout and stderr text artifacts. |
| `git/` | Optional git status and diff artifacts when available. |
| `screenshots/` | Optional copied image files. |

## Evidence Boundary

Prooftrail records captured evidence. It does not prove code correctness, security, deployability, review quality, or production readiness.

## Privacy

Prooftrail runs local redaction checks before writing shareable summaries. High-confidence secrets block finalization. Medium-severity private data is redacted in text artifacts and listed in `REDACTION.md`.

Secret checks are a best-effort safety net, not a security guarantee. Review proof folders before sharing them.

## Examples

See `examples/session.txt` for a small fake project session and `examples/proof/SUMMARY.md` for generated example output.

## Non-Goals

- No correctness certification.
- No security certification.
- No hosted archive or cloud sync.
- No browser automation.
- No package-manager publishing in this source snapshot.

## License

MIT. See `LICENSE`.
