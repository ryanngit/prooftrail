import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


VERSION = "0.1.0"
EXIT_USAGE = 64
EXIT_INPUT = 65
EXIT_REDACTION = 66
EXIT_INTERNAL = 70
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
BOUNDARY_TEXT = (
    "This folder records evidence captured by prooftrail. It does not prove code "
    "correctness, security, deployability, review quality, or production readiness."
)
CREDENTIAL_URL_PATTERN = r"[a-z][a-z0-9+.-]*" + r"://" + r"[^:\s/@]+:[^@\s]+@[^/\s]+"

HIGH_DETECTORS = [
    ("secret.private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("secret.api_key_assignment", re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*[\"']?[^\s\"']{8,}")),
    ("secret.password_assignment", re.compile(r"(?i)\b(passwd|password|secret)\s*[:=]\s*[\"']?[^\s\"']{8,}")),
    ("secret.token_assignment", re.compile(r"(?i)\b(token|access[_-]?key|secret[_-]?key)\s*[:=]\s*[\"']?[^\s\"']{8,}")),
    ("secret.openai_key", re.compile(r"\bsk-[A-Za-z0-9][A-Za-z0-9_-]{10,}\b")),
    ("secret.github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("secret.npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{10,}\b")),
    ("secret.aws_access_key", re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b")),
    ("secret.credential_url", re.compile(CREDENTIAL_URL_PATTERN, re.IGNORECASE)),
    ("secret.bearer_jwt", re.compile(r"(?i)\b(authorization|bearer|token|cookie)\b[^\n]{0,80}\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
]

MEDIUM_DETECTORS = [
    ("pii.email", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
    ("pii.phone", re.compile(r"(?<!\d)(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}(?!\d)")),
]


class ToolError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def now():
    return datetime.now().astimezone()


def iso(dt):
    return dt.isoformat(timespec="seconds")


def proof_id(dt):
    return dt.strftime("proof-%Y%m%d-%H%M%S")


def display_path(path):
    text = str(Path(path).resolve())
    home = str(Path.home())
    if text.lower().startswith(home.lower()):
        return "~" + text[len(home):]
    return text


def rel(path, root):
    return Path(path).relative_to(root).as_posix()


def command_text(command):
    try:
        return subprocess.list2cmdline(command)
    except Exception:
        return " ".join(command)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def add_finding(findings, severity, detector_id, count, artifact_path):
    if count:
        findings.append({
            "severity": severity,
            "detector_id": detector_id,
            "count": count,
            "artifact_path": artifact_path,
        })


def scan_high(texts):
    findings = []
    for artifact_path, text in texts.items():
        for detector_id, pattern in HIGH_DETECTORS:
            add_finding(findings, "high", detector_id, len(pattern.findall(text)), artifact_path)
    return findings


def redact_medium(texts):
    findings = []
    redacted = {}
    home_variants = [str(Path.home()), str(Path.home()).replace("\\", "/")]
    for artifact_path, original in texts.items():
        text = original
        for home in home_variants:
            if home:
                count = text.lower().count(home.lower())
                if count:
                    text = re.sub(re.escape(home), "~", text, flags=re.IGNORECASE)
                    add_finding(findings, "medium", "pii.home_path", count, artifact_path)
        for detector_id, pattern in MEDIUM_DETECTORS:
            matches = pattern.findall(text)
            count = len(matches)
            if count:
                text = pattern.sub(f"[REDACTED:{detector_id}:{count}]", text)
                add_finding(findings, "medium", detector_id, count, artifact_path)
        redacted[artifact_path] = text
    return redacted, findings


def redaction_status(findings):
    if any(f["severity"] == "high" for f in findings):
        return "blocked"
    if findings:
        return "redacted"
    return "clean"


def finding_summary(findings):
    counts = {}
    for item in findings:
        key = item["severity"]
        counts[key] = counts.get(key, 0) + item["count"]
    return counts


def prepare_output(out, overwrite):
    out = Path(out)
    if out.exists():
        if not overwrite:
            raise ToolError(EXIT_USAGE, f"output folder exists: {display_path(out)}")
        if out.is_dir():
            shutil.rmtree(out)
        else:
            out.unlink()
    out.mkdir(parents=True, exist_ok=False)
    return out


def log_event(out, event, detail):
    safe_detail = detail.replace("\r", " ").replace("\n", " ")
    with (out / "prooftrail.log").open("a", encoding="utf-8") as f:
        f.write(f"{iso(now())}\t{event}\t{safe_detail}\n")


def write_text(out, relative_path, text):
    path = out / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


def write_json(out, relative_path, data):
    path = out / relative_path
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return path


def validate_text_file(path):
    path = Path(path)
    if not path.exists() or not path.is_file():
        raise ToolError(EXIT_INPUT, f"missing input path: {display_path(path)}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        raise ToolError(EXIT_INPUT, f"input is not utf-8 text: {display_path(path)}")


def validate_screenshot(path):
    path = Path(path)
    if not path.exists() or not path.is_file():
        raise ToolError(EXIT_INPUT, f"missing screenshot path: {display_path(path)}")
    if path.suffix.lower() not in IMAGE_EXTENSIONS:
        raise ToolError(EXIT_USAGE, f"unsupported screenshot extension: {path.suffix}")
    return path


def run_git(cwd, args):
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def git_available(cwd):
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=cwd,
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        return False
    return result.returncode == 0 and result.stdout.strip() == "true"


def git_head_label(cwd):
    branch = run_git(cwd, ["branch", "--show-current"]).strip()
    if branch:
        return branch
    head = run_git(cwd, ["rev-parse", "--short", "HEAD"]).strip()
    return head or "unknown"


def capture_git_before(cwd, git_mode):
    info = {
        "available": False,
        "mode": git_mode,
        "diff_mode": "off",
        "head": "",
        "status_before_path": None,
        "status_after_path": None,
        "diff_stat_path": None,
        "diff_name_status_path": None,
        "diff_path": None,
        "cached_diff_path": None,
    }
    if git_mode == "off" or not git_available(cwd):
        return info, {}
    info["available"] = True
    info["head"] = git_head_label(cwd)
    info["status_before_path"] = "git/status.before.txt"
    return info, {"git/status.before.txt": run_git(cwd, ["status", "--short", "--branch"])}


def capture_git_after(cwd, info, diff_mode):
    artifacts = {}
    if not info["available"]:
        return artifacts
    info["diff_mode"] = diff_mode
    info["status_after_path"] = "git/status.after.txt"
    artifacts["git/status.after.txt"] = run_git(cwd, ["status", "--short", "--branch"])
    if diff_mode in {"summary", "full"}:
        info["diff_stat_path"] = "git/diff.stat.txt"
        info["diff_name_status_path"] = "git/diff.name-status.txt"
        artifacts["git/diff.stat.txt"] = run_git(cwd, ["diff", "--stat"])
        artifacts["git/diff.name-status.txt"] = run_git(cwd, ["diff", "--name-status"])
    if diff_mode == "full":
        info["diff_path"] = "git/git.diff"
        info["cached_diff_path"] = "git/git.cached.diff"
        artifacts["git/git.diff"] = run_git(cwd, ["diff", "--no-ext-diff"])
        artifacts["git/git.cached.diff"] = run_git(cwd, ["diff", "--cached", "--no-ext-diff"])
    return artifacts


def artifact_record(out, relative_path, kind, status):
    path = out / relative_path
    return {
        "path": relative_path,
        "kind": kind,
        "sha256": sha256_file(path),
        "bytes": path.stat().st_size,
        "redaction_status": status,
    }


def screenshot_record(path, relative_path):
    copied = Path(path)
    return {
        "path": relative_path,
        "kind": "screenshot",
        "sha256": sha256_file(copied),
        "bytes": copied.stat().st_size,
        "extension": copied.suffix.lower(),
    }


def write_redaction_report(out, findings):
    status = redaction_status(findings)
    lines = [
        "# Redaction Report",
        "",
        "## Status",
        "",
        status,
        "",
        "## Findings",
        "",
    ]
    if findings:
        lines.extend(["| Severity | Detector | Count | Artifact |", "| --- | --- | ---: | --- |"])
        for item in findings:
            lines.append(f"| {item['severity']} | {item['detector_id']} | {item['count']} | {item['artifact_path']} |")
    else:
        lines.append("No findings.")
    lines.extend([
        "",
        "## Policy",
        "",
        "High-confidence secrets block finalization. Medium-severity private data is redacted in text artifacts and recorded here.",
        "",
    ])
    write_text(out, "REDACTION.md", "\n".join(lines))


def write_block_report(out, findings):
    lines = [
        "# Redaction Blocked",
        "",
        "## Status",
        "",
        "blocked",
        "",
        "## Findings",
        "",
        "| Severity | Detector | Count | Artifact |",
        "| --- | --- | ---: | --- |",
    ]
    for item in findings:
        lines.append(f"| {item['severity']} | {item['detector_id']} | {item['count']} | {item['artifact_path']} |")
    lines.extend([
        "",
        "## Policy",
        "",
        "Final shareable files were not written because high-confidence secret patterns were detected.",
        "",
    ])
    write_text(out, "REDACTION_BLOCKED.md", "\n".join(lines))


def write_summary(out, context, command_record, manifest, findings):
    git = manifest["git"]
    if git["available"]:
        git_lines = [
            f"- Git evidence: captured for `{git.get('head') or 'unknown'}`.",
            f"- Before status: `{git['status_before_path']}`",
            f"- After status: `{git['status_after_path']}`",
            f"- Diff mode: `{git['diff_mode']}`",
        ]
        for key in ["diff_stat_path", "diff_name_status_path", "diff_path", "cached_diff_path"]:
            if git.get(key):
                git_lines.append(f"- {key.replace('_', ' ')}: `{git[key]}`")
    elif git["mode"] == "off":
        git_lines = ["- Git evidence skipped: git-mode off."]
    else:
        git_lines = ["- Git evidence skipped: not a git worktree."]

    artifact_lines = []
    for item in manifest["artifacts"]:
        artifact_lines.append(f"- `{item['kind']}`: `{item['path']}`")
    for item in manifest["screenshots"]:
        artifact_lines.append(f"- screenshot copied without visual redaction: `{item['path']}`")
    if not artifact_lines:
        artifact_lines.append("- No copied artifacts.")

    counts = finding_summary(findings)
    lines = [
        f"# {context['title']}",
        "",
        "## Result",
        "",
        f"- Mode: `{manifest['mode']}`",
        f"- Project: `{manifest['project']}`",
        f"- Command count: `{manifest['command_count']}`",
        f"- Final command exit code: `{command_record['exit_code']}`",
        f"- Started: `{command_record['started_at']}`",
        f"- Ended: `{command_record['ended_at']}`",
        f"- Duration: `{command_record['duration_ms']} ms`",
        f"- Command exited with code `{command_record['exit_code']}`.",
        "",
        "## Commands",
        "",
        "| ID | Shell | CWD | Exit | Duration | Stdout | Stderr |",
        "| --- | --- | --- | ---: | ---: | --- | --- |",
        f"| {command_record['id']} | {command_record['shell']} | `{command_record['cwd']}` | {command_record['exit_code']} | {command_record['duration_ms']} ms | `{command_record['stdout_path']}` | `{command_record['stderr_path']}` |",
        "",
        "## Git Evidence",
        "",
        *git_lines,
        "",
        "## Artifacts",
        "",
        *artifact_lines,
        "",
        "## Redaction",
        "",
        f"- Status: `{redaction_status(findings)}`",
        f"- Findings: high `{counts.get('high', 0)}`, medium `{counts.get('medium', 0)}`, low `{counts.get('low', 0)}`",
        "- Report: `REDACTION.md`",
        "",
        "## Evidence Boundary",
        "",
        BOUNDARY_TEXT,
        "",
    ]
    write_text(out, "SUMMARY.md", "\n".join(lines))


def finalize(out, context, command_record, git_info, text_artifacts, screenshots, mode, project, title, created_at, findings):
    status = redaction_status(findings)
    for relative_path, text in text_artifacts.items():
        write_text(out, relative_path, text)
        log_event(out, "artifact-copy", f"{relative_path} text")

    copied_screenshots = []
    for idx, source in enumerate(screenshots, start=1):
        ext = source.suffix.lower()
        relative_path = f"screenshots/screenshot-{idx:03d}{ext}"
        target = out / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        copied_screenshots.append(screenshot_record(target, relative_path))
        log_event(out, "artifact-copy", f"{relative_path} screenshot")

    artifacts = [
        artifact_record(out, command_record["stdout_path"], "stdout", status),
        artifact_record(out, command_record["stderr_path"], "stderr", status),
    ]
    for relative_path in sorted(path for path in text_artifacts if path.startswith("artifacts/logs/")):
        artifacts.append(artifact_record(out, relative_path, "log", status))

    manifest = {
        "schema_version": 1,
        "tool": "prooftrail",
        "tool_version": VERSION,
        "proof_id": context["proof_id"],
        "created_at": iso(created_at),
        "mode": mode,
        "project": project,
        "title": title,
        "cwd": command_record["cwd"],
        "command_count": 1,
        "commands_path": "commands.jsonl",
        "summary_path": "SUMMARY.md",
        "redaction_path": "REDACTION.md",
        "log_path": "prooftrail.log",
        "git": git_info,
        "artifacts": artifacts,
        "screenshots": copied_screenshots,
        "evidence_boundary": "capture-only",
    }

    command_record["stdout_bytes"] = len(text_artifacts[command_record["stdout_path"]].encode("utf-8"))
    command_record["stderr_bytes"] = len(text_artifacts[command_record["stderr_path"]].encode("utf-8"))
    command_record["redaction_status"] = status
    command_record["redaction_findings"] = [
        {
            "severity": item["severity"],
            "detector_id": item["detector_id"],
            "count": item["count"],
            "artifact_path": item["artifact_path"],
        }
        for item in findings
    ]

    write_text(out, "commands.jsonl", json.dumps(command_record, sort_keys=True) + "\n")
    write_json(out, "manifest.json", manifest)
    write_redaction_report(out, findings)
    write_summary(out, context, command_record, manifest, findings)
    log_event(out, "redaction", f"{status} {finding_summary(findings)}")
    log_event(out, "finalize", "success")


def handle_run(args):
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ToolError(EXIT_USAGE, "run requires -- <command> [args...]")

    cwd = Path(args.cwd).resolve()
    if not cwd.exists() or not cwd.is_dir():
        raise ToolError(EXIT_INPUT, f"missing cwd: {display_path(cwd)}")
    screenshots = [validate_screenshot(path) for path in args.screenshot]
    out = prepare_output(args.out, args.overwrite)
    created = now()
    context = {"proof_id": proof_id(created), "title": args.title or command_text(command)}
    log_event(out, "start", f"{context['proof_id']} run {display_path(out)}")

    git_info, git_artifacts = capture_git_before(cwd, args.git_mode)
    log_event(out, "git-probe", f"available={git_info['available']} mode={args.git_mode}")

    started = now()
    log_event(out, "command-start", "cmd-001")
    try:
        result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
        exit_code = result.returncode
        stdout = result.stdout
        stderr = result.stderr
    except FileNotFoundError as exc:
        exit_code = 127
        stdout = ""
        stderr = f"command could not be started: {exc.__class__.__name__}"
    ended = now()
    log_event(out, "command-end", f"cmd-001 exit={exit_code}")
    git_artifacts.update(capture_git_after(cwd, git_info, args.diff_mode))

    command_display = command_text(command)
    project = args.project or out.name
    title = args.title or command_display
    cwd_display = display_path(cwd)
    duration_ms = int((ended - started).total_seconds() * 1000)

    texts = {
        "metadata/project": project,
        "metadata/title": title,
        "metadata/cwd": cwd_display,
        "metadata/note": args.note or "",
        "commands/cmd-001/command": command_display,
        "artifacts/commands/cmd-001/stdout.txt": stdout,
        "artifacts/commands/cmd-001/stderr.txt": stderr,
    }
    texts.update(git_artifacts)
    high_findings = scan_high(texts)
    if high_findings:
        write_block_report(out, high_findings)
        log_event(out, "redaction", f"blocked {finding_summary(high_findings)}")
        log_event(out, "finalize", "blocked")
        return EXIT_REDACTION

    redacted, findings = redact_medium(texts)
    command_record = {
        "schema_version": 1,
        "id": "cmd-001",
        "mode": "run",
        "command": redacted["commands/cmd-001/command"],
        "shell": "direct",
        "cwd": redacted["metadata/cwd"],
        "started_at": iso(started),
        "ended_at": iso(ended),
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "stdout_path": "artifacts/commands/cmd-001/stdout.txt",
        "stderr_path": "artifacts/commands/cmd-001/stderr.txt",
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "redaction_status": "clean",
        "redaction_findings": [],
    }
    text_artifacts = {k: v for k, v in redacted.items() if k.startswith("artifacts/") or k.startswith("git/")}
    context["title"] = redacted["metadata/title"]
    finalize(out, context, command_record, git_info, text_artifacts, screenshots, "run", redacted["metadata/project"], redacted["metadata/title"], created, findings)
    return exit_code


def imported_timing(args):
    started = now()
    ended = started
    if args.started_at:
        started_text = args.started_at
    else:
        started_text = iso(started)
    if args.ended_at:
        ended_text = args.ended_at
    else:
        ended_text = iso(ended)
    return started_text, ended_text, 0


def handle_import(args):
    if not any([args.stdout, args.stderr, args.log, args.screenshot, args.git_root]):
        raise ToolError(EXIT_USAGE, "import requires at least one artifact")
    stdout_text = validate_text_file(args.stdout) if args.stdout else ""
    stderr_text = validate_text_file(args.stderr) if args.stderr else ""
    logs = [validate_text_file(path) for path in args.log]
    screenshots = [validate_screenshot(path) for path in args.screenshot]
    git_root = Path(args.git_root).resolve() if args.git_root else None
    if git_root and (not git_root.exists() or not git_root.is_dir()):
        raise ToolError(EXIT_INPUT, f"missing git root: {display_path(git_root)}")

    out = prepare_output(args.out, args.overwrite)
    created = now()
    command_display = args.command or "imported artifact"
    project = args.project or out.name
    title = args.title or "Imported proof"
    cwd_display = display_path(Path(args.cwd).resolve())
    context = {"proof_id": proof_id(created), "title": title}
    log_event(out, "start", f"{context['proof_id']} import {display_path(out)}")

    if git_root:
        git_info, git_artifacts = capture_git_before(git_root, "auto")
        git_artifacts.update(capture_git_after(git_root, git_info, "full"))
    else:
        git_info = {
            "available": False,
            "mode": "auto",
            "diff_mode": "off",
            "head": "",
            "status_before_path": None,
            "status_after_path": None,
            "diff_stat_path": None,
            "diff_name_status_path": None,
            "diff_path": None,
            "cached_diff_path": None,
        }
        git_artifacts = {}
    log_event(out, "git-probe", f"available={git_info['available']} mode=auto")

    texts = {
        "metadata/project": project,
        "metadata/title": title,
        "metadata/cwd": cwd_display,
        "commands/cmd-001/command": command_display,
        "artifacts/commands/cmd-001/stdout.txt": stdout_text,
        "artifacts/commands/cmd-001/stderr.txt": stderr_text,
    }
    for idx, text in enumerate(logs, start=1):
        texts[f"artifacts/logs/imported-{idx:03d}.txt"] = text
    texts.update(git_artifacts)

    high_findings = scan_high(texts)
    if high_findings:
        write_block_report(out, high_findings)
        log_event(out, "redaction", f"blocked {finding_summary(high_findings)}")
        log_event(out, "finalize", "blocked")
        return EXIT_REDACTION

    redacted, findings = redact_medium(texts)
    started_text, ended_text, duration_ms = imported_timing(args)
    command_record = {
        "schema_version": 1,
        "id": "cmd-001",
        "mode": "import",
        "command": redacted["commands/cmd-001/command"],
        "shell": "imported",
        "cwd": redacted["metadata/cwd"],
        "started_at": started_text,
        "ended_at": ended_text,
        "duration_ms": duration_ms,
        "exit_code": args.exit_code,
        "stdout_path": "artifacts/commands/cmd-001/stdout.txt",
        "stderr_path": "artifacts/commands/cmd-001/stderr.txt",
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "redaction_status": "clean",
        "redaction_findings": [],
    }
    text_artifacts = {k: v for k, v in redacted.items() if k.startswith("artifacts/") or k.startswith("git/")}
    context["title"] = redacted["metadata/title"]
    finalize(out, context, command_record, git_info, text_artifacts, screenshots, "import", redacted["metadata/project"], redacted["metadata/title"], created, findings)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(prog="prooftrail")
    subparsers = parser.add_subparsers(dest="command_name", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--out", required=True)
    run_parser.add_argument("--project")
    run_parser.add_argument("--title")
    run_parser.add_argument("--cwd", default=".")
    run_parser.add_argument("--note")
    run_parser.add_argument("--screenshot", action="append", default=[])
    run_parser.add_argument("--git-mode", choices=["auto", "off"], default="auto")
    run_parser.add_argument("--diff-mode", choices=["summary", "full", "off"], default="full")
    run_parser.add_argument("--overwrite", action="store_true")
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    run_parser.set_defaults(func=handle_run)

    import_parser = subparsers.add_parser("import")
    import_parser.add_argument("--out", required=True)
    import_parser.add_argument("--project")
    import_parser.add_argument("--title")
    import_parser.add_argument("--cwd", default=".")
    import_parser.add_argument("--command")
    import_parser.add_argument("--exit-code", type=int, default=0)
    import_parser.add_argument("--stdout")
    import_parser.add_argument("--stderr")
    import_parser.add_argument("--log", action="append", default=[])
    import_parser.add_argument("--screenshot", action="append", default=[])
    import_parser.add_argument("--git-root")
    import_parser.add_argument("--started-at")
    import_parser.add_argument("--ended-at")
    import_parser.add_argument("--overwrite", action="store_true")
    import_parser.set_defaults(func=handle_import)
    return parser


def main(argv=None):
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return args.func(args)
    except ToolError as exc:
        print(f"prooftrail: {exc.message}", file=sys.stderr)
        return exc.code
    except Exception as exc:
        print(f"prooftrail: internal error: {exc.__class__.__name__}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
