"""Safe local and shallow Git ingestion into a normalized :class:`ScanContext`."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import subprocess
import tempfile
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

from src.models import FileRecord, ScanContext, SourceMetadata
from src.core.documents import parse_context


class IngressError(ValueError):
    """Raised when an input cannot be safely normalized."""


class SkippableFileError(IngressError):
    """Raised for files that are not scannable but must not abort a directory walk."""


DEFAULT_MAX_FILE_SIZE = 1_048_576
DEFAULT_MAX_FILES = 5_000
DEFAULT_MAX_TOTAL_SIZE = 100_000_000
DEFAULT_MAX_GIT_TREE_BYTES = 50_000_000
_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".vault",
    "runtime-audit",
    "build",
    "dist",
}
_BINARY_EXTENSIONS = {
    ".7z",
    ".aac",
    ".avi",
    ".bmp",
    ".class",
    ".db",
    ".dll",
    ".dylib",
    ".eot",
    ".exe",
    ".flac",
    ".gif",
    ".gz",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".otf",
    ".pdf",
    ".png",
    ".psd",
    ".pyc",
    ".so",
    ".sqlite",
    ".sqlite3",
    ".svg",
    ".tar",
    ".tif",
    ".tiff",
    ".ttf",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
}


def _language(path: str) -> str | None:
    suffix = Path(path).suffix.lower()
    return {
        ".json": "json",
        ".json5": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".py": "python",
        ".toml": "toml",
        ".js": "javascript",
        ".ts": "typescript",
        ".md": "markdown",
        ".txt": "text",
        ".env": "dotenv",
        ".ini": "ini",
    }.get(suffix)


# An Argus report quotes the evidence it found, so ingesting a previous report
# re-reports that evidence as though it were live configuration. Scanning the
# same directory twice therefore grew the finding count with no code change.
# Detection is structural rather than by directory name, so a project's own
# unrelated "reports/" data is still scanned normally.
def _is_argus_generated_report(path: Path, content: str) -> bool:
    suffix = path.suffix.lower()
    if suffix == ".md":
        return content.lstrip().startswith("# Argus Security Evaluation Report")
    if suffix not in {".json", ".sarif"}:
        return False
    stripped = content.lstrip()
    if not stripped.startswith("{"):
        return False
    try:
        document = json.loads(content)
    except (ValueError, RecursionError):
        return False
    if not isinstance(document, dict):
        return False
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and "argus_version" in metadata:
        return True
    runs = document.get("runs")
    if isinstance(runs, list) and runs:
        first = runs[0]
        if isinstance(first, dict):
            driver = (
                first.get("tool", {}).get("driver", {})
                if isinstance(first.get("tool"), dict)
                else {}
            )
            if isinstance(driver, dict) and driver.get("name") == "Argus":
                return True
            details = first.get("automationDetails")
            if isinstance(details, dict) and str(details.get("id", "")).startswith("argus/"):
                return True
    return False


def _matches_exclude(relative: str, patterns: tuple[str, ...]) -> bool:
    if not patterns:
        return False
    posix = PurePosixPath(relative)
    for pattern in patterns:
        normalized = pattern.strip().replace("\\", "/").rstrip("/")
        if not normalized:
            continue
        if posix.match(normalized) or fnmatch(relative, normalized):
            return True
        # Treat a bare name or prefix as "this subtree", the behavior an
        # operator expects from --exclude reports or --exclude vendor/.
        if relative == normalized or relative.startswith(f"{normalized}/"):
            return True
        if f"/{normalized}/" in f"/{relative}":
            return True
    return False


def _read_record(root: Path, file_path: Path, max_file_size: int) -> FileRecord:
    relative = file_path.relative_to(root).as_posix()
    try:
        resolved = file_path.resolve(strict=True)
    except OSError as exc:
        raise IngressError(f"unable to resolve file: {relative}") from exc
    if root.resolve() not in resolved.parents and resolved != root.resolve():
        raise IngressError(f"symlink escapes scan root: {relative}")
    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise IngressError(f"unable to stat file: {relative}") from exc
    if size > max_file_size:
        raise IngressError(f"file exceeds {max_file_size} bytes: {relative}")
    raw = file_path.read_bytes()
    if b"\x00" in raw or file_path.suffix.lower() in _BINARY_EXTENSIONS:
        raise SkippableFileError(f"unsupported binary file: {relative}")
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SkippableFileError(f"unsupported non-UTF-8 file: {relative}") from exc
    if _is_argus_generated_report(file_path, content):
        raise SkippableFileError(f"previous Argus report: {relative}")
    return FileRecord(
        path=relative,
        content=content,
        size_bytes=size,
        sha256=hashlib.sha256(raw).hexdigest(),
        is_text=True,
        language=_language(relative),
    )


def _account_file(
    file_path: Path,
    *,
    files_seen: int,
    total_size: int,
    max_file_size: int,
    max_files: int,
    max_total_size: int,
) -> tuple[int, int]:
    """Check aggregate ingress limits before reading another candidate file."""

    try:
        size = file_path.stat().st_size
    except OSError as exc:
        raise IngressError(f"unable to stat file: {file_path}") from exc
    if size > max_file_size:
        raise IngressError(f"file exceeds {max_file_size} bytes: {file_path}")
    if files_seen >= max_files:
        raise IngressError(f"scan contains more than {max_files} files")
    if total_size + size > max_total_size:
        raise IngressError(f"scan exceeds {max_total_size} total file bytes")
    return files_seen + 1, total_size + size


def _validate_ingress_limits(max_file_size: int, max_files: int, max_total_size: int) -> None:
    if max_file_size < 1024 or max_files < 1 or max_total_size < 1024:
        raise IngressError("invalid ingress limits")


def ingest_local(
    path: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    exclude: tuple[str, ...] = (),
    max_files: int = DEFAULT_MAX_FILES,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> ScanContext:
    """Read a bounded directory (or one text file) without unsafe links."""

    _validate_ingress_limits(max_file_size, max_files, max_total_size)

    candidate = Path(path)
    if not candidate.exists() or candidate.is_symlink():
        raise IngressError(f"local target does not exist or is a symlink: {path}")
    root = candidate.resolve()
    files: dict[str, FileRecord] = {}
    skipped: list[str] = []
    files_seen = 0
    total_size = 0
    if root.is_file():
        files_seen, total_size = _account_file(
            root,
            files_seen=files_seen,
            total_size=total_size,
            max_file_size=max_file_size,
            max_files=max_files,
            max_total_size=max_total_size,
        )
        try:
            record = _read_record(root.parent, root, max_file_size)
        except SkippableFileError as exc:
            # An explicit single-file target that cannot be scanned is a usage
            # error, not a file to silently skip: reporting PASS over the only
            # requested file would be indistinguishable from a clean result.
            raise IngressError(f"target file cannot be scanned: {exc}") from exc
        files[record.path] = record
    elif root.is_dir():
        for current, dirs, names in os.walk(root, topdown=True, followlinks=False):
            safe_dirs: list[str] = []
            for name in dirs:
                directory = Path(current) / name
                if directory.is_symlink():
                    resolved = directory.resolve()
                    if root not in resolved.parents and resolved != root:
                        raise IngressError(
                            f"symlink escapes scan root: {directory.relative_to(root)}"
                        )
                    continue
                if name in _IGNORED_DIRS:
                    continue
                if _matches_exclude(directory.relative_to(root).as_posix(), exclude):
                    continue
                safe_dirs.append(name)
            dirs[:] = sorted(safe_dirs)
            for name in sorted(names):
                file_path = Path(current) / name
                if _matches_exclude(file_path.relative_to(root).as_posix(), exclude):
                    continue
                files_seen, total_size = _account_file(
                    file_path,
                    files_seen=files_seen,
                    total_size=total_size,
                    max_file_size=max_file_size,
                    max_files=max_files,
                    max_total_size=max_total_size,
                )
                try:
                    record = _read_record(root, file_path, max_file_size)
                    files[record.path] = record
                except SkippableFileError as exc:
                    logging.debug("Skipping file %s: %s", file_path, exc)
                    skipped.append(file_path.relative_to(root).as_posix())
    else:
        raise IngressError(f"unsupported local target: {path}")
    source = SourceMetadata(source_type="local", source=str(root))
    return parse_context(
        ScanContext(
            source_path=str(root),
            source_type="local",
            files=files,
            source_metadata=source,
            skipped_files=sorted(skipped),
        )
    )


def _is_git_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https", "ssh", "git"} and bool(parsed.netloc)


def _validate_git_tree(
    clone_path: Path, max_file_size: int, max_files: int, max_total_size: int
) -> None:
    """Stream ``ls-tree`` output so a huge metadata listing cannot fill memory."""

    process = subprocess.Popen(
        ["git", "-C", str(clone_path), "ls-tree", "-r", "-l", "-z", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    buffer = b""
    output_bytes = 0
    files_seen = 0
    total_size = 0
    try:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(64 * 1024)
            if not chunk:
                break
            output_bytes += len(chunk)
            if output_bytes > DEFAULT_MAX_GIT_TREE_BYTES:
                process.kill()
                process.wait()
                raise IngressError("Git tree listing exceeded the configured metadata limit")
            buffer += chunk
            while b"\0" in buffer:
                entry, buffer = buffer.split(b"\0", 1)
                if not entry:
                    continue
                header, separator, _path = entry.partition(b"\t")
                if not separator:
                    raise IngressError("Git tree listing was malformed")
                fields = header.decode("ascii", errors="strict").split()
                if len(fields) < 4 or fields[1] != "blob":
                    continue
                size = fields[3]
                if size == "-":
                    raise IngressError("Git server did not provide bounded blob sizes")
                try:
                    blob_size = int(size)
                except ValueError as exc:
                    raise IngressError("Git tree contained an invalid blob size") from exc
                if blob_size > max_file_size:
                    raise IngressError(f"Git repository contains a file over {max_file_size} bytes")
                files_seen += 1
                total_size += blob_size
                if files_seen > max_files:
                    raise IngressError(f"Git repository contains more than {max_files} files")
                if total_size > max_total_size:
                    raise IngressError(f"Git repository exceeds {max_total_size} total file bytes")
        if buffer:
            raise IngressError("Git tree listing was malformed")
        stderr = (process.stderr.read() if process.stderr is not None else b"").decode(
            "utf-8", errors="replace"
        )
        try:
            return_code = process.wait(timeout=60)
        except subprocess.TimeoutExpired as exc:
            process.kill()
            process.wait()
            raise IngressError("Git tree listing timed out") from exc
        if return_code != 0:
            raise IngressError(f"Git tree listing failed: {stderr.strip()[-500:]}")
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def ingest_git(
    repo_url: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    exclude: tuple[str, ...] = (),
    max_files: int = DEFAULT_MAX_FILES,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> ScanContext:
    """Shallow-clone a repository with hooks disabled, then normalize its files."""

    _validate_ingress_limits(max_file_size, max_files, max_total_size)
    if not _is_git_url(repo_url):
        raise IngressError("Git target must be an http(s), ssh, or git URL")
    temporary_root = Path(tempfile.mkdtemp(prefix="argus-git-"))
    clone_path = temporary_root / "repo"
    try:
        clone = subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "clone",
                "--depth",
                "1",
                "--no-tags",
                "--filter=blob:none",
                "--no-checkout",
                repo_url,
                str(clone_path),
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
        clone_stderr = (clone.stderr or "").lower()
        if "filtering not recognized" in clone_stderr or "filtering not supported" in clone_stderr:
            raise IngressError(
                "Git server does not support filtered clones; use a local checkout "
                "to keep repository limits enforceable"
            )
        _validate_git_tree(clone_path, max_file_size, max_files, max_total_size)
        subprocess.run(
            ["git", "-C", str(clone_path), "checkout", "--force", "HEAD", "--", "."],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
        )
        context = ingest_local(
            str(clone_path),
            max_file_size=max_file_size,
            exclude=exclude,
            max_files=max_files,
            max_total_size=max_total_size,
        )
        commit = None
        try:
            commit = subprocess.run(
                ["git", "-C", str(clone_path), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return context.model_copy(
            update={
                "source_path": repo_url,
                "source_type": "git",
                "source_metadata": SourceMetadata(
                    source_type="git", source=repo_url, commit=commit
                ),
            }
        )
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "git clone failed").strip()[-500:]
        raise IngressError(f"Git ingestion failed: {detail}") from exc
    except subprocess.TimeoutExpired as exc:
        raise IngressError("Git ingestion timed out") from exc
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)


def ingest(
    target: str,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    exclude: tuple[str, ...] = (),
    max_files: int = DEFAULT_MAX_FILES,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
) -> ScanContext:
    return (
        ingest_git(target, max_file_size, exclude, max_files, max_total_size)
        if _is_git_url(target)
        else ingest_local(target, max_file_size, exclude, max_files, max_total_size)
    )


__all__ = ["IngressError", "ingest", "ingest_git", "ingest_local"]
