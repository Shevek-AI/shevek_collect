"""Private staging, cooperative locking, and no-clobber publication.

The destination parent must be trusted. This does not isolate a hostile process
running as the same user; it preserves unexpected destinations instead of deleting
them, including during the gap between moving an old bundle and publishing a new one.
"""
from __future__ import annotations

import ctypes
import hashlib
import os
import shutil
import stat
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path


class FileSafetyError(ValueError):
    pass


def destination_path(path: Path) -> Path:
    requested = path.expanduser()
    if requested.is_symlink():
        raise FileSafetyError(f"Refusing a symlink destination: {requested}")
    return requested.parent.resolve() / requested.name


@contextmanager
def destination_lock(target: Path):
    target.parent.mkdir(parents=True, exist_ok=True)
    lock = target.parent / f".{target.name}.collect.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    if lock.is_symlink():
        raise FileSafetyError(f"Refusing a symlink lock: {lock}")
    try:
        fd = os.open(lock, flags, 0o600)
    except OSError as exc:
        raise FileSafetyError(f"Cannot open output lock: {lock}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise FileSafetyError(f"Unsafe output lock: {lock}")
        try:
            if os.name == "nt":
                import msvcrt
                if info.st_size == 0:
                    os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise FileSafetyError(f"Another collection is using this output: {target}") from exc
        yield
    finally:
        os.close(fd)  # Closing releases the lock. Never unlink a live lock inode.


def path_state(path: Path) -> str | None:
    """Fingerprint an existing destination without following any symlinks."""
    try:
        root = path.lstat()
    except FileNotFoundError:
        return None
    digest = hashlib.sha256()
    pending = [(path, "", root)]
    count = 0
    while pending:
        current, relative, info = pending.pop()
        count += 1
        if count > 1_000_000:
            raise FileSafetyError("Output has too many entries to replace safely")
        # A rename changes the root ctime. Its identity, contents and mtime must
        # still match after it is moved to a private recovery directory.
        values = (relative, info.st_dev, info.st_ino, info.st_mode, info.st_size,
                  info.st_mtime_ns, info.st_ctime_ns if relative else 0)
        digest.update(repr(values).encode("utf-8", errors="surrogateescape"))
        if stat.S_ISDIR(info.st_mode):
            children = sorted(current.iterdir(), key=lambda child: child.name, reverse=True)
            pending.extend((child, f"{relative}/{child.name}", child.lstat()) for child in children)
    return digest.hexdigest()


def rename_noreplace(source: Path, destination: Path) -> None:
    """Atomically refuse *any* existing destination; never emulate with exists()."""
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise FileSafetyError("Atomic publication requires Linux renameat2 support")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(source), -100, os.fsencode(destination), 1) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(destination))
    elif sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renamex_np
        rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(os.fsencode(source), os.fsencode(destination), 4) != 0:  # RENAME_EXCL
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(destination))
    elif os.name == "nt":
        os.rename(source, destination)  # Windows rename refuses existing destinations.
    else:
        raise FileSafetyError("Atomic no-replace directory publication is unsupported on this platform")


def publish_staged(stage: Path, target: Path, expected: str | None) -> None:
    if path_state(target) != expected:
        raise FileSafetyError(f"Output changed during collection; preserved: {target}")
    recovery: Path | None = None
    backup: Path | None = None
    try:
        if expected is not None:
            recovery = Path(tempfile.mkdtemp(prefix=f".{target.name}.recovery-", dir=target.parent))
            backup = recovery / "previous"
            rename_noreplace(target, backup)
            if path_state(backup) != expected:
                raise FileSafetyError("Output identity changed during publication")
        rename_noreplace(stage, target)
    except Exception as exc:
        if backup is not None and (backup.exists() or backup.is_symlink()):
            try:
                rename_noreplace(backup, target)
            except (OSError, FileSafetyError):
                raise FileSafetyError(
                    f"Output changed during publication; recovery preserved at {backup}"
                ) from exc
        if recovery is not None and not any(recovery.iterdir()):
            recovery.rmdir()
        raise FileSafetyError(f"Could not publish output safely: {target}") from exc
    if backup is not None:
        if path_state(backup) != expected:
            raise FileSafetyError(f"Previous output changed; recovery preserved at {backup}")
        if backup.is_dir() and not backup.is_symlink():
            shutil.rmtree(backup)
        else:
            backup.unlink()
        assert recovery is not None
        recovery.rmdir()


def regular_file_in(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or not path.parts or any(part in {"..", "."} for part in path.parts):
        raise FileSafetyError("Unsafe bundle member path")
    # Reject Windows separators/drives even when inspecting on POSIX.
    if "\\" in relative or ":" in relative or "\x00" in relative:
        raise FileSafetyError("Unsafe bundle member path")
    candidate = root
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise FileSafetyError("Bundle member symlinks are forbidden")
    info = candidate.stat()
    if not stat.S_ISREG(info.st_mode):
        raise FileSafetyError("Bundle members must be regular files")
    return candidate


@contextmanager
def open_regular(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise FileSafetyError("Refusing to read a nonregular file")
        yield stream
