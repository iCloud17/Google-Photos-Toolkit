#!/usr/bin/env python3
"""GPTK Phone Check: delete phone files that are already in your Google Photos.

Run it on the phone in Termux. It needs only Python and it sends nothing anywhere.

  1. python gptk_phone_check.py scan
     Reads the photos and videos in your WhatsApp folders and writes
     Download/gptk-fingerprints.json (fingerprints only, no file names).
  2. In Firefox, open photos.google.com > GPTK > Phone Check. Choose the
     fingerprint file, tap Check, then tap Download Result.
  3. python gptk_phone_check.py clean
     Reads the newest Download/gptk-result.json, shows what it can delete and
     deletes nothing until you type "yes".

A fingerprint is the SHA-1 of the file. Google Photos uses the same value to
find exact copies, so only exact copies match.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
import time
from typing import Callable, Dict, Iterator, List, NamedTuple, Optional, Sequence, Tuple

FORMAT = "gptk-phone-check"
VERSION = 1
FINGERPRINT_FILE_NAME = "gptk-fingerprints.json"
RESULT_FILE_NAME = re.compile(r"gptk-result.*\.json", re.IGNORECASE)
# Google Photos can change after the check, so an old result is not trusted.
MAX_RESULT_AGE = dt.timedelta(days=2)

DEFAULT_STORAGE = "/storage/emulated/0"
DEFAULT_FOLDERS = (
    "Android/media/com.whatsapp/WhatsApp/Media",
    "Android/media/com.whatsapp.w4b/WhatsApp Business/Media",
    "WhatsApp/Media",
    "WhatsApp Business/Media",
)
SKIPPED_FOLDER_NAMES = {"whatsapp stickers"}
MEDIA_EXTENSIONS = {
    "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif", "bmp", "tif", "tiff", "dng",
    "mp4", "m4v", "3gp", "3gpp", "mov", "mkv", "webm", "avi", "mpg", "mpeg", "wmv",
}
CHUNK_SIZE = 1024 * 1024
# Same rule as isFingerprint() in src/phone-check/fingerprint-file.ts.
SHA1_BASE64 = re.compile(r"[A-Za-z0-9+/]{26}[AEIMQUYcgkosw048]=")
MEDIA_KEY = re.compile(r"[A-Za-z0-9_-]{1,300}")
# Random ID of one scan. GPTK copies it into the result, so a result of an older scan is refused.
SCAN_ID = re.compile(r"[0-9a-f]{32}")
PHOTO_URL = "https://photos.google.com/photo/"

EXIT_OK = 0
EXIT_CANCELLED = 1
EXIT_INPUT_ERROR = 2
EXIT_DELETE_FAILED = 3


class MediaFile(NamedTuple):
    path: str
    size: int
    folder: str


class CheckResult(NamedTuple):
    found: Dict[str, str]
    complete: bool
    created: dt.datetime
    scan_id: str


class ResultFileError(Exception):
    pass


def shown(path: str) -> str:
    """Makes a path safe to print, also when its name is not valid UTF-8."""
    return os.fsencode(path).decode("utf-8", "replace")


def format_size(size: int) -> str:
    if size < 1000:
        return f"{size} bytes"
    value = size / 1000
    for unit in ("KB", "MB"):
        if value < 1000:
            return f"{value:.1f} {unit}"
        value /= 1000
    return f"{value:.1f} GB"


def count_text(count: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def fingerprint(path: str) -> str:
    digest = hashlib.sha1()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return base64.b64encode(digest.digest()).decode("ascii")


def resolve_folders(storage: str, requested: Optional[Sequence[str]]) -> List[str]:
    folders = []
    for folder in requested or DEFAULT_FOLDERS:
        path = os.path.normpath(os.path.join(storage, folder))
        if os.path.isdir(path):
            if path not in folders:
                folders.append(path)
        elif requested:
            print(f"Folder not found: {shown(path)}")
    return folders


def iter_media_files(folders: Sequence[str], folder_errors: List[str]) -> Iterator[MediaFile]:
    """Yields each photo and video file once. Skips hidden items, stickers and links."""
    seen = set()
    for folder in folders:
        for current, dirs, files in os.walk(folder, onerror=lambda error: folder_errors.append(str(error.filename))):
            dirs[:] = sorted(name for name in dirs if not name.startswith(".") and name.lower() not in SKIPPED_FOLDER_NAMES)
            for name in sorted(files):
                if name.startswith(".") or os.path.splitext(name)[1].lower().lstrip(".") not in MEDIA_EXTENSIONS:
                    continue
                path = os.path.join(current, name)
                try:
                    info = os.lstat(path)
                except OSError:
                    continue
                # Only real files: never links, so nothing outside the folders can be touched.
                if not stat.S_ISREG(info.st_mode):
                    continue
                real_path = os.path.realpath(path)
                if real_path in seen:
                    continue
                seen.add(real_path)
                yield MediaFile(path, info.st_size, folder)


class Progress:
    def __init__(self, label: str):
        self.label = label
        self.visible = sys.stderr.isatty()
        self.last = 0.0
        self.shown_once = False

    def update(self, files: int, size: int) -> None:
        now = time.monotonic()
        if self.visible and now - self.last >= 1:
            self.last = now
            self.shown_once = True
            print(f"\r{self.label}: {count_text(files, 'file')}, {format_size(size)}   ", end="", file=sys.stderr, flush=True)

    def finish(self) -> None:
        if self.shown_once:
            print(file=sys.stderr)


def hash_media_files(folders: Sequence[str]) -> Tuple[List[Tuple[MediaFile, str]], int, List[str]]:
    hashed: List[Tuple[MediaFile, str]] = []
    unreadable = 0
    folder_errors: List[str] = []
    progress = Progress("Reading files")
    total_size = 0
    for media in iter_media_files(folders, folder_errors):
        try:
            hashed.append((media, fingerprint(media.path)))
            total_size += media.size
        except OSError:
            unreadable += 1
        progress.update(len(hashed), total_size)
    progress.finish()
    return hashed, unreadable, folder_errors


def write_atomically(path: str, text: str) -> None:
    directory = os.path.dirname(path)
    handle, temp_path = tempfile.mkstemp(prefix=".gptk-", suffix=".tmp", dir=directory)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.replace(temp_path, path)
    except BaseException:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_time(value: object) -> Optional[dt.datetime]:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def print_no_folders(storage: str, requested: Optional[Sequence[str]]) -> None:
    if not requested:
        print("No WhatsApp media folder found in " + shown(storage) + ".")
    print("Make sure that you did these steps:")
    print("  1. Run: termux-setup-storage")
    print('  2. Give Termux the "Files" or "All files access" permission.')
    print("  3. To use a different folder, add: --folder \"FOLDER NAME\"")


def print_folder_errors(folder_errors: Sequence[str]) -> None:
    if folder_errors:
        print(f"Could not open {count_text(len(folder_errors), 'folder')}. Give Termux the \"All files access\" permission and try again.")


def command_scan(args: argparse.Namespace) -> int:
    folders = resolve_folders(args.storage, args.folder)
    if not folders:
        print_no_folders(args.storage, args.folder)
        return EXIT_INPUT_ERROR
    downloads = args.downloads or os.path.join(args.storage, "Download")
    if not os.path.isdir(downloads):
        print(f"Download folder not found: {shown(downloads)}")
        return EXIT_INPUT_ERROR

    print("Reading photos and videos in:")
    for folder in folders:
        print("  " + shown(folder))
    hashed, unreadable, folder_errors = hash_media_files(folders)
    hashes = sorted({hash_value for _, hash_value in hashed})
    content = {
        "format": FORMAT,
        "type": "fingerprints",
        "version": VERSION,
        "created": utc_now().isoformat(timespec="seconds").replace("+00:00", "Z"),
        "scanId": secrets.token_hex(16),
        "hashes": hashes,
    }
    output = os.path.join(downloads, FINGERPRINT_FILE_NAME)
    write_atomically(output, json.dumps(content, indent=1) + "\n")

    total_size = sum(media.size for media, _ in hashed)
    print(f"Read {count_text(len(hashed), 'file')} ({format_size(total_size)}), {len(hashes)} different.")
    if unreadable:
        print(f"Skipped {count_text(unreadable, 'file')} that could not be read.")
    print_folder_errors(folder_errors)
    if not hashes:
        print("No photos or videos found. Nothing to check.")
        return EXIT_OK
    print(f"Saved: {shown(output)}")
    print("Next: in Firefox, open photos.google.com > GPTK > Phone Check.")
    print('Choose this file, tap "Check", then tap "Download Result".')
    print("Then run: python gptk_phone_check.py clean")
    return EXIT_OK


def newest_result_file(downloads: str) -> Optional[str]:
    candidates = []
    with os.scandir(downloads) as entries:
        for entry in entries:
            if RESULT_FILE_NAME.fullmatch(entry.name) and entry.is_file():
                candidates.append((entry.stat().st_mtime, entry.path))
    return max(candidates)[1] if candidates else None


def load_result_file(path: str, now: dt.datetime) -> CheckResult:
    damaged = ResultFileError("The result file is damaged. Run Check in GPTK again.")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeDecodeError, ValueError):
        raise ResultFileError("Could not read the result file. Download it again from GPTK.") from None

    if not isinstance(data, dict) or data.get("format") != FORMAT or data.get("type") != "result":
        raise ResultFileError("This is not a GPTK Phone Check result file.")
    version = data.get("version")
    if type(version) is not int or version != VERSION:
        raise ResultFileError("This result file is from a different version of GPTK. Update this script.")
    created = parse_time(data.get("created"))
    if created is None:
        raise damaged
    if now - created > MAX_RESULT_AGE:
        raise ResultFileError("This result is more than 2 days old and Google Photos can change. Run Check in GPTK again.")
    scan_id = data.get("scanId")
    if not isinstance(scan_id, str) or not SCAN_ID.fullmatch(scan_id):
        raise damaged
    entries = data.get("found")
    if not isinstance(entries, list):
        raise damaged

    found: Dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise damaged
        hash_value, media_key = entry.get("hash"), entry.get("mediaKey")
        if not isinstance(hash_value, str) or not SHA1_BASE64.fullmatch(hash_value):
            raise damaged
        if not isinstance(media_key, str) or not MEDIA_KEY.fullmatch(media_key):
            raise damaged
        found.setdefault(hash_value, media_key)
    return CheckResult(found, data.get("complete") is True, created, scan_id)


def read_scan_id(downloads: str) -> str:
    """Returns the scan ID of the last scan (in gptk-fingerprints.json)."""
    missing = ResultFileError(f"Could not read {FINGERPRINT_FILE_NAME} in {shown(downloads)}. Run scan, then Check in GPTK again.")
    try:
        with open(os.path.join(downloads, FINGERPRINT_FILE_NAME), "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, UnicodeDecodeError, ValueError):
        raise missing from None
    scan_id = data.get("scanId") if isinstance(data, dict) and data.get("format") == FORMAT and data.get("type") == "fingerprints" else None
    if not isinstance(scan_id, str) or not SCAN_ID.fullmatch(scan_id):
        raise missing
    return scan_id


def print_plan(matches: Sequence[Tuple[MediaFile, str]], storage: str) -> None:
    groups: Dict[Tuple[str, str], List[int]] = {}
    for media, _ in matches:
        key = (media.folder, os.path.relpath(os.path.dirname(media.path), media.folder))
        group = groups.setdefault(key, [0, 0])
        group[0] += 1
        group[1] += media.size
    last_folder = None
    for (folder, subfolder), (count, size) in sorted(groups.items()):
        if folder != last_folder:
            print("Folder: " + shown(os.path.relpath(folder, storage)))
            last_folder = folder
        label = "(main folder)" if subfolder == "." else subfolder
        print(f"  {shown(label)}: {count_text(count, 'file')}, {format_size(size)}")


def command_clean(args: argparse.Namespace, ask: Callable[[str], str]) -> int:
    downloads = args.downloads or os.path.join(args.storage, "Download")
    try:
        result_path = args.result or (newest_result_file(downloads) if os.path.isdir(downloads) else None)
        if result_path is None:
            print(f"No gptk-result.json file in {shown(downloads)}.")
            print('First run "scan", then use Phone Check in GPTK and tap "Download Result".')
            return EXIT_INPUT_ERROR
        result = load_result_file(result_path, utc_now())
        if result.scan_id != read_scan_id(downloads):
            raise ResultFileError(
                f"This result is for an older scan. In GPTK, check the new {FINGERPRINT_FILE_NAME} file, then tap \"Download Result\" again."
            )
    except ResultFileError as error:
        print(str(error))
        print("Nothing was deleted.")
        return EXIT_INPUT_ERROR

    hours = int((utc_now() - result.created).total_seconds() // 3600)
    age = "less than 1 hour" if hours < 1 else count_text(hours, "hour")
    print(f"Result file: {shown(result_path)} (made {age} ago)")
    if not result.complete:
        print("Note: the check in GPTK was stopped before the end. Only files that it confirmed can be deleted.")
    if not result.found:
        print("The result has no files that are in Google Photos. Nothing to delete.")
        return EXIT_OK

    folders = resolve_folders(args.storage, args.folder)
    if not folders:
        print_no_folders(args.storage, args.folder)
        return EXIT_INPUT_ERROR
    hashed, unreadable, folder_errors = hash_media_files(folders)
    print_folder_errors(folder_errors)
    matches = [(media, hash_value) for media, hash_value in hashed if hash_value in result.found]
    if not matches:
        print("No phone files match the result. Nothing to delete.")
        return EXIT_OK

    total_size = sum(media.size for media, _ in matches)
    print(f"Already in your Google Photos: {count_text(len(matches), 'file')} ({format_size(total_size)})")
    print_plan(matches, args.storage)
    if args.list:
        for media, _ in matches:
            print("  " + shown(media.path))
    print("They will be deleted from this phone. The copies in Google Photos stay.")
    print("In WhatsApp chats, these photos and videos will show as not available.")
    try:
        answer = ask(f"Type yes to delete {count_text(len(matches), 'file')}: ")
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() != "yes":
        print("Nothing was deleted.")
        return EXIT_CANCELLED

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    record_path = os.path.join(downloads, f"gptk-deleted-{stamp}.txt")
    try:
        record = open(record_path, "x", encoding="utf-8", errors="backslashreplace")
    except OSError:
        print(f"Could not write the list of deleted files to {shown(record_path)}. Nothing was deleted.")
        return EXIT_INPUT_ERROR

    deleted_count, deleted_size, changed, failed = 0, 0, 0, 0
    with record:
        record.write("# Files deleted by gptk_phone_check.py. Each one was already in Google Photos.\n")
        record.write("# path<TAB>size in bytes<TAB>Google Photos link\n")
        for media, hash_value in matches:
            try:
                # Check again just before deleting: the file must still be the same real file.
                if not stat.S_ISREG(os.lstat(media.path).st_mode) or fingerprint(media.path) != hash_value:
                    changed += 1
                    continue
                os.remove(media.path)
            except FileNotFoundError:
                changed += 1
                continue
            except OSError:
                failed += 1
                continue
            deleted_count += 1
            deleted_size += media.size
            record.write(f"{media.path}\t{media.size}\t{PHOTO_URL}{result.found[hash_value]}\n")
            record.flush()

    print(f"Deleted {count_text(deleted_count, 'file')} ({format_size(deleted_size)}).")
    print(f"The list of deleted files is in {shown(record_path)}")
    if changed:
        print(f"Kept {count_text(changed, 'file')} that changed or moved after the check.")
    if failed:
        print(f'Could not delete {count_text(failed, "file")}. Give Termux the "All files access" permission and run clean again.')
        return EXIT_DELETE_FAILED
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--folder",
        action="append",
        help="folder to use instead of the WhatsApp folders, relative to the phone storage (you can use it again for more folders)",
    )
    common.add_argument(
        "--storage",
        default=os.environ.get("GPTK_PHONE_STORAGE", DEFAULT_STORAGE),
        help=f"phone storage folder (default: {DEFAULT_STORAGE})",
    )
    common.add_argument("--downloads", help="folder for the fingerprint, result and record files (default: STORAGE/Download)")

    parser = argparse.ArgumentParser(description="Delete phone files that are already in your Google Photos (with GPTK Phone Check).")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.required = True
    commands.add_parser("scan", parents=[common], help="make the fingerprint file for GPTK Phone Check")
    clean = commands.add_parser("clean", parents=[common], help="delete the files that GPTK found in Google Photos")
    clean.add_argument("--result", help="result file to use (default: the newest gptk-result*.json in Download)")
    clean.add_argument("--list", action="store_true", help="show every file before asking")
    return parser


def main(argv: Optional[Sequence[str]] = None, ask: Callable[[str], str] = input) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return command_scan(args)
    return command_clean(args, ask)


if __name__ == "__main__":
    sys.exit(main())
