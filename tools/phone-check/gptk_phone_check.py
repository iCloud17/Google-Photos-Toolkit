#!/usr/bin/env python3
"""GPTK Phone Check: free space on the phone. Deletes WhatsApp photos and videos
that are already in your Google Photos, and extra copies of them on the phone.

Run it on the phone in Termux. It needs only Python and it sends nothing anywhere.

  1. python gptk_phone_check.py scan
     Reads the photos and videos in your WhatsApp folders and writes
     Download/gptk-fingerprints.json (fingerprints only, no file names).
  2. In Firefox, open photos.google.com > GPTK > Phone Check. Choose the
     fingerprint file, tap Check, then tap Download Result.
  3. python gptk_phone_check.py clean
     Reads the newest Download/gptk-result.json. It also looks in the other
     folders of the phone for copies of the WhatsApp files. For each file that
     has more than one copy, it shows where the copies are and you choose what
     to keep. It deletes nothing until you type "yes".

"python gptk_phone_check.py copies" does only the search for copies, without
Google Photos (steps 1 and 2 are then not necessary).

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
from typing import Callable, Dict, Iterable, Iterator, List, NamedTuple, Optional, Sequence, Set, Tuple, Union

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
# Apps own the folders in Android/, and an app can delete its files at any time (cache cleanup or uninstall).
# So a file there does not count as a copy, and these folders are not searched for copies.
APP_FOLDERS = ("Android",)
# A file in a trash or recycle bin folder can disappear soon. These folders are skipped in every search,
# so such a file never counts as a copy, and the script never deletes it.
TRASH_FOLDER_NAME = re.compile(r"trash|recycle", re.IGNORECASE)
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

# Answers to the question about a file with copies. A copy number is also an answer.
DELETE_ALL = "all"
KEEP_ALL = "skip"
AUTO = "auto"
STOP = "stop"
COPY_NUMBER = re.compile(r"[0-9]{1,6}")
REVIEW_HELP = (
    "Some photos and videos have more than one copy on this phone.",
    "For each one, you see where the copies are. Then type:",
    "  a number  to keep only that copy and delete the other copies",
    "  all       to delete all copies",
    "  skip      to keep all copies",
    "  auto      to use the suggestion for this one and all the next ones",
    "  stop      to keep all copies of this one and all the next ones",
    "  (Enter)   to use the suggestion",
    'Nothing is deleted before you type "yes" at the end.',
)

EXIT_OK = 0
EXIT_CANCELLED = 1
EXIT_INPUT_ERROR = 2
EXIT_DELETE_FAILED = 3


class MediaFile(NamedTuple):
    path: str
    size: int
    # The folder that was read: a WhatsApp (or --folder) folder, or the phone storage for a copy elsewhere.
    folder: str
    # True for a copy outside the WhatsApp (or --folder) folders.
    elsewhere: bool
    modified: float
    # (device, inode): two paths with the same identity are one file, not two copies.
    identity: Tuple[int, int]


class CopyGroup(NamedTuple):
    """All the copies on the phone of one file. At least one copy is in the WhatsApp (or --folder) folders."""

    hash: str
    files: List[MediaFile]
    # The item in Google Photos, when Google Photos has the file.
    media_key: Optional[str]


class Deletion(NamedTuple):
    media: MediaFile
    hash: str
    media_key: Optional[str]
    # The copy that stays on the phone, or None when no copy stays.
    kept: Optional[MediaFile]


class CheckResult(NamedTuple):
    found: Dict[str, str]
    complete: bool
    created: dt.datetime
    scan_id: str


class ResultFileError(Exception):
    pass


# A copy number (from 0), DELETE_ALL or KEEP_ALL.
Choice = Union[int, str]


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


def folder_key(path: str) -> str:
    # The phone storage does not see a difference between upper case and lower case.
    return os.path.normpath(path).casefold()


def is_inside(path: str, folder: str) -> bool:
    path, folder = folder_key(path), folder_key(folder)
    return path == folder or path.startswith(folder.rstrip(os.sep) + os.sep)


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


def media_file(path: str, info: os.stat_result, folder: str, elsewhere: bool) -> MediaFile:
    return MediaFile(path, info.st_size, folder, elsewhere, info.st_mtime, (info.st_dev, info.st_ino))


def walk_media(top: str, folder_errors: List[str], skip_folder: Callable[[str], bool]) -> Iterator[Tuple[str, os.stat_result]]:
    """Yields the path and lstat of each photo and video under top. Skips hidden items, stickers, trash folders and links."""
    for current, dirs, files in os.walk(top, onerror=lambda error: folder_errors.append(str(error.filename))):
        dirs[:] = sorted(
            name
            for name in dirs
            if not name.startswith(".")
            and name.lower() not in SKIPPED_FOLDER_NAMES
            and TRASH_FOLDER_NAME.search(name) is None
            and not skip_folder(os.path.join(current, name))
        )
        for name in sorted(files):
            if name.startswith(".") or os.path.splitext(name)[1].lower().lstrip(".") not in MEDIA_EXTENSIONS:
                continue
            path = os.path.join(current, name)
            try:
                info = os.lstat(path)
            except OSError:
                continue
            # Only real files: never links, so nothing outside the folders can be touched.
            if stat.S_ISREG(info.st_mode):
                yield path, info


def iter_media_files(folders: Sequence[str], folder_errors: List[str]) -> Iterator[MediaFile]:
    """Yields each photo and video file in the folders once."""
    seen = set()
    for folder in folders:
        for path, info in walk_media(folder, folder_errors, lambda _path: False):
            real_path = os.path.realpath(path)
            if real_path in seen:
                continue
            seen.add(real_path)
            yield media_file(path, info, folder, elsewhere=False)


def iter_other_copies(storage: str, folders: Sequence[str], sizes: Set[int], folder_errors: List[str]) -> Iterator[MediaFile]:
    """Yields the photos and videos in the rest of the phone storage that have the size of a file in the folders."""
    skipped = {folder_key(folder) for folder in folders} | {folder_key(os.path.join(storage, name)) for name in APP_FOLDERS}
    if not sizes or any(is_inside(storage, folder) for folder in folders):
        return
    for path, info in walk_media(storage, folder_errors, lambda path: folder_key(path) in skipped):
        if info.st_size in sizes:
            yield media_file(path, info, storage, elsewhere=True)


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


def hash_files(files: Iterable[MediaFile], label: str) -> Tuple[List[Tuple[MediaFile, str]], int]:
    hashed: List[Tuple[MediaFile, str]] = []
    unreadable = 0
    progress = Progress(label)
    total_size = 0
    for media in files:
        try:
            hashed.append((media, fingerprint(media.path)))
            total_size += media.size
        except OSError:
            unreadable += 1
        progress.update(len(hashed), total_size)
    progress.finish()
    return hashed, unreadable


def hash_media_files(folders: Sequence[str]) -> Tuple[List[Tuple[MediaFile, str]], int, List[str]]:
    folder_errors: List[str] = []
    hashed, unreadable = hash_files(iter_media_files(folders, folder_errors), "Reading files")
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


def display_key(media: MediaFile, storage: str) -> Tuple[str, str]:
    return folder_key(os.path.relpath(media.path, storage)), media.path


def build_groups(hashed: Sequence[Tuple[MediaFile, str]], found: Dict[str, str], storage: str) -> List[CopyGroup]:
    """Puts the files with the same fingerprint together. Keeps only groups with a file in the WhatsApp (or --folder) folders."""
    by_hash: Dict[str, List[MediaFile]] = {}
    seen = set()
    for media, hash_value in hashed:
        # Two paths to one file (a hard link) are one copy, not two.
        if media.identity in seen:
            continue
        seen.add(media.identity)
        by_hash.setdefault(hash_value, []).append(media)
    return [
        CopyGroup(hash_value, sorted(files, key=lambda media: display_key(media, storage)), found.get(hash_value))
        for hash_value, files in by_hash.items()
        if any(not media.elsewhere for media in files)
    ]


def keep_order(media: MediaFile, storage: str) -> Tuple[bool, bool, bool, float, int, str]:
    """Sort key that puts the best copy to keep first: outside WhatsApp, outside app and Download folders, then the oldest."""
    # A copy in an app folder (Android/...) is deleted together with the app. Download is often emptied.
    in_app_folder = is_inside(media.path, os.path.join(storage, "Android"))
    in_download = is_inside(media.path, os.path.join(storage, "Download"))
    return (not media.elsewhere, in_app_folder, in_download, media.modified, len(media.path), media.path)


def suggested_choice(group: CopyGroup, storage: str) -> Choice:
    """Keep 1 copy. Delete all copies only when Google Photos has the file and all copies are in WhatsApp (or --folder)."""
    if group.media_key is not None and not any(media.elsewhere for media in group.files):
        return DELETE_ALL
    return min(range(len(group.files)), key=lambda index: keep_order(group.files[index], storage))


def planned_deletions(group: CopyGroup, choice: Choice) -> List[Deletion]:
    if choice == KEEP_ALL:
        return []
    if choice == DELETE_ALL:
        return [Deletion(media, group.hash, group.media_key, None) for media in group.files]
    kept = group.files[int(choice)]
    return [Deletion(media, group.hash, group.media_key, kept) for index, media in enumerate(group.files) if index != choice]


def modified_text(media: MediaFile) -> str:
    try:
        return dt.datetime.fromtimestamp(media.modified).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return "date unknown"


def print_group(number: int, total: int, group: CopyGroup, suggestion: Choice, google_checked: bool, storage: str) -> None:
    google = "yes" if group.media_key is not None else ("not confirmed" if google_checked else "not checked")
    print()
    print(f"[{number} of {total}] {len(group.files)} copies, {format_size(group.files[0].size)} each. In Google Photos: {google}")
    for index, media in enumerate(group.files, 1):
        folder = os.path.relpath(os.path.dirname(media.path), storage)
        print(f"  {index}. {shown(os.path.basename(media.path))} ({modified_text(media)})")
        print(f"     in {'the main folder' if folder == '.' else shown(folder)}")
    if suggestion == DELETE_ALL:
        print("  Suggestion: all (Google Photos has it)")
    else:
        print(f"  Suggestion: {int(suggestion) + 1} (keep copy {int(suggestion) + 1}, delete the others)")


def confirm_delete_all(google_checked: bool, ask: Callable[[str], str]) -> bool:
    print("  WARNING: " + ("GPTK did not confirm this file in your Google Photos." if google_checked else "Nobody checked if your Google Photos has this file."))
    print("  If you delete all copies, the file is gone for good.")
    return ask('  Type "delete" to delete all copies, or press Enter to choose again: ').strip().lower() == "delete"


def ask_choice(group: CopyGroup, suggestion: Choice, google_checked: bool, ask: Callable[[str], str]) -> Choice:
    """Asks until the answer is valid. Returns a Choice, AUTO or STOP."""
    count = len(group.files)
    while True:
        answer = ask("Your choice: ").strip().lower()
        if answer == "":
            return suggestion
        if answer in (KEEP_ALL, AUTO, STOP):
            return answer
        if COPY_NUMBER.fullmatch(answer) and 1 <= int(answer) <= count:
            return int(answer) - 1
        if answer == DELETE_ALL:
            if group.media_key is not None or confirm_delete_all(google_checked, ask):
                return DELETE_ALL
            continue
        print(f"Type a number from 1 to {count}, all, skip, auto or stop. Or press Enter to use the suggestion.")


def review_copies(groups: Sequence[CopyGroup], google_checked: bool, ask: Callable[[str], str], storage: str) -> List[Deletion]:
    """Asks what to keep of each file with copies. EOFError and KeyboardInterrupt from ask go to the caller."""
    print()
    for line in REVIEW_HELP:
        print(line)
    deletions: List[Deletion] = []
    automatic = False
    for number, group in enumerate(groups, 1):
        suggestion = suggested_choice(group, storage)
        choice = suggestion
        if not automatic:
            print_group(number, len(groups), group, suggestion, google_checked, storage)
            answer = ask_choice(group, suggestion, google_checked, ask)
            if answer == STOP:
                print(f"Kept all copies of the last {count_text(len(groups) - number + 1, 'file')}.")
                break
            if answer == AUTO:
                automatic = True
                print(f"Used the suggestion for the last {count_text(len(groups) - number + 1, 'file')}.")
            else:
                choice = answer
        deletions += planned_deletions(group, choice)
    return deletions


def print_plan(files: Sequence[MediaFile], storage: str) -> None:
    """Shows how many files are deleted from each folder."""
    groups: Dict[Tuple[bool, str, str], List[int]] = {}
    for media in files:
        key = (media.elsewhere, media.folder, os.path.relpath(os.path.dirname(media.path), media.folder))
        group = groups.setdefault(key, [0, 0])
        group[0] += 1
        group[1] += media.size
    last_folder = None
    for (elsewhere, folder, subfolder), (count, size) in sorted(groups.items()):
        if (elsewhere, folder) != last_folder:
            print("Other folders:" if elsewhere else "Folder: " + shown(os.path.relpath(folder, storage)))
            last_folder = (elsewhere, folder)
        label = "(main folder)" if subfolder == "." else subfolder
        print(f"  {shown(label)}: {count_text(count, 'file')}, {format_size(size)}")


def print_summary(deletions: Sequence[Deletion], storage: str, list_files: bool) -> None:
    kinds = (
        ("In your Google Photos (the copies there stay)", [item.media for item in deletions if item.kept is None and item.media_key is not None]),
        ("Extra copies (1 copy of each file stays on this phone)", [item.media for item in deletions if item.kept is not None]),
        ("All copies, NOT confirmed in Google Photos (gone for good)", [item.media for item in deletions if item.kept is None and item.media_key is None]),
    )
    print()
    print(f"Ready to delete {count_text(len(deletions), 'file')} ({format_size(sum(item.media.size for item in deletions))}):")
    for label, files in kinds:
        if files:
            print(f"  {label}: {count_text(len(files), 'file')}, {format_size(sum(media.size for media in files))}")
    print_plan([item.media for item in deletions], storage)
    if list_files:
        for item in deletions:
            print("  " + shown(item.media.path))
    if any(not item.media.elsewhere for item in deletions):
        print("In WhatsApp chats, deleted photos and videos will show as not available.")


def unchanged_file(path: str, hash_value: str) -> Optional[os.stat_result]:
    """The lstat of path when it is still a real file with this fingerprint, else None."""
    try:
        info = os.lstat(path)
        if stat.S_ISREG(info.st_mode) and fingerprint(path) == hash_value:
            return info
    except OSError:
        pass
    return None


def delete_files(deletions: Sequence[Deletion], downloads: str) -> int:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    record_path = os.path.join(downloads, f"gptk-deleted-{stamp}.txt")
    try:
        record = open(record_path, "x", encoding="utf-8", errors="backslashreplace")
    except OSError:
        print(f"Could not write the list of deleted files to {shown(record_path)}. Nothing was deleted.")
        return EXIT_INPUT_ERROR

    deleted_count, deleted_size, changed, no_kept_copy, failed = 0, 0, 0, 0, 0
    kept_files: Dict[str, Optional[os.stat_result]] = {}
    with record:
        record.write("# Files deleted by gptk_phone_check.py.\n")
        record.write("# path<TAB>size in bytes<TAB>Google Photos link (if Google Photos has the file)<TAB>copy that stays on the phone (if one stays)\n")
        for item in deletions:
            kept_info = None
            if item.kept is not None:
                # The copy that stays must still be there, unchanged. If not, keep this copy.
                if item.kept.path not in kept_files:
                    kept_files[item.kept.path] = unchanged_file(item.kept.path, item.hash)
                kept_info = kept_files[item.kept.path]
                if kept_info is None:
                    no_kept_copy += 1
                    continue
            try:
                info = os.lstat(item.media.path)
                # Check again just before deleting: the file must still be the same real file, and not the copy that stays.
                if (
                    not stat.S_ISREG(info.st_mode)
                    or (kept_info is not None and os.path.samestat(info, kept_info))
                    or fingerprint(item.media.path) != item.hash
                ):
                    changed += 1
                    continue
                os.remove(item.media.path)
            except FileNotFoundError:
                changed += 1
                continue
            except OSError:
                failed += 1
                continue
            deleted_count += 1
            deleted_size += item.media.size
            link = PHOTO_URL + item.media_key if item.media_key is not None else ""
            kept_path = item.kept.path if item.kept is not None else ""
            record.write(f"{item.media.path}\t{item.media.size}\t{link}\t{kept_path}\n")
            record.flush()

    print(f"Deleted {count_text(deleted_count, 'file')} ({format_size(deleted_size)}).")
    print(f"The list of deleted files is in {shown(record_path)}")
    if changed:
        print(f"Kept {count_text(changed, 'file')} that changed or moved after the check.")
    if no_kept_copy:
        print(f"Kept {count_text(no_kept_copy, 'file')}, because the copy that was to stay on the phone changed or moved.")
    if failed:
        print(f'Could not delete {count_text(failed, "file")}. Give Termux the "All files access" permission and run the command again.')
        return EXIT_DELETE_FAILED
    return EXIT_OK


def find_and_delete(args: argparse.Namespace, ask: Callable[[str], str], downloads: str, found: Dict[str, str], google_checked: bool) -> int:
    folders = resolve_folders(args.storage, args.folder)
    if not folders:
        print_no_folders(args.storage, args.folder)
        return EXIT_INPUT_ERROR
    hashed, _, folder_errors = hash_media_files(folders)
    print_folder_errors(folder_errors)
    print("Looking for copies in the other folders of the phone. This can take a few minutes.")
    sizes = {media.size for media, _ in hashed if media.size > 0}
    others, _ = hash_files(iter_other_copies(args.storage, folders, sizes, []), "Reading possible copies")
    groups = build_groups(hashed + others, found, args.storage)

    single = [group for group in groups if len(group.files) == 1 and group.media_key is not None]
    with_copies = [group for group in groups if len(group.files) > 1 and group.files[0].size > 0]
    # The biggest files first: they free the most space.
    with_copies.sort(key=lambda group: (-group.files[0].size, display_key(group.files[0], args.storage)))
    if not single and not with_copies:
        print(("No phone files match the result, and n" if google_checked else "N") + "o photos or videos have copies on the phone. Nothing to delete.")
        return EXIT_OK

    deletions = [Deletion(group.files[0], group.hash, group.media_key, None) for group in single]
    if single:
        print(f"Already in your Google Photos, with no other copy on the phone: {count_text(len(single), 'file')} ({format_size(sum(group.files[0].size for group in single))})")
    if with_copies:
        try:
            deletions += review_copies(with_copies, google_checked, ask, args.storage)
        except (EOFError, KeyboardInterrupt):
            print()
            print("Nothing was deleted.")
            return EXIT_CANCELLED
    if not deletions:
        print("You chose to keep all copies. Nothing was deleted.")
        return EXIT_OK

    print_summary(deletions, args.storage, args.list)
    try:
        answer = ask(f"Type yes to delete {count_text(len(deletions), 'file')}: ")
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer.strip().lower() != "yes":
        print("Nothing was deleted.")
        return EXIT_CANCELLED
    return delete_files(deletions, downloads)


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
        print("Note: the check in GPTK was stopped before the end. Only files that it confirmed are treated as in Google Photos.")
    if not result.found:
        print("GPTK found none of the files in your Google Photos.")
    return find_and_delete(args, ask, downloads, result.found, google_checked=True)


def command_copies(args: argparse.Namespace, ask: Callable[[str], str]) -> int:
    downloads = args.downloads or os.path.join(args.storage, "Download")
    if not os.path.isdir(downloads):
        print(f"Download folder not found: {shown(downloads)}")
        return EXIT_INPUT_ERROR
    return find_and_delete(args, ask, downloads, {}, google_checked=False)


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
    deleting = argparse.ArgumentParser(add_help=False)
    deleting.add_argument("--list", action="store_true", help="show every file before the last question")

    parser = argparse.ArgumentParser(description="Free phone space: delete WhatsApp photos and videos that are in your Google Photos (with GPTK Phone Check), and extra copies.")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    commands.required = True
    commands.add_parser("scan", parents=[common], help="make the fingerprint file for GPTK Phone Check")
    clean = commands.add_parser(
        "clean", parents=[common, deleting], help="delete the files that GPTK found in Google Photos, and choose what to do with copies"
    )
    clean.add_argument("--result", help="result file to use (default: the newest gptk-result*.json in Download)")
    commands.add_parser("copies", parents=[common, deleting], help="only find copies on the phone and choose what to keep (no Google Photos)")
    return parser


def main(argv: Optional[Sequence[str]] = None, ask: Callable[[str], str] = input) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return command_scan(args)
    if args.command == "copies":
        return command_copies(args, ask)
    return command_clean(args, ask)


if __name__ == "__main__":
    sys.exit(main())
